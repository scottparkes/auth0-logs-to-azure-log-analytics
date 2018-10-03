"use latest";

const useragent = require('useragent');
const moment    = require('moment');
const express   = require('express');
const Webtask   = require('webtask-tools');
const app       = express();
const Request   = require('request');
const crypto    = require('crypto');
const memoizer  = require('lru-memoizer');

function lastLogCheckpoint (req, res) {
  let ctx = req.webtaskContext;

  if (!ctx.data.AUTH0_DOMAIN || !ctx.data.AUTH0_CLIENT_ID || !ctx.data.AUTH0_CLIENT_SECRET) {
    return res.status(400).send({ message: 'Auth0 API v1 credentials or domain missing.' });
  }

  if (!ctx.data.LOG_ANALYTICS_WORKSPACE_ID) {
    return res.status(400).send({ message: 'Log Analytics Workspace ID key is missing.' });
  }

  if (!ctx.data.LOG_ANALYTICS_SHARED_KEY) {
    return res.status(400).send({ message: 'Log Analytics Shared Key is missing.' });
  }

  req.webtaskContext.storage.get((err, data) => {
    let checkpointId = typeof data === 'undefined' ? null : data.checkpointId;
    /*
     * If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
     */
    console.log('Starting from:', checkpointId);

    /*
     * Test authenticating with the Auth0 API.
     */
    const authenticate = (callback) => {
      return callback();
    };

    /*
     * Get the logs from Auth0.
     */
    const logs = [];
    const getLogs = (checkPoint, callback) => {
      let take = Number.parseInt(ctx.data.BATCH_SIZE);

      take = take > 100 ? 100 : take;

      getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, checkPoint, function (result, err) {
	        if (err) {
	          console.log('Error getting logs from Auth0', err);
	          return callback(err);
	        }

	        if (result && result.length > 0) {
	          result.forEach(function (log) {
	            // Azure Log Analytics does not allow you to send very old logs, so we'll only send the logs of the last 48 hours max.
	            if (log.date && moment().diff(moment(log.date), 'hours') < 48) {
	              logs.push(log);
	            }
	          });

	          console.log('Retrieved ' + logs.length + ' logs from Auth0 after ' + checkPoint + '.');
	          setImmediate(function () {
	            checkpointId = result[result.length - 1]._id;
	            getLogs(result[result.length - 1]._id, callback);
	          });
	        } else {
	          console.log('Reached end of logs. Total: ' + logs.length + '.');
	          return callback(null, logs);
	        }
	      });
    };

    /*
     * Export the logs to Azure Log Analytics.
     */
    const exportLogs = (logs, callback) => {
      console.log('Exporting logs to Azure Log Analytics: ' + logs.length);

      if (logs && logs.length) {
        console.log('Sending all data...');

        postLogsFromToLogAnalytics(
          ctx.data.LOG_ANALYTICS_WORKSPACE_ID,
          ctx.data.LOG_ANALYTICS_SHARED_KEY,
          logs,
          (response) => {
            return callback(null, response);
          });
      } else {
        console.log('No data to send...');
        return callback(null, '{ "itemsAccepted": 0 }');
      }
    };

    /*
     * Start the process.
     */
    authenticate((err) => {
      if (err) {
        return res.status(500).send({ err: err });
      }

      getLogs(checkpointId, (err, logs) => {
        if (!logs) {
          return res.status(500).send({ err: err });
        }

        exportLogs(logs, (err, response) => {
          try {
            response = JSON.parse(response);
          } catch (e) {
            console.log('Error parsing response, this might indicate that an error occurred:', response);

            return req.webtaskContext.storage.set({checkpointId: checkpointId}, {force: 1}, (error) => {
              if (error) return res.status(500).send(error);

              res.status(500).send({
                error: response
              });
            });
          }

          // At least one item we sent was accepted, so we're good and next run can continue where we stopped.
          if (response.itemsAccepted && response.itemsAccepted > 0) {
            return req.webtaskContext.storage.set({checkpointId: checkpointId}, {force: 1}, (error) => {
              if (error) {
                console.log('Error storing startCheckpoint', error);
                return res.status(500).send({ error: error });
              }

              res.sendStatus(200);
            });
          }

          // None of our items were accepted, next run should continue from same starting point.
          console.log('No items accepted.');
          return req.webtaskContext.storage.set({checkpointId: checkpointId}, {force: 1}, (error) => {
            if (error) {
              console.log('Error storing checkpoint', error);
              return res.status(500).send({ error: error });
            }

            res.sendStatus(200);
          });
        });
      });
    });
  });
}

function getLogsFromAuth0 (domain, token, take, from, cb) {
  var url = `https://${domain}/api/v2/logs`;

  Request({
    method: 'GET',
    url: url,
    json: true,
    qs: {
      take: take,
      from: from,
      sort: 'date:1',
      per_page: take
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err) {
      console.log('Error getting logs', err);
      cb(null, err);
    } else {
      cb(body);
    }
  });
}

function postLogsFromToLogAnalytics (workspaceId, sharedKey, jsonData, cb) {
  var apiVersion = '2016-04-01';
  var processingDate = new Date().toUTCString();
  
  var body = JSON.stringify(jsonData);    
  var contentLength = Buffer.byteLength(body, 'utf8');

  var stringToSign = 'POST\n' + contentLength + '\napplication/json\nx-ms-date:' + processingDate + '\n/api/logs';
  var signature = crypto.createHmac('sha256', new Buffer(sharedKey, 'base64')).update(stringToSign, 'utf-8').digest('base64');
  var authorization = 'SharedKey ' + workspaceId + ':' + signature;

  var headers = {
      'content-type': 'application/json', 
      'Authorization': authorization,
      'Log-Type': 'Auth0Logs',
      'x-ms-date': processingDate,
      'time-generated-field': 'date'
  };

  var url = 'https://' + workspaceId + '.ods.opinsights.azure.com/api/logs?api-version=' + apiVersion;

  Request.post({url: url, headers: headers, body: body}, function (error, response, body) {
    if (error) {
      console.log('Error sending logs to Azure Log Analytics', error);
      cb(null, error);
    } else {
      cb(body);
    }
  });
}

const getTokenCached = memoizer({
  load: (apiUrl, audience, clientId, clientSecret, cb) => {
    Request({
      method: 'POST',
      url: apiUrl,
      json: true,
      body: {
        audience: audience,
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret
      }
    }, (err, res, body) => {
      if (err) {
        cb(null, err);
      } else {
        cb(body.access_token);
      }
    });
  },
  hash: (apiUrl) => apiUrl,
  max: 100,
  maxAge: 1000 * 60 * 60
});

app.use(function (req, res, next) {
  var apiUrl       = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
  var audience     = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
  var clientId     = req.webtaskContext.data.AUTH0_CLIENT_ID;
  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

  getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
    if (err) {
      console.log('Error getting access_token', err);
      return next(err);
    }

    req.access_token = access_token;
    next();
  });
});

app.get ('/', lastLogCheckpoint);
app.post('/', lastLogCheckpoint);

module.exports = Webtask.fromExpress(app);
