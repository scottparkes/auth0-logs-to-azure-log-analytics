const moment = require('moment');
const crypto    = require('crypto');
const Request   = require('request');

const loggingTools = require('auth0-log-extension-tools');
const config = require('../lib/config');
const logger = require('../lib/logger');

module.exports = storage =>
  (req, res, next) => {
    const wtBody = (req.webtaskContext && req.webtaskContext.body) || req.body || {};
    const wtHead = (req.webtaskContext && req.webtaskContext.headers) || {};
    const isCron = (wtBody.schedule && wtBody.state === 'active') || (wtHead.referer === `${config('AUTH0_MANAGE_URL')}/` && wtHead['if-none-match']);

    if (!isCron) {
      return next();
    }

    const postLogsFromToLogAnalytics = (workspaceId, sharedKey, jsonData, cb) => {
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
          logger.error(`Error sending logs to Azure Log Analytics: ${error}, Response: ${response}, Body: ${body}`);
          cb(error);
        } else {
          cb(null);
        }
      });
    };
    
    const sendLogs = (logs, cb) => {
      if (!logs || !logs.length) {
        cb();
      }

      postLogsFromToLogAnalytics(
        config('LOG_ANALYTICS_WORKSPACE_ID'),
        config('LOG_ANALYTICS_SHARED_KEY'),
        logs,
        (error) => {
          if (!error) {
            logger.info(`${logs.length} events successfully sent to Azure log analytics.`);
            return cb();
          } else {
            return cb(error);
          }
        });
    };

    const onLogsReceived = (logs, cb) => {
      if (!logs || !logs.length) {
        return cb();
      }

      logger.info(`${logs.length} logs received.`);
      return sendLogs(logs, cb);
    };

    const slack = new loggingTools.reporters.SlackReporter({ hook: config('SLACK_INCOMING_WEBHOOK_URL'), username: 'logs-to-azure-log-analytics', title: 'Logs To Azure Log Analytics' });

    const options = {
      domain: config('AUTH0_DOMAIN'),
      clientId: config('AUTH0_CLIENT_ID'),
      clientSecret: config('AUTH0_CLIENT_SECRET'),
      batchSize: config('BATCH_SIZE'),
      startFrom: config('START_FROM'),
      logTypes: config('LOG_TYPES'),
      logLevel: config('LOG_LEVEL')
    };

    if (!options.batchSize || options.batchSize > 100) {
      options.batchSize = 100;
    }

    if (options.logTypes && !Array.isArray(options.logTypes)) {
      options.logTypes = options.logTypes.replace(/\s/g, '').split(',');
    }

    const auth0logger = new loggingTools.LogsProcessor(storage, options);

    const sendDailyReport = (lastReportDate) => {
      const current = new Date();

      const end = current.getTime();
      const start = end - 86400000;
      auth0logger.getReport(start, end)
        .then(report => slack.send(report, report.checkpoint))
        .then(() => storage.read())
        .then((data) => {
          data.lastReportDate = lastReportDate;
          return storage.write(data);
        });
    };

    const checkReportTime = () => {
      storage.read()
        .then((data) => {
          const now = moment().format('DD-MM-YYYY');
          const reportTime = config('DAILY_REPORT_TIME') || 16;

          if (data.lastReportDate !== now && new Date().getHours() >= reportTime) {
            sendDailyReport(now);
          }
        });
    };

    return auth0logger
      .run(onLogsReceived)
      .then((result) => {
        if (result && result.status && result.status.error) {
          slack.send(result.status, result.checkpoint);
        } else if (config('SLACK_SEND_SUCCESS') === true || config('SLACK_SEND_SUCCESS') === 'true') {
          slack.send(result.status, result.checkpoint);
        }
        checkReportTime();
        res.json(result);
      })
      .catch((err) => {
        slack.send({ error: err, logsProcessed: 0 }, null);
        checkReportTime();
        next(err);
      });
  };
