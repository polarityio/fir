const request = require('postman-request');
const async = require('async');
const fs = require('fs');
const _ = require('lodash');
const config = require('./config/config');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_PARALLEL_LOOKUPS = 10;

let incidentFields = null;
/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function _isEntityBlocklisted(entity, { blocklist }) {
  Logger.trace({ blocklist }, 'Blocklist Values');

  const entityIsBlocklisted = _.includes(blocklist, entity.value.toLowerCase());

  const ipIsBlocklisted =
    entity.isIP && !entity.isPrivateIP && ipBlocklistRegex !== null && ipBlocklistRegex.test(entity.value);
  if (ipIsBlocklisted) Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');

  const domainIsBlocklisted =
    entity.isDomain && domainBlocklistRegex !== null && domainBlocklistRegex.test(entity.value);
  if (domainIsBlocklisted) Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');

  return entityIsBlocklisted || ipIsBlocklisted || domainIsBlocklisted;
}

function _isInvalidEntity(blocklist, entity) {
  return entity.isIPv4 && IGNORED_IPS.has(entity.value);
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);

  getIncidentFields(options, (err, mappings) => {
    if(err){
      return cb(err);
    }
    incidentFields = mappings;
    Logger.info({incidentFields}, 'incidentFields');
    _setupRegexBlocklists(options);
    let url = options.url.endsWith('/') ? options.url : `${options.url}/`;

    entities.forEach((entity) => {
      if (!_isInvalidEntity(options.blocklist, entity) && !_isEntityBlocklisted(entity, options)) {
        let requestOptions = {
          method: 'GET',
          headers: {
            Authorization: 'Token ' + options.apiKey
          },
          uri: `${url}api/artifacts`,
          qs: {
            search: `${entity.value}`
          },
          json: true
        };

        Logger.trace({ uri: requestOptions }, 'Request URI');

        tasks.push(function(done) {
          requestWithDefaults(requestOptions, function(error, res, body) {
            let processedResult = handleRestError(error, entity, res, body);

            if (processedResult.error) {
              done(processedResult);
              return;
            }

            done(null, processedResult);
          });
        });
      }
    });

    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err: err }, 'Error');
        cb(err);
        return;
      }

      Logger.info({ results }, 'Results');

      results.forEach((result) => {
        if (result.body === null || _.isEmpty(result.body) || _isMiss(result.body)) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          let incidentCount = 0;
          for (let i = 0; i < result.body.results.length; i++) {
            let artifact = result.body.results[i];
            artifact.incidentIds = artifact.incidents.map((url) => {
              return url.split('/').slice(-1)[0];
            });
            incidentCount += artifact.incidentIds.length;
            artifact.incidents = [];
            artifact.link = `${url}artifacts/${artifact.id}/correlations/`;
          }

          lookupResults.push({
            entity: result.entity,
            data: {
              summary: [`Artifacts: ${result.body.results.length}`, `Incidents: ${incidentCount}`],
              details: result.body
            }
          });
        }
      });

      Logger.debug({ lookupResults }, 'Results');
      cb(null, lookupResults);
    });
  });
}

function getIncidentFields(options, cb) {
  if (incidentFields !== null) {
    return cb(null, incidentFields);
  }

  let url = options.url.endsWith('/') ? options.url : `${options.url}/`;
  let requestOptions = {
    method: 'OPTIONS',
    headers: {
      Authorization: 'Token ' + options.apiKey
    },
    uri: `${url}api/incidents`,
    json: true
  };

  requestWithDefaults(requestOptions, (err, response, body) => {
    if (err) {
      return cb({ detail: 'Error retrieving incident options', err });
    }

    if (response.statusCode !== 200) {
      return cb({
        detail: body.detail ? body.detail : `Unexpected HTTP status code ${response.statusCode} received.`
      });
    }

    Logger.info({body}, 'OPTIONS lookup');

    let mappings = {
      severity: {},
      status: {},
      confidentiality: {}
    };

    if (body && body.actions && body.actions.POST) {
      let severity = body.actions.POST.severity;
      let status = body.actions.POST.status;
      let confidentiality = body.actions.POST.confidentiality;

      if (severity) {
        severity.choices.forEach((option) => {
          mappings.severity[option.value] = option.display_name;
        });
      }

      if (status) {
        status.choices.forEach((option) => {
          mappings.status[option.value] = option.display_name;
        });
      }

      if (confidentiality) {
        confidentiality.choices.forEach((option) => {
          mappings.confidentiality[option.value] = option.display_name;
        });
      }
    }

    cb(null, mappings);
  });
}

function getIncident(incidentId, options, cb) {
  let url = options.url.endsWith('/') ? options.url : `${options.url}/`;
  let requestOptions = {
    method: 'GET',
    headers: {
      Authorization: 'Token ' + options.apiKey
    },
    uri: `${url}api/incidents/${incidentId}`,
    json: true
  };

  requestWithDefaults(requestOptions, (err, response, body) => {
    if (err) {
      return cb({ detail: 'Error retrieving incident details', err });
    }

    if (response.statusCode !== 200) {
      return cb({
        detail: body.detail ? body.detail : `Unexpected HTTP status code ${response.statusCode} received.`
      });
    }

    body.link = `${url}incidents/${body.id}/`;

    cb(null, body);
  });
}

function onDetails(resultObject, options, cb) {
  async.each(
    resultObject.data.details.results,
    (artifact, artifactDone) => {
      async.each(
        artifact.incidentIds,
        (incidentId, incidentDone) => {
          getIncident(incidentId, options, (err, incident) => {
            if (err) {
              return incidentDone(err);
            }

            incident.confidentialityDisplay = incidentFields.confidentiality[incident.confidentiality];
            incident.statusDisplay = incidentFields.status[incident.status];

            artifact.incidents.push(incident);
            incidentDone();
          });
        },
        artifactDone
      );
    },
    (err) => {
      Logger.debug({ resultObject }, 'onDetails result');
      cb(err, resultObject.data);
    }
  );
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 404 || res.statusCode === 202) {
    // no result found
    result = {
      entity: entity,
      body: null
    };
  } else {
    // unexpected status code
    result = {
      error: body,
      detail: body.detail ? body.detail : `Unexpected HTTP status code ${res.statusCode} received.`
    };
  }
  return result;
}

function _isMiss(body) {
  if (!Array.isArray(body.results)) {
    return true;
  }

  if (body.results.length === 0) {
    return true;
  }

  return false;
}

module.exports = {
  doLookup,
  startup,
  onDetails
};
