/*jslint node: true */
/*

The internal query result maps to the internal query in that it contains a set
of result nodes that can be used to create the output graph.

For each query node it contains the following information
- information on the query node
- the syndicate entites that are the result of the query.

The query result is wrapped in a JWT
- QUERY_CLAIM - contains the query result
- SUBJECT_CLAIM - array of subjects used in the query result. For each unique subject @id it contains all the properties for that subject.
  Note it may itself come from > 1 source subject and JWTs the only think that is common is they all have the same @id and the same @type.
  Note the syndicated entity can be unpacked to find the actual source JWT using the JWT Id.
- PRIVACY_PIPE_CLAIM
- JWT_TYPE_CLAIM
- JWT_ID_CLAIM

An example query result node

{
   @id: http://pn.id.webshield.io/query_result/com/acme#73733737 - used for log messages and async return of messages
   @type: https://pn.schema.webshield.io/type#subject_query_result,
   pn_p.query_privacy_agent: the @id of the query privacy agent making the request, used to get provision and callback URL
   pn_p.responding_to: the query id
   query_node_results: [
     { @id: blank node id
       @type: queryNodeResult,
       pn_p.result_graph_property: 'bob',
       pn_p.query_node: the @id of the query node this result is for
       pn_p.syndicated_entity: [ array of syndicate entities for this node]
     }
  ]
  }
 }
 */

/*
   CODE Restrictions as have not added code yet
   1. Can only have one query node
   2. Only support by id
*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTType = require('jwt-utils/lib/jwtUtils').jwtType;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

let messageIdCounter = 0;
function nextIdCounter() {
  'use strict';
  messageIdCounter = messageIdCounter + 1;
  return moment().unix() + '-' + messageIdCounter;
}

class QueryResult {

  static createJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(props, 'props param is missing');
    assert(props.queryPrivacyAgentId, util.format('props.queryPrivacyAgentId param is missing:%j', props));
    assert(props.queryId, util.format('props.queryId param is missing:%j', props));
    assert(props.queryResultNodes, util.format('props.queryResultNodes param is missing:%j', props));
    assert(props.subjects, util.format('props.subjects param is missing:%j', props));
    assert(props.privacyPipeId, util.format('props.privacyPipeId param is missing:%j', props));

    let queryResult = {
      '@id': PNDataModel.ids.createQueryResultId(serviceCtx.config.DOMAIN_NAME, nextIdCounter()),
      '@type': [PN_T.SubjectQueryResult],
      [PN_P.respondingTo]: props.queryId,
      [PN_P.queryResultNodes]: props.queryResultNodes,
    };

    return JWTUtils.signSubjectQueryResult(
            queryResult,
            props.subjects,
            props.privacyPipeId,
            serviceCtx.config.crypto.jwt, { subject: queryResult['@id'], });
  }

  /* OUTPUTs a stucture

      { error: the jwt was somehow invalid so send a bad request to caller,
        decoded: the decoded query result JWT,
        queryResult: the query result node,
        subjects: array of subjects
        privacyPipeId: the pipe id
      }
  */
  static validateJWT(serviceCtx, inputJWT) {

    const loggingMD = {
            ServiceType: serviceCtx.serviceName,
            FileName: 'isUtils/messages/subjectQueryResult.js', };

    const hostname = serviceCtx.config.getHostname();

    // verify the JWT
    let result = {};
    if (serviceCtx.config.VERIFY_JWT) {
      try {
        result.decoded = JWTUtils.newVerify(inputJWT, serviceCtx.config.crypto.jwt);
      } catch (err) {
        result.error = PNDataModel.errors.createInvalidJWTError({
                  id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
                  type: PN_T.SubjectSyndicationRequest, jwtError: err, });

        serviceCtx.logger.logJSON('error', { serviceType: serviceCtx.name,
                                    action: 'SubjectQueryResult-ERROR-JWT-VERIFY',
                                    inputJWT: inputJWT,
                                    error: result.error,
                                    decoded: JWTUtils.decode(inputJWT, { complete: true }),
                                    jwtError: err, }, loggingMD);

        return result;
      }
    }

    if (!result.decoded) {
      result.decoded = JWTUtils.decode(inputJWT); // decode as may not have verified
    }

    if (!result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PN_JWT_TYPE_CLAIM, result.decoded),
      });

      return result;
    }

    if (result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM] !== JWTType.subjectQueryResult) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR JWT not expected type::%s JWT:%j', JWTType.subjectQueryResult, result.decoded),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.SUBJECT_QUERY_RESULT_CLAIM]) { // holds result
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_QUERY_RESULT_CLAIM, result.decoded),
      });

      return result;
    }

    result.queryResult = result.decoded[JWTClaims.SUBJECT_QUERY_RESULT_CLAIM];
    if (!((JSONLDUtils.isType(result.queryResult, PN_T.SubjectQueryResult)))) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.SubjectQueryResult, result.queryResult),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.SUBJECT_CLAIM]) { // holds result
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_CLAIM, result.decoded),
      });

      return result;
    }

    // validate privacy pipe claim
    if (!result.decoded[JWTClaims.PRIVACY_PIPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PRIVACY_PIPE_CLAIM, result.decoded),
      });

      return result;
    } else {
      result.privacyPipeId = result.decoded[JWTClaims.PRIVACY_PIPE_CLAIM];
    }

    return result;
  }

  // The message ack JWT just contains the @id of the query in a QUERY_CLAIM
  static createMessageAckJWT(serviceCtx, decoded) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(decoded, 'decoded param is missing');

    let messageId = decoded[JWTClaims.SUBJECT_QUERY_RESULT_CLAIM]['@id'];
    return JWTUtils.signMessageAck(messageId, serviceCtx.config.crypto.jwt);
  }

}

module.exports = QueryResult;
