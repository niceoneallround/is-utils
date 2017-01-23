/*

This message is a JWT sent from the RSP to the Identity Syndicate to carry the
RS query results. It has the following claims

- a PN_JWT_TYPE_CLAM  of pn_t.RSPQueryResult
- a QUERY_CLAIM - contains the RSPQuery Result node that contains
  - @id:
  - @type:
  - pn_p.responding_to: the corresponding RSP query that the results are for
- a EMBEDDED_MESSAGE_CLAIM - contains the validated RS Query Result JWT from the RS

*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils').npUtils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const RSQueryResult = require('./RSQueryResult');
const util = require('util');

let messageIdCounter = 0;

class RSPQueryResult {

  static createJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(props, 'props param is missing');
    assert(props.respondingTo, util.format('props.respondingTo param is missing:%j', props));
    assert(props.message, util.format('props.message param is missing:%j', props));

    let query = {
      '@id': PNDataModel.ids.createQueryResultId(serviceCtx.config.DOMAIN_NAME, moment().unix() + '-' + messageIdCounter),
      '@type': [PN_T.RSPSubjectQueryResult],
      [PN_P.respondingTo]: props.respondingTo,
    };

    messageIdCounter = messageIdCounter + 1;

    // allow id to overrriden - used for testing
    if (props.id) {
      query['@id'] = props.id;
    }

    return JWTUtils.signRSPQueryResult(
            query, props.message,
            serviceCtx.config.crypto.jwt, { subject: query['@id'], });
  }

  /* OUTPUTs a stucture

      { error: the jwt was somehow invalid so send a bad request to caller,
        decoded: the decoded payload
        query: the query
        message: the message }
  */
  static validateJWT(serviceCtx, inputJWT) {

    const loggingMD = {
            ServiceType: serviceCtx.serviceName,
            FileName: 'isUtils/messages/RSPQueryResult.js', };

    const hostname = serviceCtx.config.getHostname();

    // verify the JWT
    let result = {};
    if (serviceCtx.config.VERIFY_JWT) {
      try {
        result.decoded = JWTUtils.newVerify(inputJWT, serviceCtx.config.crypto.jwt);
      } catch (err) {
        result.error = PNDataModel.errors.createInvalidJWTError({
                  id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
                  type: PN_T.RSSubjectQueryResult, jwtError: err, });

        serviceCtx.logger.logJSON('error', { serviceType: serviceCtx.name,
                                    action: 'RSPQuery-Result-ERROR-JWT-VERIFY',
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

    if (!result.decoded[JWTClaims.QUERY_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.QUERY_CLAIM, result.decoded),
      });

      return result;
    } else {
      result.query = result.decoded[JWTClaims.QUERY_CLAIM];

      //
      // validate the query
      //
      if (!((JSONLDUtils.isType(result.query, PN_T.RSPSubjectQueryResult)))) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.RSSubjectQueryResult, result.query),
        });

        return result;
      }

      if (!result.query[PN_P.respondingTo]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR proeprty %s from:%j', PN_P.respondingTo, result.query),
        });

        return result;
      }
    }

    // note just check claim there, do not validate embedded claim
    if (!result.decoded[JWTClaims.EMBEDDED_JWT_MESSAGE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.EMBEDDED_JWT_MESSAGE_CLAIM, result.decoded),
      });

      return result;
    } else {
      result.message = result.decoded[JWTClaims.EMBEDDED_JWT_MESSAGE_CLAIM];
    }

    return result;
  }

  // The message ack JWT just contains the @id of the query in a QUERY_CLAIM
  static createMessageAckJWT(serviceCtx, decoded) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(decoded, 'decoded param is missing');

    let messageId = decoded[JWTClaims.QUERY_CLAIM]['@id'];
    return JWTUtils.signMessageAck(messageId, serviceCtx.config.crypto.jwt);
  }

  //
  // Create a canon rsQueryResult JWT that can be used for testing
  // props.respondingTo - optional
  // props.syndicationId - optional
  // props.pnDataModelId - optional
  // props.privacyPipeId - optional
  static createCanonJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');

    let respondingTo = 'id-1';
    if ((props) && (props.respondingTo)) {
      respondingTo = props.respondingTo;
    }

    let messageJWT = RSQueryResult.createCanonJWT(serviceCtx, props);

    return RSPQueryResult.createJWT(serviceCtx, { respondingTo: respondingTo, message: messageJWT, });
  }

} // class

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const rsQueryResult = require('..../rsQueryResult');
// result = rsQueryResult.validateJWT()
//
module.exports = RSPQueryResult;
