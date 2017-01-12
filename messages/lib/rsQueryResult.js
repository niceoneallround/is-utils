
/*

 This message is sent from the Reference Source Privacy Agent to the Reference Source Proxy
 in response to a RS query and contains the query results.

 The RSQueryResult JWT contains the following claims
 - a pn jwt type claim of pn_t.rsQueryResult
 - a query claim - this the query result node that was passed in
 - a privacy pipe claim - this is the pipe used to send the data to the IS
 - a subject jwts claim - the subject results represented as an array of subject JWTs - one per returned subject
     - note transaction id is part of the subject record so know what transaction creates this subject
 - a subject link jwts claim - a jwt for each link between a reference source subject and the passed in subject
   - can also contains custom claims - how do this

For creation the INPUT is
  - the serviceCtx
  - the query
  - the subject JWTs
  - the subject link JWTs
  - the privacy pipe Id

The creation OUTPUT is a rsQueryResponse JWT


The validateJWT(serviceCtx, jwt) performs the following
  - verifyies all JWTs
  - verifies the query
  - creates the output structure
*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils').npUtils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const util = require('util');

class RSQueryResult {

  /* OUTPUTs a stucture

      { error: the jwt was somehow invalid so send a bad request to caller,
        decoded: the decoded payload
        subjects: an array of decoded payload subject JWTs
        links: an array of decoded payload link JWTs
        query: the query  }
  */
  static validateJWT(serviceCtx, inputJWT) {

    const loggingMD = {
            ServiceType: serviceCtx.serviceName,
            FileName: 'isUtils/rsQueryResult.js', };

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
                                    action: 'RsQuery-Result-ERROR-JWT-VERIFY',
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
    }

    if (!result.decoded[JWTClaims.SUBJECT_JWTS_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_JWTS_CLAIM, result.decoded),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.PRIVACY_PIPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PRIVACY_PIPE_CLAIM, result.decoded),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.SUBJECT_LINK_JWTS_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_LINK_JWTS_CLAIM, result.decoded),
      });

      return result;
    }

    //
    // validate the query
    result.query = result.decoded[JWTClaims.QUERY_CLAIM];
    if (!((JSONLDUtils.isType(result.query, PN_T.RSSubjectQueryResult)))) {
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

    //
    // verify the subject JWTS
    result.subjectJWTs = result.decoded[JWTClaims.SUBJECT_JWTS_CLAIM];
    result.decodedSubjectJWTs = [];
    if (serviceCtx.config.VERIFY_JWT) {
      for (let i = 0; i < result.subjectJWTs.length; i++) {
        try {
          result.decodedSubjectJWTs.push(JWTUtils.newVerify(result.subjectJWTs[i], serviceCtx.config.crypto.jwt));
        } catch (err) {

          result.badRequest = PNDataModel.errors.createInvalidJWTError({
                    id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
                    type: PN_T.RSSubjectQueryResult, jwtError: err, });

          serviceCtx.logger.logJSON('error', { serviceType: serviceCtx.name,
                                      action: 'RsQuery-Result-ERROR-JWT-VERIFY-OF-SUBJECT_JWTs',
                                      query: result.query['@id'],
                                      inputJWT: inputJWT,
                                      error: result.subjectJWTs[i],
                                      decoded: JWTUtils.decode(result.subjectJWTs[i], { complete: true }),
                                      jwtError: err, }, loggingMD);

          return result;
        }
      }
    }

    // verify the subject JWT claims are as expected
    for (let i = 0; i < result.decodedSubjectJWTs.length; i++) {

      if (!result.decodedSubjectJWTs[i][JWTClaims.SUBJECT_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_CLAIM, result.decodedSubjectJWTs[i]),
        });
        return result;
      }

      if (!result.decodedSubjectJWTs[i][JWTClaims.SUBJECT_SYNDICATION_ID_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_SYNDICATION_ID_CLAIM, result.decodedSubjectJWTs[i]),
        });
        return result;
      }

      if (!result.decodedSubjectJWTs[i][JWTClaims.PN_DATA_MODEL_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PN_DATA_MODEL_CLAIM, result.decodedSubjectJWTs[i]),
        });
        return result;
      }
    }

    return result;
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

    let syndicationId = 'synd-id-1';
    if ((props) && (props.syndicationId)) {
      syndicationId = props.syndicationId;
    }

    let pnDataModelId = 'pnDataModelId-1';
    if ((props) && (props.pnDataModelId)) {
      pnDataModelId = props.pnDataModelId;
    }

    let privacyPipeId = 'ppId-1';
    if ((props) && (props.privacyPipeId)) {
      privacyPipeId = props.privacyPipeId;
    }

    let queryResult = {
      '@id': 'fake-query-id',
      '@type': [PN_T.RSSubjectQueryResult],
      [PN_P.respondingTo]: respondingTo, };

    let alice = TestReferenceSourcePNDataModel.canons.createAlice({ domainName: serviceCtx.config.DOMAIN_NAME, });
    let aliceJWT = JWTUtils.signSubject(
        alice, pnDataModelId, syndicationId, serviceCtx.config.crypto.jwt, { subject: alice['@id'], });

    let bob = TestReferenceSourcePNDataModel.canons.createBob({ domainName: serviceCtx.config.DOMAIN_NAME, });
    let bobJWT = JWTUtils.signSubject(
        alice, pnDataModelId, syndicationId, serviceCtx.config.crypto.jwt, { subject: bob['@id'], });

    let rsQueryResultJWT = JWTUtils.signRSQueryResult(
                              queryResult,
                              [aliceJWT, bobJWT],
                              [], // link JWTs
                              privacyPipeId,
                              serviceCtx.config.crypto.jwt,
                              { subject: queryResult['@id'], }
                            );

    return rsQueryResultJWT;
  }

} // class

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const rsQueryResult = require('..../rsQueryResult');
// result = rsQueryResult.validateJWT()
//
module.exports = RSQueryResult;
