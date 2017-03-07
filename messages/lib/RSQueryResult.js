/*jslint node: true */
/*

 This message is sent from the Reference Source Privacy Agent to the Reference Source Proxy
 in response to a RS query and contains the query results.

 The RSQueryResult JWT contains the following claims
 - a pn jwt type claim of pn_t.rsQueryResult
 - a query claim - this the query result node that was passed in. A query result node has the followig fields
    - @id: the message id for the result
    - @type: pn_t.RSQueryResult
    - pn_p.responding_to: the @id of the query that this is the results for
 - a privacy pipe claim - this is the obfuscate pipe Id used to send the data from the RS
 - a subject jwts claim - the subject results represented as an array of subject JWTs - one per returned subject
 - a subject link jwts claim - a jwt for each link between a reference source subject and the passed in subject
   - can also contains custom claims - how do this

For creation the INPUT is
  - the serviceCtx
  - the query result node
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
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const canonConstants = require('./canonConstants');
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
            FileName: 'isUtils/messages/RSQueryResult.js', };

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
    } else {
      //
      // validate the query
      //
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
    }

    if (!result.decoded[JWTClaims.PRIVACY_PIPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PRIVACY_PIPE_CLAIM, result.decoded),
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

    //
    // verify the subject JWTS
    //
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

      if (!result.decodedSubjectJWTs[i][JWTClaims.JWT_ID_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.JWT_ID_CLAIM, result.decodedSubjectJWTs[i]),
        });
        return result;
      }

      if (!result.decodedSubjectJWTs[i][JWTClaims.SUBJECT_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_CLAIM, result.decodedSubjectJWTs[i]),
        });
        return result;
      }

      if (!result.decodedSubjectJWTs[i][JWTClaims.SYNDICATION_ID_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SYNDICATION_ID_CLAIM, result.decodedSubjectJWTs[i]),
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

    if (!result.decoded[JWTClaims.SUBJECT_LINK_JWTS_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_LINK_JWTS_CLAIM, result.decoded),
      });

      return result;
    }

    //
    // verify the subject link JWTS
    //
    result.subjectLinkJWTs = result.decoded[JWTClaims.SUBJECT_LINK_JWTS_CLAIM];
    result.decodedSubjectLinkJWTs = [];
    if (serviceCtx.config.VERIFY_JWT) {
      for (let i = 0; i < result.subjectLinkJWTs.length; i++) {
        try {
          result.decodedSubjectLinkJWTs.push(JWTUtils.newVerify(result.subjectLinkJWTs[i], serviceCtx.config.crypto.jwt));
        } catch (err) {

          result.badRequest = PNDataModel.errors.createInvalidJWTError({
                    id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
                    type: PN_T.RSSubjectQueryResult, jwtError: err, });

          serviceCtx.logger.logJSON('error', { serviceType: serviceCtx.name,
                                      action: 'RsQuery-Result-ERROR-JWT-VERIFY-OF-SUBJECT_LINK_JWTs',
                                      query: result.query['@id'],
                                      inputJWT: inputJWT,
                                      error: result.subjectLinkJWTs[i],
                                      decoded: JWTUtils.decode(result.subjectLinkJWTs[i], { complete: true }),
                                      jwtError: err, }, loggingMD);

          return result;
        }
      }
    }

    // verify the subject link JWT claims are as expected
    for (let i = 0; i < result.decodedSubjectLinkJWTs.length; i++) {

      if (!result.decodedSubjectLinkJWTs[i][JWTClaims.JWT_ID_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.JWT_ID_CLAIM, result.decodedSubjectLinkJWTs[i]),
        });
        return result;
      }

      if (!result.decodedSubjectJWTs[i][JWTClaims.SYNDICATION_ID_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SYNDICATION_ID_CLAIM, result.decodedSubjectLinkJWTs[i]),
        });
        return result;
      }

      if (!result.decodedSubjectLinkJWTs[i][JWTClaims.SUBJECT_LINK_CLAIM]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_LINK_CLAIM, result.decodedSubjectLinkJWTs[i]),
        });
        return result;
      }

      // basic verification of the link credential
      let link = result.decodedSubjectLinkJWTs[i][JWTClaims.SUBJECT_LINK_CLAIM];

      if (!link[PN_P.subject]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s  in link in JWT:%j', PN_P.subject, result.decodedSubjectLinkJWTs[i]),
        });
        return result;
      }

      if (!link[PN_P.linkSubject]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s  in link in JWT:%j', PN_P.linkSubject, result.decodedSubjectLinkJWTs[i]),
        });
        return result;
      }

      if (!link[PN_P.syndicatedEntity]) {
        result.error = PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
          errMsg: util.format('ERROR no %s  in link in JWT:%j', PN_P.syndicatedEntity, result.decodedSubjectLinkJWTs[i]),
        });
        return result;
      }

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

    if ((props) && (props.syndicationId)) {
      assert(false, 'props.syndicationId no longer supported');
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

    // Note the data should be encypted as passing from the rspa to the IS - but as test data only
    // used for sub systems tests only encrypt taxID for now add the rest later - this is taken from the
    // rspa log so valid.
    let alice = TestReferenceSourcePNDataModel.canons.createAlice({ domainName: serviceCtx.config.DOMAIN_NAME, });
    alice['https://schema.org/taxID'] = {
      '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/rs#rspa-paction1488493433-1',
      '@value': '3AtEhwBZxE858c15..lvmfA2gx7Ea1B6c5k1JL0YnKxgue5hAhj47gL64=',
    };

    let aliceJWT = JWTUtils.signSubject(
        alice, pnDataModelId, canonConstants.ALICE_SYNDICATION_JOB_ID,
        serviceCtx.config.crypto.jwt, { subject: alice['@id'], privacyPipe: privacyPipeId, });

    // Note the data should be encypted as passing from the rspa to the IS - but as test data only
    // used for sub systems tests only encrypt taxID for now add the rest later - this is taken from the
    // rspa log so valid.
    let bob = TestReferenceSourcePNDataModel.canons.createBob({ domainName: serviceCtx.config.DOMAIN_NAME, });
    bob['https://schema.org/taxID'] = {
      '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/rs#rspa-paction1488493433-1',
      '@value': 'TOI6mjg/63U8cyLt../Mw19A2Oo7atBxJr+6gFDCGRo/FBHVCyipiu',
    };

    let bobJWT = JWTUtils.signSubject(
        alice, pnDataModelId, canonConstants.BOB_SYNDICATION_JOB_ID,
        serviceCtx.config.crypto.jwt, { subject: bob['@id'], privacyPipe: privacyPipeId, });

    //
    // create links credentials
    //
    let aliceLink = {
      '@id': PNDataModel.ids.createSubjectLinkId('fake.com', 'link-1'), // note the RSPA will convert to a URL
      '@type': PN_T.SubjectLinkCredential,
      [PN_P.linkSubject]: { '@id': alice['@id'], '@type': alice['@type'], }, // the reference source subject
      [PN_P.syndicatedEntity]: 'https://pn.id.webshield.io/syndicated_entity/localhost#test-se-1', // hard coded from RSQuery canon!!!!
      [PN_P.subject]: [BaseSubjectPNDataModel.canons.data.alice.id],
    };

    let aliceLinkJWT = JWTUtils.signSubjectLink(aliceLink, canonConstants.ALICE_SYNDICATION_JOB_ID,
                                  serviceCtx.config.crypto.jwt,
                                  { subject: aliceLink['@id'], });

    let bobLink = {
      '@id': PNDataModel.ids.createSubjectLinkId('fake.com', 'link-2'), // note the RSPA will convert to a URL
      '@type': PN_T.SubjectLinkCredential,
      [PN_P.linkSubject]: { '@id': bob['@id'], '@type': bob['@type'], }, // the reference source subject
      [PN_P.syndicatedEntity]: 'https://pn.id.webshield.io/syndicated_entity/localhost#test-se-2', // hard coded from RSQuery canon!!!!
      [PN_P.subject]: [BaseSubjectPNDataModel.canons.data.bob.id],
    };

    let bobLinkJWT = JWTUtils.signSubjectLink(bobLink, canonConstants.BOB_SYNDICATION_JOB_ID,
                                  serviceCtx.config.crypto.jwt,
                                  { subject: bobLink['@id'], });

    let rsQueryResultJWT = JWTUtils.signRSQueryResult(
                              queryResult,
                              [aliceJWT, bobJWT],
                              [aliceLinkJWT, bobLinkJWT],
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
