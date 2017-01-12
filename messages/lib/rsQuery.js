/*

This message is a JWT sent from the Reference Source Proxy to the Reference Source Privacy Agent
via the Reference Source Adapter.

It asks the reference source to query for the passed in subjects with the output
being subject link credential, and a reference source subject containing any identity
properties and any enrichment properties. The result is sent back asynchronously using
and obfuscate privacy pipe.

The RS Query JWT contains the following claims
- a PN_JWT_TYPE_CLAM  of pn_t.rsQuery
- a QUERY_CLAIM - contains a pn_t.RSQuery jsonld node as described below
- a PRIVACY_PIPE_CLAIM - this is the pipe used to send the data to the reference source - a deobfuscate pipe
- a SUBJECT_CLAIM - an array of all the subjects jsonld nodes needed by the syndicated entity.
  - These are privacy graphs in source data model format, with obfuscated data.

The pn_t.rsQuery node has the following properties
- @id
- @type
- pn_p.postBackUrl - where to post the query results
- pn_p.pnDataModel - the @id of the data model used to create the syndicated entities
- pn_p.syndicated_entities: the array of syndicated entities that should be queried for.

*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils').npUtils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTType = require('jwt-utils/lib/jwtUtils').jwtType;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const util = require('util');

class RSQuery {

  static createJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(props, 'props param is missing');
    assert(props.pnDataModelId, util.format('props.pnDataModelId param is missing:%j', props));
    assert(props.postBackURL, util.format('props.postBackURL param is missing:%j', props));
    assert(props.privacyPipeId, util.format('props.privacyPipeId param is missing:%j', props));
    assert(props.subjects, util.format('props.subjects param is missing:%j', props));
    assert(props.syndicatedEntities, util.format('props.syndicatedEntities param is missing:%j', props));

    let query = {
      '@id': PNDataModel.ids.createQueryId(serviceCtx.config.DOMAIN_NAME, moment().unix()),
      '@type': [PN_T.RSSubjectQuery],
      [PN_P.postBackUrl]: props.postBackURL,
      [PN_P.pnDataModel]: props.pnDataModelId,
      [PN_P.syndicatedEntity]: props.syndicatedEntities,
    };

    return JWTUtils.signRSQuery(
            query,
            props.subjects, props.privacyPipeId,
            serviceCtx.config.crypto.jwt, { subject: query['@id'], });
  }

  /* OUTPUTs a stucture

      { error: the jwt was somehow invalid so send a bad request to caller,
        query: the query claim
        subjects: the subject claim
        privacyPipe: the privacy pipe claim,
        decoded: the decoded JWT}
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

    if (!result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PN_JWT_TYPE_CLAIM, result.decoded),
      });

      return result;
    }

    if (result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM] !== JWTType.rsQuery) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR JWT not expected type::%s JWT:%j', JWTType.rsQuery, result.decoded),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.QUERY_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.QUERY_CLAIM, result.decoded),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.SUBJECT_CLAIM]) {
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

    //
    // validate the query
    result.query = result.decoded[JWTClaims.QUERY_CLAIM];
    console.log(result.query);
    if (!((JSONLDUtils.isType(result.query, PN_T.RSSubjectQuery)))) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.RSSubjectQuery, result.query),
      });

      return result;
    }

    if (!result.query[PN_P.postBackUrl]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR property [%s] missing in:%j', PN_P.postBackUrl, result.query),
      });

      return result;
    }

    if (!result.query[PN_P.syndicatedEntity]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR property [%s] missing in:%j', PN_P.syndicatedEntity, result.query),
      });

      return result;
    }

    if (!result.query[PN_P.pnDataModel]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR property [%s] missing in:%j', PN_P.pnDataModel, result.query),
      });

      return result;
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

    let pnDataModelId = 'pnDataModelId-1';
    if ((props) && (props.pnDataModelId)) {
      pnDataModelId = props.pnDataModelId;
    }

    let privacyPipeId = 'ppId-1';
    if ((props) && (props.privacyPipeId)) {
      privacyPipeId = props.privacyPipeId;
    }

    let postBackURL = 'http://fake';
    if ((props) && (props.postBackURL)) {
      postBackURL = props.postBackURL;
    }

    let query = {
      '@id': 'fake-query-id',
      '@type': [PN_T.RSSubjectQuery],
      [PN_P.pnDataModel]: pnDataModelId,
      [PN_P.syndicatedEntities]: [], };

    let alice = TestReferenceSourcePNDataModel.canons.createAlice({ domainName: serviceCtx.config.DOMAIN_NAME, });
    let bob = TestReferenceSourcePNDataModel.canons.createBob({ domainName: serviceCtx.config.DOMAIN_NAME, });

    let createProps = {
      query: query,
      postBackURL: postBackURL,
      pnDataModelId: pnDataModelId,
      privacyPipeId: privacyPipeId,
      subjects: [alice, bob],
      syndicatedEntities: [],
    };

    return RSQuery.createJWT(serviceCtx, createProps);

  }

} // class

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const rsQueryResult = require('..../rsQueryResult');
// result = rsQueryResult.validateJWT()
//
module.exports = RSQuery;
