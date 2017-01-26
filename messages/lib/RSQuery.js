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
- pn_p.post_back_URL - where to post the query results
- pn_p.pn_data_model - the @id of the data model used to create the syndicated entities
- pn_p.syndicated_entities: the array of syndicated entities that should be queried for.

*/

const assert = require('assert');
const canonConstants = require('./canonConstants');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils').npUtils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTType = require('jwt-utils/lib/jwtUtils').jwtType;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const PNSyndicatedEntity = require('data-models/lib/PNSyndicatedEntity');
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

    // allow id to overrriden - used for testing
    if (props.id) {
      query['@id'] = props.id;
    }

    return JWTUtils.signRSQuery(
            query,
            props.subjects, props.privacyPipeId,
            serviceCtx.config.crypto.jwt, { subject: query['@id'], });
  }

  // The message ack JWT just contains the @id
  static createMessageAckJWT(serviceCtx, decoded) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(decoded, 'query param is missing');

    let queryId = decoded[JWTClaims.QUERY_CLAIM]['@id'];
    return JWTUtils.signMessageAck(queryId, serviceCtx.config.crypto.jwt);
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
            FileName: 'isUtils/messages/rsQueryResult.js', };

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
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_CLAIM, result.decoded),
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

    const hostname = serviceCtx.config.getHostname();

    let pnDataModelId = TestReferenceSourcePNDataModel.model.ID;
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

    // this subject data is tied to content encrypt key metadata
    // https://md.pn.id.webshield.io/encrypt_key_md/io/webshield/test/dc#content-key-1
    //
    // Note the suject type is the base subject -  needs to be this to work with the canon privacy step instance
    let subjects = [
      {
        '@id': 'https://id.webshield.io/io/webshield/test/subject#111',
        '@type': [
          'https://subject.pn.schema.webshield.io/type#Subject',
          'http://pn.schema.webshield.io/type#PrivacyGraph',
        ],
        'https://schema.org/givenName': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
          '@value': 'BwY/p37oY1nhoFfO..y1oXJpIG52/tMiQJ9gM8lQ9YEQ==',
        },
        'https://schema.org/familyName': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
          '@value': 'E/jJ1i3xyFElWMeM..lphpi5id1rXwkbXOj5zvYapUD2sw1K4=',
        },
        'https://schema.org/taxID': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#invalid-so-will-not-decrypt',
          '@value': 'E/jJ1i3xyFElWMeM..lphpi5id1rXwkbXOj5zvYapUD2sw1K4=',
        },
        'http://pn.schema.webshield.io/prop#sourceID': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
          '@value': 'sqOU8UjpmO/HCzS4..suxTN7CGGMXG82AD7pM0vxGZmQ==',
        },
        'https://schema.org/address': {
          '@id': 'https://id.webshield.io/io/webshield/test/address#adr_1',
          '@type': 'https://schema.org/PostalAddress',
          'https://schema.org/postalCode': {
            '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
            '@value': '66DRmDUnumKXJlxE..u2pceQfCCexJFXzruOhmuWPyPa0Q',
          },
        },
      },
      {
        '@id': 'https://id.webshield.io/io/webshield/test/subject#222',
        '@type': [
          'https://subject.pn.schema.webshield.io/type#Subject',
          'http://pn.schema.webshield.io/type#PrivacyGraph',
        ],
        'https://schema.org/givenName': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
          '@value': 'kMqyinSWZ5hOMqL9..KTNxgYEFhprKvuScZG7aGRgrxr5p',
        },
        'https://schema.org/familyName': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
          '@value': 'W3mfgDnGOtbva6WT..DPJK4Md0EzV/cQnvn72DdoITYiRZ',
        },
        'https://schema.org/taxID': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#invalid-so-will-not-decrypt',
          '@value': 'E/jJ1i3xyFElWMeM..lphpi5id1rXwkbXOj5zvYapUD2sw1K4=',
        },
        'http://pn.schema.webshield.io/prop#sourceID': {
          '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
          '@value': 'BVaHuCa/tS4CZTyR..cAwRnxvEM9IOAZewoZERHOoWUQ==',
        },
        'https://schema.org/address': {
          '@id': 'https://id.webshield.io/io/webshield/test/address#adr_2',
          '@type': 'https://schema.org/PostalAddress',
          'https://schema.org/postalCode': {
            '@type': 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
            '@value': 'JPmAsz6ibgbNE9mk..posJpbMs4vdScEyJ7JUfBvWYgzH7',
          },
        },
      },
    ];

    let syndEnts = [
      PNSyndicatedEntity.createJSON('test-se-1',
        { hostname: hostname,
          jobId: canonConstants.ALICE_SYNDICATION_JOB_ID,
          pnDataModelId: pnDataModelId,
          subjectIds: subjects[0]['@id'],
        }),
      PNSyndicatedEntity.createJSON('test-se-2',
        { hostname: hostname,
          jobId: canonConstants.BOB_SYNDICATION_JOB_ID,
          pnDataModelId: pnDataModelId,
          subjectIds: subjects[1]['@id'],
        }),
    ];

    let createProps = {
      postBackURL: postBackURL,
      pnDataModelId: pnDataModelId,
      privacyPipeId: privacyPipeId,
      subjects: subjects,
      syndicatedEntities: syndEnts,
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
