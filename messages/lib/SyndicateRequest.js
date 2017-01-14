/*

This message is a JWT sent from the Ingest Privacy Agent to the Identity Syndicate.

It asks the Identity Syndicate to save the subject JWTs to the obfuscated data lake
and for each subject starts a subject enrichment and linking job.

The response is sent once the message is verified, not processed, and is either
a signed ack or a signed error.

The caller users the IS query jobs interface using there passed in tag to find the reevant jobs

The RS Query JWT contains the following claims
- a PN_JWT_TYPE_CLAM  of pn_t.syndicate_request
- a SYNDICATE_REQUEST_CLAIM - contains a PN_T.SubjectSyndicationRequest jsonld node as described below
- a PRIVACY_PIPE_CLAIM - this is the pipe used to send the data to the reference source - a deobfuscate pipe
- a SUBJECT_JWTS_CLAIM - an array of all the subjects JWTs containing the subject jsonld nodes needed by the syndicated entity.
  - These are privacy graphs in source data model format, with obfuscated data.

A PN_T.SubjectSyndicationRequest has the following properties
- @id: the globally unique id
- @type: PN_T.SubjectSyndicationRequest
- pn_p.user_tag: a tag that can be used by the issuer to look for the results
- pn_p.identity_syndication_algorithm: the @id of the syndication algorithm to use

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
const util = require('util');

class SyndicateRequest {

  static createJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(props, 'props param is missing');
    assert(props.userTag, util.format('props.userTag param is missing:%j', props));
    assert(props.isa, util.format('props.isa param is missing:%j', props));
    assert(props.privacyPipeId, util.format('props.privacyPipeId param is missing:%j', props));
    assert(props.subjectJWTs, util.format('props.subjectJWTs param is missing:%j', props));

    const loggingMD = {
            ServiceType: serviceCtx.serviceName,
            FileName: 'isUtils/rsQueryResult.js', };

    let syndRequest = {
      '@id': PNDataModel.ids.createSyndicationRequestId(serviceCtx.config.DOMAIN_NAME, moment().unix()),
      '@type': [PN_T.SubjectSyndicationRequest],
      [PN_P.userTag]: props.userTag,
      [PN_P.identitySyndicationAlgorithm]: props.isa,
    };

    // allow id to overrriden
    if (props.id) {
      syndRequest['@id'] = props.id;
    }

    serviceCtx.logger.logJSON('info', { serviceType: serviceCtx.name,
                                        action: 'Create-Syndicate-Request-JWT',
                                        data: syndRequest, }, loggingMD);

    return JWTUtils.signSyndicateRequest(
                    syndRequest,
                    props.subjectJWTs,
                    props.privacyPipeId,
                    serviceCtx.config.crypto.jwt, { subject: syndRequest['@id'], });

  }

  // The message ack JWT just contains the @id
  static createMessageAckJWT(serviceCtx, decoded) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(decoded, 'query param is missing');

    let queryId = decoded[JWTClaims.SYNDICATE_REQUEST_CLAIM]['@id'];
    return JWTUtils.signMessageAck(queryId, serviceCtx.config.crypto.jwt);
  }

  /* OUTPUTs a stucture

      { error: the jwt was somehow invalid so send a bad request to caller,
        syndicateRequest: the syndicat request claim
        subjectJWTsDecoded: the decoded subjectJWTs payloads
        privacyPipe: the privacy pipe claim,
        decoded: the decoded JWT}
  */
  static validateJWT(serviceCtx, inputJWT) {

    const loggingMD = {
            ServiceType: serviceCtx.serviceName,
            FileName: 'isUtils/syndicateRequest.js', };

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
                                    action: 'SyndicateRequest-ERROR-JWT-VERIFY',
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

    if (result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM] !== JWTType.syndicateRequest) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR JWT not expected type::%s JWT:%j', JWTType.syndicateRequest, result.decoded),
      });

      return result;
    }

    if (!result.decoded[JWTClaims.SYNDICATE_REQUEST_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SYNDICATE_REQUEST_CLAIM, result.decoded),
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

    //
    // validate the query
    result.syndicateRequest = result.decoded[JWTClaims.SYNDICATE_REQUEST_CLAIM];
    console.log(result.syndicateRequest);
    if (!((JSONLDUtils.isType(result.syndicateRequest, PN_T.SubjectSyndicationRequest)))) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.RSSubjectQuery, result.syndicateRequest),
      });

      return result;
    }

    if (!result.syndicateRequest[PN_P.userTag]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR property [%s] missing in:%j', PN_P.userTag, result.syndicateRequest),
      });

      return result;
    }

    if (!result.syndicateRequest[PN_P.identitySyndicationAlgorithm]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR property [%s] missing in:%j', PN_P.identitySyndicationAlgorithm, result.syndicateRequest),
      });

      return result;
    }

    return result;
  }

  //
  // Create a canon syndicate rqeuest JWT that can be used for testing
  // props.userTag - optional
  // props.isa - optional
  // props.privacyPipeId - optional
  // props.pnDataModelId - optional - stamped in the subject JWTs
  static createCanonJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');

    let isa = 'isaId-1';
    if ((props) && (props.isa)) {
      isa = props.isa;
    }

    let privacyPipeId = 'ppId-1';
    if ((props) && (props.privacyPipeId)) {
      privacyPipeId = props.privacyPipeId;
    }

    let userTag = 'fake-user-tag';
    if ((props) && (props.userTag)) {
      userTag = props.userTag;
    }

    let pnDataModelId = 'pnDataModelId-1';
    if ((props) && (props.pnDataModelId)) {
      pnDataModelId = props.pnDataModelId;
    }

    let syndicationId = PNDataModel.ids.createSyndicationRequestId(serviceCtx.config.DOMAIN_NAME, moment().unix());

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

    let subjectJWTs = [];
    for (let i = 0; i < subjects; i++) {
      subjectJWTs.push(JWTUtils.signSubject(
                      subjects[i],
                      pnDataModelId,
                      syndicationId,
                      serviceCtx.config.crypto.jwt,
                      { subject: subjects[i]['@id'], })
                    );
    }

    let createProps = {
      userTag: userTag,
      isa: isa,
      privacyPipeId: privacyPipeId,
      subjectJWTs: subjectJWTs,
      id: syndicationId,
    };

    return SyndicateRequest.createJWT(serviceCtx, createProps);

  }

} // class

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const rsQueryResult = require('..../rsQueryResult');
// result = rsQueryResult.validateJWT()
//
module.exports = SyndicateRequest;
