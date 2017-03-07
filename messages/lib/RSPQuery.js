/*jslint node: true */
/*

This message is a JWT sent from the Identity Syndicate to Reference Source Proxy

It causes the RSP to create a de-obfuscate privacy pipe to the specified Reference Source
and send a RSQuery to the Reference Source.

There is a V1 and a V2 format both are query nodes help in the PN_GRAPH_CLAIM.

This code only handles V2 format, as phasing out V1 once completed V2 code.

The Query has the following properties

  qry['@id'] = a generic message id used in logs
  qry['@type'] = PN_T.RSPSubjectQuery;
  qry[PN_P.referenceSource] = the reference source JSON-LD node to send query to - not @id but object
  qry[PN_P.privacyContext] = props.privacyContext;
    - PN_P.subjectPrivacyPipe = the privacy pipe used to load the subjects - do not think need this
    - PN_P.privacyActionInstance2Deobfuscate - the PAI to see if can de-obfuscate
  qry[PN_P.subject] = Array of subjects to send
  qry[PN_P.version] = 'v2'
  qry[PN_P.syndicatedEntity] = Array of syndicated entities to send that are built from subject data

*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils').npUtils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const SyndicatedEntity = require('../../se/lib/SyndicatedEntity');
const PrivacyPNDataModelUtils = require('data-models/lib/PrivacyPNDataModel').utils;
const RSCanon = require('metadata/lib/referenceSource').canons;
const util = require('util');

class RSPQuery {

  /* OUTPUTs a stucture

     NOTE THIS IS A SKELETON UNTIL MOVE TO V2 silly to write thne throw away

      { error: the jwt was somehow invalid so send a bad request to caller,
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

    if (!result.decoded[JWTClaims.PN_GRAPH_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PN_JWT_TYPE_CLAIM, result.decoded),
      });

      return result;
    }

    return result;
  }

  //
  // Create a canon RSPQuery JWT that can be used for testing
  // props.privacyPipeId - optional
  static createCanonJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');

    const hostname = serviceCtx.config.getHostname();

    let privacyPipeId = 'canon-ppId-1';
    if ((props) && (props.privacyPipeId)) {
      privacyPipeId = props.privacyPipeId;
    }

    let qry = {
      '@id': PNDataModel.ids.createMessageId(hostname, moment().unix()),
      '@type': PN_T.RSPSubjectQuery,
      [PN_P.version]: 'v2',
      [PN_P.referenceSource]: RSCanon.createTestReferenceSource(
            { hostname: serviceCtx.config.getHostname(), domainName: serviceCtx.config.DOMAIN_NAME, }),
    };

    qry[PN_P.privacyContext] = PrivacyPNDataModelUtils.createPrivacyContext({ hostname: 'fake.hostname' });
    qry[PN_P.privacyContext][PN_P.subjectPrivacyPipe] = privacyPipeId;

    //
    // This is the PAI from the subject data
    //
    qry[PN_P.privacyContext][PN_P.privacyActionInstance2Deobfuscate] = [
      'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111',
    ];

    // this subject data is tied to content encrypt key metadata
    // https://md.pn.id.webshield.io/encrypt_key_md/io/webshield/test/dc#content-key-1
    //
    // Note the suject type is the base subject -  needs to be this to work with the canon privacy step instance
    qry[PN_P.subject] = [
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

    //
    // Create a syndicated entity in the format of the target reference source data model
    // FOR NOW JUST HARD CODE as FOLLOWS
    // - just use name and given name
    qry[PN_P.syndicatedEntity] = [];

    let subject = qry[PN_P.subject][0];
    let se = new SyndicatedEntity('canon-se-id-1', {
      hostname: 'fake.com',
      pnDataModelId: JSONLDUtils.getId(qry[PN_P.referenceSource], PN_P.pnDataModel),
      jobId: 'canon-jobid-1',
    });

    se.addProperty('https://schema.org/givenName', // target schema the test referecne source
                subject['@id'], 'https://schema.org/givenName', 'jwt1-rspquery-canon');
    se.addProperty('https://schema.org/familyName', subject['@id'],
                'https://schema.org/familyName', 'jwt1-rspquery-canon');

    qry[PN_P.syndicatedEntity].push(se);

    subject = qry[PN_P.subject][1];
    se = new SyndicatedEntity('canon-se-id-2', {
      hostname: 'fake.com',
      pnDataModelId: JSONLDUtils.getId(qry[PN_P.referenceSource], PN_P.pnDataModel),
      jobId: 'canon-jobid-2',
    });

    se.addProperty('https://schema.org/givenName', // target schema the test referecne source
                subject['@id'], 'https://schema.org/givenName', 'jwt2-rspquery-canon');
    se.addProperty('https://schema.org/familyName', subject['@id'],
                'https://schema.org/familyName', 'jwt2-rspquery-canon');

    qry[PN_P.syndicatedEntity].push(se);

    /*// create syndicated entity based on above subjects
    qry[PN_P.syndicatedEntity] = [
      PNSyndicatedEntity.createJSON('canon-se-id-1',
        {
          hostname: 'fake.com',
          jobId: 'canon-jobid-1',
          pnDataModelId: JSONLDUtils.getId(qry[PN_P.referenceSource], PN_P.pnDataModel),
          subjectIds: qry[PN_P.subject][0]['@id'],
        }),
      PNSyndicatedEntity.createJSON('canon-se-id-2',
        {
          hostname: 'fake.com',
          jobId: 'canon-jobid-2',
          pnDataModelId: JSONLDUtils.getId(qry[PN_P.referenceSource], PN_P.pnDataModel),
          subjectIds: qry[PN_P.subject][1]['@id'],
        }),
      ];*/

    return JWTUtils.signData(qry, serviceCtx.config.crypto.jwt, {});
  }
}

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const rsQueryResult = require('..../rsQueryResult');
// result = rsQueryResult.validateJWT()
//
module.exports = RSPQuery;
