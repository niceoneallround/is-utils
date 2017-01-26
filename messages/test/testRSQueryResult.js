/*jslint node: true, vars: true */

const assert = require('assert');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const localTestUtils = require('./testUtils').utils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const rsQueryResult = require('../lib/RSQueryResult');
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const testUtils = require('node-utils/testing-utils/lib/utils');
const should = require('should');

describe('1 Test Validate', function () {
  'use strict';

  const pnDataModelId = 'pn_data_model_id_1';
  const syndicationId = 'syndicationId-1';
  const privacyPipeId = 'ppId-1';

  let dummyServiceCtx;

  before(function (done) {
    let props = {};
    props.name = 'test-is-messages';
    testUtils.createDummyServiceCtx(props, function (ctx) {
      dummyServiceCtx = ctx;
      dummyServiceCtx.config = localTestUtils.getTestConfig();
      done();
    });
  });

  it('1.1 should return results with no error if JWT is valid', function () {

    let queryResult = {
      '@id': 'fake-query',
      '@type': [PN_T.RSSubjectQueryResult],
      [PN_P.respondingTo]: 'id-1', };
    let alice = TestReferenceSourcePNDataModel.canons.createAlice({ domainName: dummyServiceCtx.config.DOMAIN_NAME, });
    let aliceJWT = JWTUtils.signSubject(
        alice, pnDataModelId, syndicationId, dummyServiceCtx.config.crypto.jwt, { subject: alice['@id'], });

    let aliceLink = {
      '@id': PNDataModel.ids.createSubjectLinkId('fake.com', 'link-1'), // note the RSPA will convert to a URL
      '@type': PN_T.SubjectLinkCredential,
      [PN_P.linkSubject]: { '@id': alice['@id'], '@type': alice['@type'], }, // the reference source subject
      [PN_P.syndicatedEntity]: 'https://pn.id.webshield.io/syndicated_entity/localhost#test-se-1', // hard coded from RSQuery canon!!!!
      [PN_P.subject]: [BaseSubjectPNDataModel.canons.data.alice.id],
    };

    let aliceLinkJWT = JWTUtils.signSubjectLink(aliceLink, syndicationId, dummyServiceCtx.config.crypto.jwt,
                                  { subject: aliceLink['@id'], });

    let rsQueryResultJWT = JWTUtils.signRSQueryResult(
                              queryResult,
                              [aliceJWT],
                              [aliceLinkJWT], // link JWTs
                              privacyPipeId,
                              dummyServiceCtx.config.crypto.jwt,
                              { subject: queryResult['@id'], }
                            );

    let result = rsQueryResult.validateJWT(dummyServiceCtx, rsQueryResultJWT);
    result.should.not.have.property('error');
    result.should.have.property('decoded');
    result.should.have.property('decodedSubjectJWTs');
    result.decodedSubjectJWTs.length.should.be.equal(1);
    result.should.have.property('decodedSubjectLinkJWTs');
    result.decodedSubjectLinkJWTs.length.should.be.equal(1);
  }); // 1.1

  it('1.2 should return error if jwt is malformed', function () {
    let result = rsQueryResult.validateJWT(dummyServiceCtx, 'fake-jwt-SO_SHOULD_BE-AN_ERROR');
    result.should.have.property('error');
  }); // 1.2

  it('1.3 canon should be valid', function () {
    let canon = rsQueryResult.createCanonJWT(dummyServiceCtx, {});
    assert(canon, 'no canon returned');

    let result = rsQueryResult.validateJWT(dummyServiceCtx, canon);
    result.should.not.have.property('error');
  }); // 1.3

  it('1.4 validate message ack JWT', function () {

    let canonJWT = rsQueryResult.createCanonJWT(dummyServiceCtx, {});
    let valid = rsQueryResult.validateJWT(dummyServiceCtx, canonJWT);
    let messageAck = rsQueryResult.createMessageAckJWT(dummyServiceCtx, valid.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, valid.decoded[JWTClaims.QUERY_CLAIM]['@id']);
  }); // 1.4

}); // describe 1
