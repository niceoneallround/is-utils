/*jslint node: true */
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const QueryResult = require('../lib/QueryResult');
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const testUtils = require('node-utils/testing-utils/lib/utils');
const should = require('should');

describe('1 Test Query Result', function () {
  'use strict';

  let dummyServiceCtx;
  const config = localTestUtils.getTestConfig();

  const pnDataModelId = 'pn_data_model_id_1';
  const syndicationId = 'syndicationId-1';
  const privacyPipeId = 'ppId-1';

  const alice = TestReferenceSourcePNDataModel.canons.createAlice({ domainName: config.DOMAIN_NAME, });
  const aliceJWT = JWTUtils.signSubject(
      alice, pnDataModelId, syndicationId, config.crypto.jwt, { subject: alice['@id'], privacyPipe: privacyPipeId, });

  const createProps = {
      queryPrivacyAgentId: 'qpaId',
      queryId: 'queryId',
      queryResultNodes: ['node1'],
      subjectJWTs: [aliceJWT],
      privacyPipeId: privacyPipeId,
    };

  before(function (done) {
    let props = {};
    props.name = 'test-is-messages';
    testUtils.createDummyServiceCtx(props, function (ctx) {
      dummyServiceCtx = ctx;
      dummyServiceCtx.config = config;
      done();
    });
  });

  it('1.1 should return a query result JWT from create that is valid', function () {
    let queryResultJWT = QueryResult.createJWT(dummyServiceCtx, createProps);
    let validated = QueryResult.validateJWT(dummyServiceCtx, queryResultJWT);
    validated.should.not.have.property('error');
    validated.should.have.property('decoded');
    validated.should.have.property('subjectJWTs');
    validated.should.have.property('decodedSubjectJWTs');
  }); // 1.1

  it('1.2 should return a ack JWT from a valid message', function () {
    let queryResultJWT = QueryResult.createJWT(dummyServiceCtx, createProps);
    let validated = QueryResult.validateJWT(dummyServiceCtx, queryResultJWT);
    let messageAck = QueryResult.createMessageAckJWT(dummyServiceCtx, validated.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, validated.decoded[JWTClaims.SUBJECT_QUERY_RESULT_CLAIM]['@id']);
  }); // 1.2

}); // describe 1
