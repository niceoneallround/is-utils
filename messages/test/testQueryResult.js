/*jslint node: true */
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
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
    console.log(validated);
    validated.should.not.have.property('error');
    validated.should.have.property('decoded');
    validated.should.have.property('subjectJWTs');
    validated.should.have.property('decodedSubjectJWTs');
    validated.decodedSubjectJWTs.length.should.be.equal(1);
    validated.should.have.property('subjects');
    validated.subjects.length.should.be.equal(1);
  }); // 1.1

  it('1.2 should return a ack JWT from a valid message', function () {
    let queryResultJWT = QueryResult.createJWT(dummyServiceCtx, createProps);
    let validated = QueryResult.validateJWT(dummyServiceCtx, queryResultJWT);
    let messageAck = QueryResult.createMessageAckJWT(dummyServiceCtx, validated.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, validated.decoded[JWTClaims.SUBJECT_QUERY_RESULT_CLAIM]['@id']);
  }); // 1.2

  it('1.3 should return a canon queryResultJWT', function () {
    let queryResultJWT = QueryResult.createCanonJWT(dummyServiceCtx);
    let validated = QueryResult.validateJWT(dummyServiceCtx, queryResultJWT);
    validated.should.not.have.property('error');
  }); // 1.3

  it('1.4 should return query result node', function () {
    const qnProps = {
      queryNode: { '@id': 'canon-qry-node-id', [PN_P.queryResultGraphProp]: 'bob', },
      ses: ['resultGraph'],
    };

    let queryNode = QueryResult.createQueryResultNode(qnProps);
    queryNode.should.have.property('@id');
    queryNode.should.have.property('@type', [PN_T.QueryResultNode]);
    queryNode.should.have.property(PN_P.respondingTo, 'canon-qry-node-id');
    queryNode.should.have.property(PN_P.queryResultGraphProp, 'bob');
    queryNode.should.have.property(PN_P.syndicatedEntity, ['resultGraph']);
  }); // 1.3

}); // describe 1
