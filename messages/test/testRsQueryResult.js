/*jslint node: true, vars: true */

const localTestUtils = require('./testUtils').utils;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const rsQueryResult = require('../lib/rsQueryResult');
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

    let rsQueryResultJWT = JWTUtils.signRSQueryResult(
                              queryResult,
                              [aliceJWT],
                              [], // link JWTs
                              privacyPipeId,
                              dummyServiceCtx.config.crypto.jwt,
                              { subject: queryResult['@id'], }
                            );

    let result = rsQueryResult.validateJWT(dummyServiceCtx, rsQueryResultJWT);
    console.log(result);
    result.should.not.have.property('error');
    result.should.have.property('decoded');
    result.should.have.property('decodedSubjectJWTs');
  }); // 1.1

  it('1.2 should return error if jwt is malformed', function () {
    let result = rsQueryResult.validateJWT(dummyServiceCtx, 'fake-jwt');
    result.should.have.property('error');
  }); // 1.1

}); // describe 1
