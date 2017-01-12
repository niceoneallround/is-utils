/*jslint node: true, vars: true */

const assert = require('assert');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const RSQuery = require('../lib/rsQuery');
const testUtils = require('node-utils/testing-utils/lib/utils');
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const TRSCanons = TestReferenceSourcePNDataModel.canons;
const should = require('should');
const util = require('util');

describe('1 Test Create', function () {
  'use strict';

  const pnDataModelId = 'pn_data_model_id_1';
  const privacyPipeId = 'ppId-1';
  const postBackURL = 'post-url';

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

  it('1.1 should create a valid rsQuery JWT', function () {

    let alice = TRSCanons.createAlice({ domainName: dummyServiceCtx.config.DOMAIN_NAME, });
    let bob = TRSCanons.createBob({ domainName: dummyServiceCtx.config.DOMAIN_NAME, });
    let subjects = [alice, bob];

    let props = {
      postBackURL: postBackURL,
      pnDataModelId: pnDataModelId,
      privacyPipeId: privacyPipeId,
      subjects: subjects,
      syndicatedEntities: [],
    };

    let rsQueryJWT = RSQuery.createJWT(dummyServiceCtx, props);
    let valid = RSQuery.validateJWT(dummyServiceCtx, rsQueryJWT);
    assert(!valid.error, util.format('Query should be valid:%j', valid.error));
  }); // 1.1

  it('1.2 validate canon JWT', function () {

    let canonJWT = RSQuery.createCanonJWT(dummyServiceCtx, {});
    let valid = RSQuery.validateJWT(dummyServiceCtx, canonJWT);
    assert(!valid.error, util.format('Query should be valid:%j', valid.error));
  }); // 1.2

  it('1.3 validate message ack JWT', function () {

    let canonJWT = RSQuery.createCanonJWT(dummyServiceCtx, {});
    let valid = RSQuery.validateJWT(dummyServiceCtx, canonJWT);
    let messageAck = RSQuery.createMessageAckJWT(dummyServiceCtx, valid.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, valid.decoded[JWTClaims.QUERY_CLAIM]['@id']);
  }); // 1.2

}); // describe 1
