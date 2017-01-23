/*jslint node: true, vars: true */

const assert = require('assert');
const localTestUtils = require('./testUtils').utils;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const RSPQueryResult = require('../lib/RSPQueryResult');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const testUtils = require('node-utils/testing-utils/lib/utils');
const should = require('should');

describe('1 Test Validate', function () {
  'use strict';

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

    let props = {
      respondingTo: 'respond-1',
      message: 'fake-jwt',
    };

    let jwt = RSPQueryResult.createJWT(dummyServiceCtx, props);
    let validated = RSPQueryResult.validateJWT(dummyServiceCtx, jwt);
    console.log(validated);
    validated.should.not.have.property('error');
    validated.should.have.property('decoded');
    validated.should.have.property('query');
    validated.query.should.have.property(PN_P.respondingTo, 'respond-1');
    validated.should.have.property('message');
  }); // 1.1

  it('1.2 should return error if jwt is malformed', function () {
    let result = RSPQueryResult.validateJWT(dummyServiceCtx, 'fake-jwt-SO_SHOULD_BE-AN_ERROR');
    result.should.have.property('error');
  }); // 1.2

  it('1.3 canon should be valid', function () {
    let canonJWT = RSPQueryResult.createCanonJWT(dummyServiceCtx, {});
    assert(canonJWT, 'no canon returned');

    let validated = RSPQueryResult.validateJWT(dummyServiceCtx, canonJWT);
    validated.should.not.have.property('error');
  }); // 1.3

  it('1.4 validate message ack JWT', function () {

    let canonJWT = RSPQueryResult.createCanonJWT(dummyServiceCtx, {});
    let valid = RSPQueryResult.validateJWT(dummyServiceCtx, canonJWT);
    let messageAck = RSPQueryResult.createMessageAckJWT(dummyServiceCtx, valid.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, valid.decoded[JWTClaims.QUERY_CLAIM]['@id']);
  }); // 1.4

}); // describe 1
