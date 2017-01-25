/*jslint node: true, vars: true */

const assert = require('assert');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const SyndicateRequest = require('../lib/SyndicateRequest');
const testUtils = require('node-utils/testing-utils/lib/utils');
const should = require('should');
const util = require('util');

describe('1 Test Syndicate Request', function () {
  'use strict';

  const privacyPipeId = 'ppId-1';
  const userTag = 'fake-user-tag';
  const isa = 'fake-isa';

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

  it('1.1 should create a valid syndicate request JWT', function () {

    let createProps = {
      userTag: userTag,
      isa: isa,
      privacyPipeId: privacyPipeId,
      subjectJWTs: [],
    };

    let syndicateRequestJWT = SyndicateRequest.createJWT(dummyServiceCtx, createProps);
    let valid = SyndicateRequest.validateJWT(dummyServiceCtx, syndicateRequestJWT);
    assert(!valid.error, util.format('should be valid:%j', valid.error));
    valid.should.have.property('decoded');
    valid.should.have.property('syndicateRequest');
    valid.should.have.property('privacyPipeId');
    valid.should.have.property('subjectJWTsDecoded');
    valid.subjectJWTsDecoded.length.should.be.equal(0);
  }); // 1.1

  it('1.2 validate canon JWT', function () {
    let canonJWT = SyndicateRequest.createCanonJWT(dummyServiceCtx, {});
    let valid = SyndicateRequest.validateJWT(dummyServiceCtx, canonJWT);
    assert(!valid.error, util.format('should be valid:%j', valid.error));
    valid.should.have.property('decoded');
    valid.should.have.property('syndicateRequest');
    valid.should.have.property('privacyPipeId');
    valid.should.have.property('subjectJWTsDecoded');
    valid.subjectJWTsDecoded.length.should.be.equal(2);

    // make sure decoded subjects are for different subjects
    valid.subjectJWTsDecoded[0][JWTClaims.SUBJECT_CLAIM]['@id'].should.not.be.equal(
          valid.subjectJWTsDecoded[1][JWTClaims.SUBJECT_CLAIM]['@id']);

  }); // 1.2

  it('1.3 validate message ack JWT', function () {

    let syndicateRequestJWT = SyndicateRequest.createCanonJWT(dummyServiceCtx, {});
    let valid = SyndicateRequest.validateJWT(dummyServiceCtx, syndicateRequestJWT);
    let messageAck = SyndicateRequest.createMessageAckJWT(dummyServiceCtx, valid.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, valid.decoded[JWTClaims.SYNDICATE_REQUEST_CLAIM]['@id']);
  }); // 1.3

}); // describe 1
