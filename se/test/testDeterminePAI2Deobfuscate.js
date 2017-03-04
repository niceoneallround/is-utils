/*jslint node: true, vars: true */

const determinePAI2Deobfuscate = require('../lib/determinePAI2Deobfuscate').execute;
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const SyndicatedEntity = require('../lib/SyndicatedEntity');
const SyndicateRequest = require('../../messages/lib/SyndicateRequest');
const should = require('should');
const testUtils = require('node-utils/testing-utils/lib/utils');

describe('Test Determine PAI2Deobfuscate', function () {
  'use strict';

  let dummyServiceCtx;
  let srJWT;
  let decodedSR;
  let subjectJWTs;
  let decodedSubject1;
  let subject1;
  let decodedSubject2;
  let subject2;

  before(function (done) {
    let props = {};
    props.name = 'test-is-messages';
    testUtils.createDummyServiceCtx(props, function (ctx) {
      dummyServiceCtx = ctx;
      dummyServiceCtx.config = localTestUtils.getTestConfig();

      srJWT = SyndicateRequest.createCanonJWT(dummyServiceCtx, {});
      decodedSR = JWTUtils.decode(srJWT);
      subjectJWTs = decodedSR[JWTClaims.SUBJECT_JWTS_CLAIM];
      decodedSubject1 = JWTUtils.decode(subjectJWTs[0]);
      subject1 = decodedSubject1[JWTClaims.SUBJECT_CLAIM];

      decodedSubject2 = JWTUtils.decode(subjectJWTs[1]);
      subject2 = decodedSubject2[JWTClaims.SUBJECT_CLAIM];
      done();
    });
  });

  const seProps = {
    hostname: 'fake.com',
    pnDataModelId: 'dm_id',
    jobId: 'jobId',
  };

  it('1.1 should return a single {paiId, ppId} that needs to be deobfuscated',
        function () {

    // create the SE
    let se = new SyndicatedEntity('id1', seProps);
    se.addProperty('https://schema.org/givenName', subject1['@id'], 'https://schema.org/givenName', decodedSubject1[JWTClaims.JWT_ID_CLAIM]);
    se.addProperty('https://schema.org/familyName', subject1['@id'], 'https://schema.org/familyName', decodedSubject1[JWTClaims.JWT_ID_CLAIM]);

    let result = determinePAI2Deobfuscate(dummyServiceCtx, [se], subjectJWTs);
    result.length.should.be.equal(1);
    result[0].should.be.deepEqual({
          paiId: subject1['https://schema.org/givenName']['@type'], // the paid from the property value
          ppId: decodedSubject1[JWTClaims.PRIVACY_PIPE_CLAIM], });
  }); // 1.1

  it('1.2 should return a two {paiId, ppId} that needs to be deobfuscated',
        function () {

    // create the SE
    let se = new SyndicatedEntity('id1', seProps);
    se.addProperty('https://schema.org/givenName', subject1['@id'], 'https://schema.org/givenName', decodedSubject1[JWTClaims.JWT_ID_CLAIM]);
    se.addProperty('https://schema.org/familyName', subject1['@id'], 'https://schema.org/familyName', decodedSubject1[JWTClaims.JWT_ID_CLAIM]);

    se.addProperty('https://schema.org/taxID', subject2['@id'], 'https://schema.org/taxID', decodedSubject2[JWTClaims.JWT_ID_CLAIM]);

    let result = determinePAI2Deobfuscate(dummyServiceCtx, [se], subjectJWTs);
    result.length.should.be.equal(2);
    result[0].should.be.deepEqual({
          paiId: subject1['https://schema.org/givenName']['@type'], // the paid from the property value
          ppId: decodedSubject1[JWTClaims.PRIVACY_PIPE_CLAIM], });

    result[1].should.be.deepEqual({
          paiId: subject2['https://schema.org/taxID']['@type'], // the paid from the property value
          ppId: decodedSubject2[JWTClaims.PRIVACY_PIPE_CLAIM], });
  }); // 1.1

}); // describe
