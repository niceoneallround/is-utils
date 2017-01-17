/*jslint node: true, vars: true */

const assert = require('assert');
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const RSPQuery = require('../lib/RSPQuery');
const testUtils = require('node-utils/testing-utils/lib/utils');
const should = require('should');
const util = require('util');

describe('1 Test Create', function () {
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

  it('1.2 validate canon JWT', function () {

    let canonJWT = RSPQuery.createCanonJWT(dummyServiceCtx, {});
    let valid = RSPQuery.validateJWT(dummyServiceCtx, canonJWT);
    assert(!valid.error, util.format('Query should be valid:%j', valid.error));

    let qry = JWTUtils.getPnGraph(valid.decoded);

    qry.should.have.property(PN_P.privacyContext);
    qry[PN_P.privacyContext].should.have.property(PN_P.privacyActionInstance2Deobfuscate);
  }); // 1.2

}); // describe 1
