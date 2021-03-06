/*jslint node: true, vars: true */
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const localTestUtils = require('./testUtils').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const testUtils = require('node-utils/testing-utils/lib/utils');
const Query = require('../lib/Query');

describe('1 Test Query', function () {
  'use strict';

  let dummyServiceCtx;
  const createProps = { qpaId: 'test-id', };

  before(function (done) {
    let props = {};
    props.name = 'test-is-messages';
    testUtils.createDummyServiceCtx(props, function (ctx) {
      dummyServiceCtx = ctx;
      dummyServiceCtx.config = localTestUtils.getTestConfig();
      done();
    });
  });

  it('1.1 should create an internal subject query with all the public query information', function () {

    let publicJSON = Query.createPublicJSONCanonById(); // use default id

    let mess = Query.createJSONFromPublicJSON(publicJSON, 'fakehostname.com', createProps);
    mess.should.have.property('@id');
    mess.should.have.property('@type', PN_T.SubjectQuery);
    mess.should.have.property(PN_P.queryPrivacyAgent, 'test-id');
    mess.should.have.property(PN_P.queryNodes);
    mess[PN_P.queryNodes].length.should.be.equal(1);

    let node = mess[PN_P.queryNodes][0];
    node.should.have.property('@id');
    node.should.have.property('@type', [PN_T.QueryNode]);
    node.should.have.property(PN_P.queryResultGraphProp, 'bob');

    node.should.have.property(PN_P.params);
    node[PN_P.params].should.have.property('@id');
    node[PN_P.params].should.have.property('@type', PN_T.SubjectQueryRestriction);
    node[PN_P.params].should.have.property(PN_P.subjectID);

    node.should.have.property(PN_P.properties);
    let keys = Object.keys(node[PN_P.properties]);
    keys.should.be.eql([
      'familyName',
      'givenName',
      'taxID',
    ]);
  }); // 1.1

  it('1.2 should create a JWT with all the necessary information', function () {

    let publicJSON = Query.createPublicJSONCanonById(); // use default id
    let mess = Query.createJSONFromPublicJSON(publicJSON, 'fakehostname.com', createProps);
    let jwt = Query.createJWT(dummyServiceCtx, { query: mess, privacyPipeId: 'pipe-1', });

    let decoded = JWTUtils.decode(jwt);
    decoded.should.have.property('sub', mess['@id']);
  }); // 1.2

  it('1.3 should create a canon in the internal format query ', function () {
    let qry = Query.createInternalJSONCanonById();
    qry.should.have.property('@id');
  }); // 1.3

  it('1.4 should verify a request JWT and pass back a structure containing decoded and query', function () {
    let publicJSON = Query.createPublicJSONCanonById(); // use default id
    let mess = Query.createJSONFromPublicJSON(publicJSON, 'fakehostname.com', createProps);
    let jwt = Query.createJWT(dummyServiceCtx, { query: mess, privacyPipeId: 'pipe-1', });

    let result = Query.validateJWT(dummyServiceCtx, jwt);
    result.should.not.have.property('error');
    result.should.have.property('decoded');
    result.should.have.property('query');
    result.should.have.property('privacyPipeId');
  }); // 1.4

  it('1.5 should create an ack message JWT that contains the query id', function () {

    let publicJSON = Query.createPublicJSONCanonById(); // use default id
    let mess = Query.createJSONFromPublicJSON(publicJSON, 'fakehostname.com', createProps);
    let jwt = Query.createJWT(dummyServiceCtx, { query: mess, privacyPipeId: 'pipe-1', });
    let valid = Query.validateJWT(dummyServiceCtx, jwt);

    let messageAck = Query.createMessageAckJWT(dummyServiceCtx, valid.decoded);
    let decoded = JWTUtils.decode(messageAck);
    decoded.should.have.property(JWTClaims.MESSAGE_ACK_ID_CLAIM, valid.decoded[JWTClaims.SUBJECT_QUERY_CLAIM]['@id']);
  }); // 1.5

}); // describe 1
