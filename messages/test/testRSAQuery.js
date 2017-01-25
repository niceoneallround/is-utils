/*jslint node: true, vars: true */

const assert = require('assert');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const RSAQuery = require('../lib/RSAQuery');
const util = require('util');

describe('1 create JSON messages tests', function () {
  'use strict';

  it('1.1 should create a valid json message', function () {

    let subjectRestrictions =  [
      { '@id': '2', '@type': [PN_T.SubjectQueryRestriction], [PN_P.pnDataModel]: 'db1', },
      { '@id': '3', '@type': [PN_T.SubjectQueryRestriction], [PN_P.pnDataModel]: 'db1', },
    ];

    let domainName = 'abc.com';

    let mess = RSAQuery.createJSON(domainName, subjectRestrictions);
    mess.should.have.property('@id');
    mess.should.have.property('@type');
    mess.should.have.property('subject_restrictions', subjectRestrictions);
    mess.should.have.property('version', '2');
    let invalid = RSAQuery.validateJSON(mess, 'fakehost.com');
    assert(!invalid, util.format('should be valid:%j', invalid));
  }); // 1.1

  it('1.2 validate canon ', function () {

    let canon = RSAQuery.createCanonJSON();
    let invalid = RSAQuery.validateJSON(canon, 'fake.com');
    assert(!invalid, util.format('Query should be valid:%j', invalid));
  }); // 1.2
}); // describe 1
