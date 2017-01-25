/*jslint node: true, vars: true */

const assert = require('assert');
const RSAQueryResult = require('../lib/RSAQueryResult');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const BASE_T = BaseSubjectPNDataModel.TYPE;
const util = require('util');

describe('1 create JSON messages tests', function () {
  'use strict';

  it('1.1 should create a valid json message', function () {
    let subjectResults =  [
      { '@id': '2', '@type': [BASE_T.Subject], },
      { '@id': '3', '@type': [BASE_T.Subject], },
      { '@id': '4', '@type': ['abc'], },
    ];

    let linkCredentials = ['a', 'b', 'c'];
    let domainName = 'abc.com';
    let query = { '@id': '1', };

    let mess = RSAQueryResult.createJSON(domainName, query, subjectResults, linkCredentials);
    mess.should.have.property('@id');
    mess.should.have.property('@type');
    mess.should.have.property('subjects', subjectResults);
    mess.should.have.property('links', linkCredentials);
    mess.should.have.property('responding_to', query['@id']);
    let invalid = RSAQueryResult.validateJSON(mess, 'fakehost.com');
    assert(!invalid, util.format('should be valid:%j', invalid));
  }); // 1.1
}); // describe 1

/*describe('1 Test Validate', function () {
  'use strict';

  it('1.0 should return null if valid', function () {
    let req = { '@graph': [{ '@id': '1', '@type': [PN_T.RSSubjectQuery], }] };

    let invalid = ApplyOutboundPPRequest.validateJSON(req, 'fakehost.com');
    assert(!invalid, util.format('should be valid:%j', invalid));
  }); // 1.1

  it('1.1 should find null invalid', function () {
    let invalid = ApplyOutboundPPRequest.validateJSON(null, 'fakehost.com');
    assert(invalid, 'null should be invalid');
  }); // 1.1

  it('1.2 should find invalid if no @graph', function () {
    let req = { '@id': 'bad-request' };
    let invalid = ApplyOutboundPPRequest.validateJSON(req, 'fakehost.com');
    assert(invalid, 'should be invalid');
  }); // 1.2

  it('1.3 should find invalid if no query node', function () {
    let req = { '@graph': [{ '@type': 'abc', }] };
    let invalid = ApplyOutboundPPRequest.validateJSON(req, 'fakehost.com');
    assert(invalid, 'should be invalid');
  }); // 1.3
}); // describe 1 */
