/*jslint node: true, vars: true */

const assert = require('assert');
const ApplyOutboundPPRequest = require('../lib/ApplyOutboundPPRequest');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const BASE_T = BaseSubjectPNDataModel.TYPE;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_T = PNDataModel.TYPE;
const util = require('util');

describe('1 Test Validate', function () {
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
}); // describe 1

describe('2 Test Find Query', function () {
  'use strict';

  it('2.1 should return query', function () {
    let req = { '@graph': [{ '@id': '1', '@type': [PN_T.RSSubjectQuery], }] };

    let query = ApplyOutboundPPRequest.findQueryNode(req);
    query.should.have.property('@id', '1');
  }); // 2.1
}); // describe 2

describe('3 Test Find Nodes of a specified type', function () {
  'use strict';

  it('3.1 should return query', function () {
    let req = { '@graph': [
      { '@id': '1', '@type': [PN_T.RSSubjectQuery], },
      { '@id': '2', '@type': [BASE_T.Subject], },
      { '@id': '3', '@type': [BASE_T.Subject], },
      { '@id': '4', '@type': ['abc'], },
    ], };

    let results = ApplyOutboundPPRequest.findNodes(req, BASE_T.Subject);
    results.length.should.be.equal(2);
  }); // 3.1
}); // describe 3

describe('4 create JSON messages tests', function () {
  'use strict';

  it('4.1 should create a valid json message', function () {
    let query = { '@id': '1', '@type': [PN_T.RSSubjectQuery], };
    let subjectResults =  [
      { '@id': '2', '@type': [BASE_T.Subject], },
      { '@id': '3', '@type': [BASE_T.Subject], },
      { '@id': '4', '@type': ['abc'], },
    ];

    let req = ApplyOutboundPPRequest.createJSON(query, subjectResults);
    let invalid = ApplyOutboundPPRequest.validateJSON(req, 'fakehost.com');
    assert(!invalid, util.format('should be valid:%j', invalid));
    req['@graph'].length.should.be.equal(4);
  }); // 4.1
}); // describe 4
