/*jslint node: true, vars: true */
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const Query = require('../lib/Query');

describe('1 create JSON messages tests', function () {
  'use strict';

  it('1.1 should create an internal subject query with all the public query information', function () {

    let publicJSON = Query.createPublicJSONCanonById(); // use default id

    let mess = Query.createJSONFromPublicJSON(publicJSON, 'fakehostname.com');
    console.log(mess);
    mess.should.have.property('@id');
    mess.should.have.property('@type', PN_T.SubjectQuery);
    mess.should.have.property(PN_P.queryNodes);
    mess[PN_P.queryNodes].length.should.be.equal(1);

    let node = mess[PN_P.queryNodes][0];
    node.should.have.property('@id');
    node.should.have.property('@type', [PN_T.QueryNode]);
    node.should.have.property(PN_P.queryResultGraphNode, 'bob');

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
}); // describe 1
