/*jslint node: true, vars: true */

const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const BASE_P = BaseSubjectPNDataModel.PROPERTY;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_T = PNDataModel.TYPE;
const SyndicatedEntity = require('../lib/SyndicatedEntity');
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const should = require('should');

describe('1 Test Syndicated Entity', function () {
  'use strict';

  const props = {
    hostname: 'fake.com',
    pnDataModelId: TestReferenceSourcePNDataModel.model.ID,
    jobId: 'jobId',
  };

  it('1.1 create a concrete test reference source subject subject restriction from syndicate entity that is based on a base subject NO EMBED',
        function () {

    // create the SE
    let se = new SyndicatedEntity('id1', props);

    let baseAlice = BaseSubjectPNDataModel.canons.createAlice({ domainName: 'abc.com', });
    se.addProperty('https://schema.org/givenName', baseAlice['@id'], BASE_P.givenName, 'jwt1');
    se.addProperty('https://schema.org/familyName', baseAlice['@id'], BASE_P.familyName, 'jwt2');

    // flatten
    let flattenedNodes = [];
    flattenedNodes.push(baseAlice);
    flattenedNodes.push(baseAlice[BASE_P.address]);

    let nodeMap = new Map();
    nodeMap.set(baseAlice['@id'], baseAlice);
    nodeMap.set(baseAlice[BASE_P.address]['@id'], baseAlice[BASE_P.address]);

    let rsAlice = se.pnDataModelEntity(PN_T.SubjectQueryRestriction, TestReferenceSourcePNDataModel.model.ID, nodeMap, flattenedNodes);
    console.log(rsAlice);
    rsAlice.should.have.property('@id', se['@id']);
    rsAlice.should.have.property('@type', [PN_T.SubjectQueryRestriction]);
    rsAlice.should.have.property('https://schema.org/givenName', baseAlice[BASE_P.givenName]);
    rsAlice.should.have.property('https://schema.org/familyName', baseAlice[BASE_P.familyName]);
  }); // 1.1

}); // describe 1
