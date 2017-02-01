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

    const customLastNameAttr = 'https://rs.schema.webshield.io/custom_last_name';

    // create the SE
    let se = new SyndicatedEntity('id1', props);

    // populate the syndicated enity so that it represents a Test Reference Source object
    // add a custom field to make sure works as expected, as base and test have same props so
    // bit confusing
    let baseAlice = BaseSubjectPNDataModel.canons.createAlice({ domainName: 'abc.com', });
    se.addProperty('https://schema.org/givenName', baseAlice['@id'], BASE_P.givenName, 'jwt1');
    se.addProperty(customLastNameAttr, baseAlice['@id'], BASE_P.familyName, 'jwt2');

    // flatten
    let flattenedNodes = [];
    flattenedNodes.push(baseAlice);
    flattenedNodes.push(baseAlice[BASE_P.address]);

    let nodeMap = new Map();
    nodeMap.set(baseAlice['@id'], baseAlice);
    nodeMap.set(baseAlice[BASE_P.address]['@id'], baseAlice[BASE_P.address]);

    let rsAlice = se.pnDataModelEntity(PN_T.SubjectQueryRestriction, TestReferenceSourcePNDataModel.model.ID, nodeMap, flattenedNodes);
    rsAlice.should.have.property('@id', se['@id']);
    rsAlice.should.have.property('@type', [PN_T.SubjectQueryRestriction]);
    rsAlice.should.have.property('https://schema.org/givenName', baseAlice[BASE_P.givenName]);
    rsAlice.should.have.property(customLastNameAttr, baseAlice[BASE_P.familyName]);
  }); // 1.1

  /* FIXME ADD CODE TO MAKE TEST works

  it('1.2 create a concrete test reference source subject subject restriction from syndicate entity that is based on a base subject WITH EMBED ADDRESS',
        function () {

    const addressAttrName = 'https://abc.com.schema.webshield.io/prop#current_address';

    // create the SE
    let se = new SyndicatedEntity('id1', props);

    let baseAlice = BaseSubjectPNDataModel.canons.createAlice({ domainName: 'abc.com', });

    // populate the syndicated enity so that it represents a Test Reference Source object
    // add a custom field to make sure works as expected, as base and test have same props so
    // bit confusing
    se.addProperty('https://schema.org/givenName', baseAlice['@id'], BASE_P.givenName, 'jwt1');

    // add address an field from address so test embedded entity.
    se.addEmbeddedObjectProperty(
            addressAttrName,  // name in the output object
            'https://schema.org/postalCode', // name in output object
            baseAlice[BASE_P.address]['@id'], // the @id of the adress node - this is pointed to be subjct so no subkect id
            BASE_P.postalCode, // attribute name in backing subject
            'jwt5');

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
    rsAlice.should.have.property(addressAttrName);
    rsAlice[addressAttrName].should.have.property(BASE_P.postalCode, baseAlice[BASE_P.address][BASE_P.postalCode]);
  }); // 1.2

  */

}); // describe 1
