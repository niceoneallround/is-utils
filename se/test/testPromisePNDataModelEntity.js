/*jslint node: true, vars: true */

const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const BASE_P = BaseSubjectPNDataModel.PROPERTY;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_T = PNDataModel.TYPE;
const PromisePNDataModelEntities = require('../lib/PromisePNDataModelEntities');
const SyndicatedEntity = require('../lib/SyndicatedEntity');
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const should = require('should');

describe('1 Test Promise PN Data Model Entity', function () {
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

    return PromisePNDataModelEntities(PN_T.SubjectQueryRestriction, TestReferenceSourcePNDataModel.model.ID, [baseAlice], [se])
      .then(
        function (subjects) {
          subjects.length.should.be.equal(1);
          let rsAlice = subjects[0];
          rsAlice.should.have.property('@id', se['@id']);
          rsAlice.should.have.property('@type', [PN_T.SubjectQueryRestriction]);
          rsAlice.should.have.property('https://schema.org/givenName', baseAlice[BASE_P.givenName]);
          rsAlice.should.have.property('https://schema.org/familyName', baseAlice[BASE_P.familyName]);
          return;
        },

        function (err) {
          console.log('TEST-FAILED_ERR', err);
          throw err;
        })
        .catch(function (err) {
          console.log('TEST-FAILED-CATCH', err);
          throw err;
        });

  }); // 1.1

  it('1.2 test if passing in just JSON objects not Syndicated Entities',
        function () {

    let baseAlice = BaseSubjectPNDataModel.canons.createAlice({ domainName: 'abc.com', });
    let seJSON =  {
        '@id': 'https://pn.id.webshield.io/syndicated_entity/com/fake#id1',
        '@type': ['http://pn.schema.webshield.io/type#SyndicatedEntity'],
        'https://pn.schema.webshield.io/prop#pndatamodel': 'https://md.pn.id.webshield.io/pndatamodel/io/webshield/test/rs#subject_records',
        'http://pn.schema.webshield.io/prop#job': 'jobId',
        'https://pn.schema.webshield.io/prop#properties':
           { 'https://schema.org/givenName':
              { 'https://pn.schema.webshield.io/prop#ptype': 'string',
                'http://pn.schema.webshield.io/prop#node': 'https://id.webshield.io/com/abc/alice_abc',
                'https://pn.schema.webshield.io/prop#subject_prop_name': 'https://schema.org/givenName',
                'http://pn.schema.webshield.io/prop#jwt': 'jwt1', },
              'https://schema.org/familyName':
              { 'https://pn.schema.webshield.io/prop#ptype': 'string',
                'http://pn.schema.webshield.io/prop#node': 'https://id.webshield.io/com/abc/alice_abc',
                'https://pn.schema.webshield.io/prop#subject_prop_name': 'https://schema.org/familyName',
                'http://pn.schema.webshield.io/prop#jwt': 'jwt2', }, },
        'http://pn.schema.webshield.io/prop#subject': ['https://id.webshield.io/com/abc/alice_abc'], };

    return PromisePNDataModelEntities(PN_T.SubjectQueryRestriction, TestReferenceSourcePNDataModel.model.ID, [baseAlice], [seJSON])
      .then(
        function (subjects) {
          subjects.length.should.be.equal(1);
          let rsAlice = subjects[0];
          rsAlice.should.have.property('@id', seJSON['@id']);
          rsAlice.should.have.property('@type', [PN_T.SubjectQueryRestriction]);
          rsAlice.should.have.property('https://schema.org/givenName', baseAlice[BASE_P.givenName]);
          rsAlice.should.have.property('https://schema.org/familyName', baseAlice[BASE_P.familyName]);
          return;
        },

        function (err) {
          console.log('TEST-FAILED_ERR', err);
          throw err;
        })
        .catch(function (err) {
          console.log('TEST-FAILED-CATCH', err);
          throw err;
        });

  }); // 1.1

}); // describe 1
