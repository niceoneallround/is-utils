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

}); // describe 1
