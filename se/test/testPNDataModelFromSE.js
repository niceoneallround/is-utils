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
    se.addProperty('https://schema.org/givenName', baseAlice['@id'], BASE_P.givenName);
    se.addProperty('https://schema.org/familyName', baseAlice['@id'], BASE_P.familyName);

    return se.promisePNDataModelEntity(PN_T.SubjectQueryRestriction, TestReferenceSourcePNDataModel.model.ID, [baseAlice])
      .then(
        function (rsAlice) {
          console.log(rsAlice);
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
