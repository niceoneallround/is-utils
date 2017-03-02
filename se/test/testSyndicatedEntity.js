/*jslint node: true, vars: true */

const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const SyndicatedEntity = require('../lib/SyndicatedEntity');
const should = require('should');

describe('1 Test Syndicated Entity', function () {
  'use strict';

  const props = {
    hostname: 'fake.com',
    pnDataModelId: 'dm_id',
    jobId: 'jobId',
  };

  it('1.1 should create a SE from passed in ctor params', function () {

    let se = new SyndicatedEntity('id1', props);
    se.should.have.property('@id');
    se.should.have.property('@type', [PN_T.SyndicatedEntity]);
    se.should.have.property(PN_P.pnDataModel, 'dm_id');
    se.should.have.property(PN_P.job, 'jobId');
    se.should.have.property(PN_P.subject, []);
    se.should.have.property(PN_P.properties, {});
    se.should.have.property(PN_P.subjectLinkJWT);
  }); // 1.1

  it('1.1a should create a SE from JSON version', function () {

    let se = {
      '@id': 'abc',
      '@type': [PN_T.SyndicatedEntity],
      [PN_P.pnDataModel]: 'dm_id',
      [PN_P.job]: 'jobId',
      [PN_P.subject]: ['1', '2'],
      [PN_P.properties]: { a: '1' },
      [PN_P.subjectLinkJWT]: ['fake'],
    };

    let newSE = SyndicatedEntity.createFromJSON(se);
    newSE.should.have.property('@id', 'abc');
    newSE.should.have.property('@type', [PN_T.SyndicatedEntity]);
    newSE.should.have.property(PN_P.pnDataModel, 'dm_id');
    newSE.should.have.property(PN_P.job, 'jobId');
    newSE.should.have.property(PN_P.subject, ['1', '2']);
    newSE.should.have.property(PN_P.properties,  { a: '1' });
    newSE.should.have.property(PN_P.subjectLinkJWT);

  }); // 1.1a

  it('1.2 should be able to add top level properties and update the properties and subjects', function () {

    let se = new SyndicatedEntity('id1', props);
    se.addProperty('https://schema.org/givenName', 'back-sub-1', 'sub_prop1', 'jwt1');
    se.should.have.property(PN_P.subject, ['back-sub-1']);
    se.should.have.property(PN_P.properties);
    se[PN_P.properties].should.have.property('https://schema.org/givenName',
              { [PN_P.ptype]: 'string', [PN_P.node]: 'back-sub-1', [PN_P.subjectPropName]: 'sub_prop1', [PN_P.jwt]: 'jwt1', });

    // add a another prop for same subject - should not update subjects
    se.addProperty('https://schema.org/familyName', 'back-sub-1', 'sub_prop2', 'jwt2');
    se[PN_P.properties].should.have.property('https://schema.org/givenName',
              { [PN_P.ptype]: 'string', [PN_P.node]: 'back-sub-1', [PN_P.subjectPropName]: 'sub_prop1', [PN_P.jwt]: 'jwt1', });
    se[PN_P.properties].should.have.property('https://schema.org/familyName',
                { [PN_P.ptype]: 'string', [PN_P.node]: 'back-sub-1', [PN_P.subjectPropName]: 'sub_prop2', [PN_P.jwt]: 'jwt2', });

    // add a another prop for different subject - should update subjects
    se.addProperty('https://schema.org/taxID', 'back-sub-2', 'sub2_prop1', 'jwt3');
    se.should.have.property(PN_P.subject, ['back-sub-1', 'back-sub-2']);
    se[PN_P.properties].should.have.property('https://schema.org/taxID',
                { [PN_P.ptype]: 'string', [PN_P.node]: 'back-sub-2', [PN_P.subjectPropName]: 'sub2_prop1', [PN_P.jwt]: 'jwt3', });

    //console.log(se);
  }); // 1.2

  it('1.3 should be able to add embedded properties', function () {

    let se = new SyndicatedEntity('id1', props);
    se.addEmbeddedObjectProperty(
            'https://schema.org/address',
            'https://schema.org/postalCode',
            'address-object-id',
            'https://acme.com.schema.webshield.io/prop#zipCode',
            'jwt5');

    //console.log(se);
    se[PN_P.properties].should.have.property('https://schema.org/address');
    se[PN_P.properties].should.have.property('https://schema.org/address', {
      [PN_P.ptype]: 'object',
      [PN_P.properties]: {
        'https://schema.org/postalCode': {
          [PN_P.ptype]: 'string',
          [PN_P.node]: 'address-object-id',
          [PN_P.subjectPropName]:   'https://acme.com.schema.webshield.io/prop#zipCode',
          [PN_P.jwt]: 'jwt5',
        },
      },
    });

    se.should.have.property(PN_P.subject, []);
  }); // 1.3

}); // describe 1
