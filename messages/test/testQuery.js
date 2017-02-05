/*jslint node: true, vars: true */

const assert = require('assert');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const Query = require('../lib/Query');
const util = require('util');

describe('1 create JSON messages tests', function () {
  'use strict';

  it('1.1 should create a valid json message', function () {

    let mess = Query.createJSONFromPublicJSON('fakehostname.com');
    console.log(mess);
    mess.should.have.property('@id');
    mess.should.have.property('@type');

    mess.should.have.property(PN_P.params);
    mess[PN_P.params].should.have.property('@id');
    mess[PN_P.params].should.have.property('@type', PN_T.SubjectQueryRestriction);
    mess[PN_P.params].should.have.property(PN_P.subjectID);

    mess.should.have.property(PN_P.properties);
    let keys = Object.keys(mess[PN_P.properties]);
    keys.should.be.eql([
      'https://schema.org/familyName',
      'https://schema.org/givenName',
      'https://schema.org/taxID',
      'https://schema.org/address',
    ]);

    for (let i = 0; i < keys.length; i++) {

      switch (typeof mess[PN_P.properties][keys[i]]) {

        case 'string': {
          if ((keys[i] !== 'https://schema.org/familyName') &&
             (keys[i] !== 'https://schema.org/givenName') &&
             (keys[i] !== 'https://schema.org/taxID')) {
            assert(false, util.format('string key is unexpected:%j', keys[i]));
          }

          break;
        }

        case 'object': {
          keys[i].should.be.equal('https://schema.org/address');
          break;
        }

        default: {
          console.log(typeof mess[PN_P.properties][keys[i]]);
          assert(false, util.format('key is not a string or object:%s - typeof:%s',
                  keys[i],
                  (typeof mess[PN_P.properties][keys[i]])
                )
              );
        }
      }
    }

    mess.should.have.property(PN_P.queryResultGraphProp, 'bob');
  }); // 1.1
}); // describe 1
