/*

The public query is sent to the query agent from some party
The Query messages is sent from the query agent to the IS using a privacy pipe

IS queries are a JSON representation of the public input query



{
   @graph:[ {
     @id: http://pn.id.webshield.io/query/com/acme#73733737
     @type: https://pn.schema.webshield.io/type#query,
     pn_p.params: {
       @id: ...
       @type: http://pn.schema.webshield.io/type#SubjectQueryRestriction,
       http://pn.schema.webshield.io/prop#subjectID: value
       http://pn.schema.webshield.io/prop#subject_type: value
       ... other query params
     },
     pn_p.properties: {
       familyName:
       givenName:
       taxID:
     },
     result_graph_property: 'bob',
  }
 }
*/

const assert = require('assert');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

let messageIdCounter = 0;
function nextIdCounter() {
  'use strict';
  messageIdCounter = messageIdCounter + 1;
  return moment().unix() + '-' + messageIdCounter;
}

class Query {

  static createJSONFromPublicJSON(hostname) {
    assert(hostname, 'createJSON hostname param is missing');

    let qry = {
      '@id': PNDataModel.ids.createQueryId(hostname, nextIdCounter()),
      '@type': PN_T.Query,
      [PN_P.description]: 'Hard coded to get flow workingf does not reflect results',
      [PN_P.params]: {
        '@id': PNDataModel.ids.createQueryRestrictionId(hostname, nextIdCounter()),
        '@type': PN_T.SubjectQueryRestriction,
        [PN_P.subjectID]: 'https://acme.com/customer/7272372',   // the @id of the subject to query for
        'https://schema.org/givenName': 'bob', // add so can make sure obfuscation works
      },
      [PN_P.properties]: {  // note not an array as want to keep shape and also be able to use compact/expand
        'https://schema.org/familyName': '',
        'https://schema.org/givenName': '',
        'https://schema.org/taxID': '',
        'https://schema.org/address': {
            'https://schema.org/postalCode': '',
          },
      },
      [PN_P.queryResultGraphProp]: 'bob',
    };

    return qry;
  }

  //
  // validates the public query before any expansion has occured
  // only validates must have properties
  // - id
  // - subjects
  //
  static validatePublicJSON(query, hostname) {

    if (!query) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no query object'),
      });

    }

    if (!query.id) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no id in query object:%j', query),
      });
    }

    if (!query.subjects) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no subjects in query object:%j', query),
      });
    }

    return null;
  }

  // create a public JSON query for one subject by id
  static createPublicJSONCanonById(id) {

    let queryId = 'https://fake.com/subjectId';
    if (id) {
      queryId = id;
    }

    // this is query by an id
    return {
      id: 'abc',
      type: 'Query',
      subjects: {
        bob: {
          __params: { id: queryId, }, // query params
          __quality: {}, // future quality attributes needed by provider
          familyName: '',
          givenName: '',
          taxId: '',
        },
      },
    };

  }

}

module.exports = Query;
