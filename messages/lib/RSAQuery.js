/*jslint node: true, vars: true */
/*
  The RSAQuery is sent from the RSPA to RSA as the body of the response to the
  POST apply inbound message request.

  It has the following format

  {
    @id: globally unique id
    @type: https://pn.schema.webshield.io/prop#RSAQuery
    version: 2
    subject_restrictions: [] of subject restriction nodes
  }

  The subject query restriction nodes are as follows

  {
    '@id': a globally unique id
    '@type': https://pn.schema.webshield.io/type#SubjectQueryRestriction"
    'https://pn.schema.webshield.io/prop#pndatamodel': the @id of the pn data model that is representing the
    the query properties
  }
*/

const assert = require('assert');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const TestReferenceSourcePNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const util = require('util');

let messageIdCounter = 0;
function nextIdCounter() {
  'use strict';
  messageIdCounter = messageIdCounter + 1;
  return moment().unix() + '-' + messageIdCounter;
}

class RSAQuery {

  // props.notMatched - optional
  static createJSON(domainName, subjectRestrictions) {
    assert(domainName, 'createJSON domainName param is missing');
    assert(subjectRestrictions, 'createJSON subjectRestrictions param is missing');

    return {
      '@id': PNDataModel.ids.createQueryId(domainName, nextIdCounter()),
      '@type': PN_T.RSAQuery,
      version: '2',
      subject_restrictions: subjectRestrictions, };
  }

  static validateJSON(rq, hostname) {

    if (!rq) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no %s passed in request', PN_T.RSSubjectQuery),
      });
    }

    if (!rq['@id']) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no @id passed in request:%j', rq),
      });
    }

    if (!rq['@type']) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no @type passed in request:%j', rq),
      });
    }

    if (rq['@type'] !== PN_T.RSAQuery) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no type passed in request:%j', rq),
      });
    }

    if (!rq.version) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no version passed in request:%j', rq),
      });
    }

    if (rq.version !== '2') {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR unknown version passed in request:%j', rq),
      });
    }

    if (!rq.subject_restrictions) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no subject_restrictions passed in request:%j', rq),
      });
    }

    for (let i = 0; i < rq.subject_restrictions.length; i++) {
      if (!rq.subject_restrictions[i][PN_P.pnDataModel]) {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
          errMsg: util.format('ERROR subject_restrictions does not have %s in request:%j', PN_P.pnDataModel, rq),
        });
      }
    }

    return null;
  }

  static createCanonJSON() {

    // create query restriction nodes from the test reference source canon nodes
    let alice = TestReferenceSourcePNDataModel.canons.createAlice(
                { domainName: 'fake.com',
                  idValue: nextIdCounter(), });
    alice['@id'] = 'https://pn.id.webshield.io/syndicated_entity/localhost#test-se-1'; // hard coded from RSQuery canon!!!!
    alice['@type'] = [PN_T.SubjectQueryRestriction];
    alice[PN_P.pnDataModel] = TestReferenceSourcePNDataModel.model.ID;

    let bob = TestReferenceSourcePNDataModel.canons.createBob(
                { domainName: 'fake.com',
                  idValue: nextIdCounter(), });
    bob['@id'] = 'https://pn.id.webshield.io/syndicated_entity/localhost#test-se-1'; // hard coded from RSQuery canon!!!!
    bob['@type'] = [PN_T.SubjectQueryRestriction];
    bob[PN_P.pnDataModel] = TestReferenceSourcePNDataModel.model.ID;

    return {
      '@id': PNDataModel.ids.createQueryId('fake.com', nextIdCounter()),
      '@type': PN_T.RSAQuery,
      version: '2',
      subject_restrictions: [alice, bob],
    };

  }

} // class

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const ApplyOutboundPPRequest = require('..../ApplyOutboundPPRequest');
// let invalid = ApplyOutboundPPRequest.validateJSON()
// ley ApplyOutboundPPRequest = ApplyOutboundPPRequest(req);
//
module.exports = RSAQuery;
