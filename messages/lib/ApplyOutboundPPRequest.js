/*jslint node: true, vars: true */

/*

This message is sent from the Reference Source Adapter to the Reference Source Privacy Agent
and contains the subject results.

 Contains utils for validating the apply outbound request privacy pipe request
 from the adapter

 Its V1 message format is

 {
   "@graph": [{
     "@id": "the @id that was passed to the adapter as result of apply inbound",
     "@type": "http://pn.schema.webshield.io/type#RSSubjectQuery"
   }, {
     "@id": "subject specific @id that corrresponds to the sourceID",
     "@type": "https://<specific subject type>/type#Subject",
     "https://pn.schema.webshield.io/prop#job_id": < the @id of the query restriction node that found this subject>
     "https://pn.schema.webshield.io/prop#sourceID":
     <subject specific properties>
   }]
 }

 If cannot find a subject the following subject information is returned

 {
   {   “@id” : "The @id from the subject restiction that was used to find the subject",
       “@type: [“https://pn.schema.webshield.io/type#Error,
         “http://pn.schema.webshield.io/prop#error_code: :404”
   }
 ]
 }

 */

const assert = require('assert');
const moment = require('moment');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils').npUtils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_T = PNDataModel.TYPE;
const util = require('util');

class ApplyOutboundPPRequest {

  // find the query node - not should check if more than one
  static createJSON(query, subjectResults) {
    assert(query, 'createJSON query param is missing');
    assert(subjectResults, 'createJSON subjectResults param is missing');

    let req = { '@graph': [], };
    req['@graph'].push(query);

    for (let i = 0; i < subjectResults.length; i++) {
      req['@graph'].push(subjectResults[i]);
    }

    return req;
  }

  static validateJSON(rq, hostname) {

    if (!rq) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s passed in request', PN_T.RSSubjectQuery),
      });
    }

    if (!rq['@graph']) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR @raph missing from:%j', rq),
      });
    }

    // make sure a query node
    if (!ApplyOutboundPPRequest.findQueryNode(rq)) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR could not find query node:%s in request:%j', PN_T.RSSubjectQuery, rq),
      });
    }

    return null;
  }

  // find the query node - not should check if more than one
  static findQueryNode(rq) {

    let results = ApplyOutboundPPRequest.findNodes(rq, PN_T.RSSubjectQuery);
    if (results.length === 0) {
      return null;
    } else {
      return results[0];
    }
  }

  // find the query node - not should check if more than one
  static findNodes(rq, type) {

    let results = [];
    for (let i = 0; i < rq['@graph'].length; i++) {
      if (JSONLDUtils.isType(rq['@graph'][i], type)) {
        results.push(rq['@graph'][i]);
      }
    }

    return results;
  }
} // class

// just want to expose the class and nothing else and allow
// parties to issue statements such
//
// const ApplyOutboundPPRequest = require('..../ApplyOutboundPPRequest');
// let invalid = ApplyOutboundPPRequest.validateJSON()
// ley ApplyOutboundPPRequest = ApplyOutboundPPRequest(req);
//
module.exports = ApplyOutboundPPRequest;
