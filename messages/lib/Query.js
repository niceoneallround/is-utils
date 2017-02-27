/*

The public query is sent to the query agent from some party
The Internal Query messages is sent from the query agent to the IS using a privacy pipe

The query contains
- the parameters/restriction values
- the requested graph properties/projection

The parameters are dependent on the domain and are described through a PN Data Model so that
it is possible to obfuscate them. They are captured in a type called a SubjectQueryRestriction
that can have any properties. Note the properties need to be able to be expanded so JSONLD compliant
and also need to be obfuscated by a privacy algorithm.

IS queries are a JSON representation of the public input query


{
   @id: http://pn.id.webshield.io/query/com/acme#73733737 - used for log messages and async return of messages
   @type: https://pn.schema.webshield.io/type#subject_query,
   query_nodes: [
     { @id: blank node id
       @type: queryNode,
       pn_p.result_graph_property: 'bob',
       pn_p.params:{ // the query restrictions are run through a privacy algorithm
         @id: ...
         @type: http://pn.schema.webshield.io/type#SubjectQueryRestriction, // note need this type as the privacy algorithm applies to this
         http://pn.schema.webshield.io/prop#subjectID: value
         http://pn.schema.webshield.io/prop#subject_type: value
         ... other query params ...
       },
       pn_p.properties: // need to think more how to represent - maybe as a json schema or a properitery
        familyName:
        givenName:
        taxID:
     }
  ]
  }
 }
*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTType = require('jwt-utils/lib/jwtUtils').jwtType;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
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

  static createJSONFromPublicJSON(publicQry, hostname) {
    assert(hostname, 'createJSONFromPublicJSON hostname param is missing');
    assert(publicQry, 'createJSONFromPublicJSON hostname param is missing');

    let err = Query.validatePublicJSON(publicQry, hostname);
    if (err) {
      throw err;
    }

    let qry = {
      '@id': PNDataModel.ids.createQueryId(hostname, publicQry.id),
      '@type': PN_T.SubjectQuery,
      [PN_P.queryNodes]: [],
    };

    if (publicQry.description) {
      qry[PN_P.description] = publicQry.description;
    }

    // find all the top level properties of graph and for each one create a query node as described above.
    let keys = Object.keys(publicQry.graph);

    for (let i = 0; i < keys.length; i++) {
      let keyData = publicQry.graph[keys[i]];

      let node = JSONLDUtils.createBlankNode({ '@type': PN_T.QueryNode, });
      node[PN_P.queryResultGraphNode] = keys[i];

      // create the query restriction based on the params for now hard coded to
      // just use the id
      // let paramKeys = Object.keys(keyData.__params);
      node[PN_P.params] = {
        '@id': PNDataModel.ids.createQueryRestrictionId(hostname, nextIdCounter()),
        '@type': PN_T.SubjectQueryRestriction,
        [PN_P.subjectID]: keyData.__params.id,
      };

      // add the properties that are required -  note not an array as want to keep the shape and use compact/expand
      // FIXME add code to handle embedded types
      //
      node[PN_P.properties] = {};
      let properties =  Object.keys(keyData); // the keys within the object are the properties that are needed. Skip __params
      for (let j = 0; j < properties.length; j++) {
        if ((properties[j] !== '__params') && (properties[j] !== '__quality')) {

          // FIXME add code to handle embedded objects if the property is an object
          node[PN_P.properties][properties[j]] = '';
        }
      }

      qry[PN_P.queryNodes].push(node);
    }

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

    if (!query.graph) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR no graph property in query object:%j', query),
      });
    }

    let keys = Object.keys(query.graph);
    if (keys.length === 0) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR graph does not have any properties:%j', query),
      });
    }

    if (keys.length !== 1) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
        errMsg: util.format('ERROR graph has more than one property can only handle one property for now:%j', query),
      });
    }

    for (let i = 0; i < keys.length; i++) {
      let keyData = query.graph[keys[i]];

      if (!keyData.__params) {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(hostname, nextIdCounter()),
          errMsg: util.format('ERROR graph has no params data for key:%s :%j', keys[i], query),
        });
      }
    }

    return null;
  }

  // create a subject query JWT
  static createJWT(serviceCtx, props) {
    assert(serviceCtx, 'serviceCtx param is missing');
    assert(props, 'props param is missing');
    assert(props.query, util.format('props.query param is missing:%j', props));
    assert(props.privacyPipeId, util.format('props.privacyPipeId param is missing:%j', props));

    return JWTUtils.signSubjectQuery(
                    props.query,
                    props.privacyPipeId,
                    serviceCtx.config.crypto.jwt, { subject: props.query['@id'], });

  }

  //
  // Validate a subject query JWT
  //
  /* OUTPUTs a stucture

      { error: the jwt was somehow invalid so send a bad request to caller,
        query: the subject query
        decoded: the decoded JWT}
  */
  static validateJWT(serviceCtx, inputJWT) {

    const loggingMD = {
            ServiceType: serviceCtx.serviceName,
            FileName: 'isUtils/messages/Query.js', };

    const hostname = serviceCtx.config.getHostname();

    // verify the JWT
    let result = {};
    if (serviceCtx.config.VERIFY_JWT) {
      try {
        result.decoded = JWTUtils.newVerify(inputJWT, serviceCtx.config.crypto.jwt);
      } catch (err) {
        result.error = PNDataModel.errors.createInvalidJWTError({
                  id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
                  type: PN_T.SubjectQuery, jwtError: err, });

        serviceCtx.logger.logJSON('error', { serviceType: serviceCtx.name,
                                    action: 'Query-ERROR-JWT-VERIFY',
                                    inputJWT: inputJWT,
                                    error: result.error,
                                    decoded: JWTUtils.decode(inputJWT, { complete: true }),
                                    jwtError: err, }, loggingMD);

        return result;
      }
    }

    if (!result.decoded) {
      result.decoded = JWTUtils.decode(inputJWT); // decode as may not have verified
    }

    if (!result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PN_JWT_TYPE_CLAIM, result.decoded),
      });

      return result;
    }

    if (result.decoded[JWTClaims.PN_JWT_TYPE_CLAIM] !== JWTType.subjectQuery) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR JWT not expected type::%s JWT:%j', JWTType.subjectQuery, result.decoded),
      });

      return result;
    }

    // validate privacy pipe claim
    if (!result.decoded[JWTClaims.PRIVACY_PIPE_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.PRIVACY_PIPE_CLAIM, result.decoded),
      });

      return result;
    } else {
      result.privacyPipeId = result.decoded[JWTClaims.PRIVACY_PIPE_CLAIM];
    }

    // validate subject query exists
    if (!result.decoded[JWTClaims.SUBJECT_QUERY_CLAIM]) {
      result.error = PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR no %s claim in JWT:%j', JWTClaims.SUBJECT_QUERY_CLAIM, result.decoded),
      });

      return result;
    } else {
      result.query = result.decoded[JWTClaims.SUBJECT_QUERY_CLAIM];
    }

    // FIXME add query validation checks

    return result;
  }

  //----------------
  // Canons
  //----------------

  static createInternalJSONCanonById(id) {

    let publicQry = Query.createPublicJSONCanonById(id);

    // fixup the property names so expanded - all else is by default
    publicQry.graph.bob = {
      __params: publicQry.graph.bob.__params,
      __quality: publicQry.graph.bob.__quality,
      'https:/https://schema.org/https://schema.org//schema.org/familyName': '',
      'https://schema.orhttps://schema.org/g/givenName': '',
      'https://schema.org/taxID': '',
    };

    let qry = Query.createJSONFromPublicJSON(publicQry, 'fake-canon-host-name.com');
    return qry;
  }

  // create a public JSON query for one subject by id
  static createPublicJSONCanonById(id) {

    let queryId = 'https://fake.com/subjectId';
    if (id) {
      queryId = id;
    }

    // this is query by an id
    return {
      id: 'test-query-by-id',
      type: 'SubjectQuery',
      graph: {
        bob: {
          __params: { id: queryId, }, // query params
          __quality: {}, // future quality attributes needed by provider
          familyName: '',
          givenName: '',
          taxID: '',
        },
      },
    };

  }

}

module.exports = Query;
