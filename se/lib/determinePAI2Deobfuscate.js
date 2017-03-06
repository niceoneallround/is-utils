/*jslint node: true, vars: true */

const assert = require('assert');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const JWTType = require('jwt-utils/lib/jwtUtils').jwtType;
const JWTUtils = require('jwt-utils/lib/jwtUtils').jwtUtils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PNObfuscatedValue = require('data-models/lib/PNObfuscatedValue').utils;
const util = require('util');

/**

 Based on the properties and underlying subject JWTs determine the set of
 <privacy_pipe_id, privacy_action_instance_id> that need to be de-obfuscated
 for this syndicated enitity.

 @param serviceCtx
 @param ses - array of the syndicated entities to process
 @param jwts array of JWTs used to build all the SE
 @return an Array of unique <ppId, paiId>.

*/
function execute(serviceCtx, ses, jwts) {
  'use strict';

  let result = [];

  //
  // The properties are tagged with the JWTid so create a map of JWTid to
  // decoded JWT so can look up and find the necessary information
  //
  let JWTIdMap = new Map();
  for (let i = 0; i < jwts.length; i++) {
    let decoded = JWTUtils.decode(jwts[i]);
    assert(decoded, util.format('DetereminePAI2Deobfuscate could not decode JWT:%s', jwts[i]));
    if (decoded[JWTClaims.PN_JWT_TYPE_CLAIM] === JWTType.subject) {
      JWTIdMap.set(decoded[JWTClaims.JWT_ID_CLAIM], decoded);
    }
  }

  //
  // Process each property in the SE as follows
  // 1. Look up decoded subject JWT by its JWTid
  // 2. extract the subject and the property value
  // 3. If an obfuscated value then
  // 3.1 See if the PAI already in the set to de-obfuscate if not add to output as <paiId, ppId>
  // 3.2 add to list if already processed.
  //

  let properties;
  let propKeys;
  let property;
  let decodedJWT;
  let paiAlreadyIncluded = new Map();
  for (let i = 0; i < ses.length; i++) {
    properties = ses[i][PN_P.properties];
    propKeys = Object.keys(properties);

    //console.log('***propKeys', propKeys);

    for (let j = 0; j < propKeys.length; j++) {
      property = properties[propKeys[j]];
      decodedJWT = JWTIdMap.get(property[PN_P.jwt]);

      //console.log('***property', property);

      switch (property[PN_P.ptype]) {

        case 'string': {
          let v = getPropertyValueFromSubjectJWT(
                    decodedJWT,
                    property[PN_P.subjectPropName]);

          if (PNObfuscatedValue.isOV(v)) {
            let paiId = v['@type'];
            if (!paiAlreadyIncluded.get(paiId)) {
              paiAlreadyIncluded.set(paiId, paiId);
              result.push({
                    ppId: decodedJWT[JWTClaims.PRIVACY_PIPE_CLAIM],
                    paiId: paiId, });
            }
          }

          break;
        }

        case 'object': {
          assert(false, util.format('object not yet supported:%j', property)); // actually would only arrive here if only sending an address
          break;
        }

        default: {
          assert(false, util.format('Unexpected ptype:%j', property));
        }
      }

    }

  }

  return result;
}

// helper utils
function getPropertyValueFromSubjectJWT(decodedJWT, propName) {
  'use strict';
  assert(decodedJWT, 'getPropertyValueFromSubjectJWT decodedJWT param is null');
  assert(propName, 'getPropertyValueFromSubjectJWT propName paran is null');
  let subject = decodedJWT[JWTClaims.SUBJECT_CLAIM];
  return subject[propName];
}

module.exports = {
  execute: execute,
};
