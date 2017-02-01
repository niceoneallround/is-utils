/*jslint node: true, vars: true */
/*

A Syndicated Entity is a virtual subject that is manufactured from a set of backing PN Data Model subjects that all represent the same subject.
- It has an @id manufactured by the IS, and @type SyndicatedEnity.
- The syndicated entities properties represent one schema from either the ISIM or a participants PN Data Model.
- the backing subjects have @ids that represent entities in the real world, and @type and properties from Participants PN Data models.


A syndicated entity has the following properties - note it can be transported across the wire.
- @id - globally unqiue id
-	@type: pn_t.ISSyndicatedSubject
-	pn_p.properties: the SE properties
- pn_p.subject: The array of backing subject ids - this is pulled from the information model
- job_id: the identity syndicate job id that produced the syndicated entity
-	Future can add linking information

The following shows the properties mapping of scalar top level values and a scalar embedded object

pn_p.properties: {
   the property name: {
      ptype: "string",  // property type
      node: backing subject id,
      propName: backing subject property name
      jwt: the id of the jwt that produced the property - for now clear case may be obfuscated in future
 },
  the propery name: {
      ptype: "object", // note properties may come from multiple say addresses
      pn_p.properties: {
        propertyName: {
          type: "string" | object
          node:'backing embedded object id', // note they have globally unqiue and backing entities are flattened
          propName: the backing embedded object id
          jwt: the id of the jwt that produced the property - for now clear case may be obfuscated in future
    }
}

The following is an example showing embedded object address

pn_p.properties: {
  'https://schema.org/givenName': {
    ptype: "string",
    node: "https://id.webshield.io/com/abc/subject#1",
    propName: 'http://abc.com.schema.../firstName',
    jwt: http://jwt id
  },
  'https://schema.org/address' : {
    ptype: 'object',
    properties: {
      'https://schema.org/postalCode': {
        ptype: 'string',
        node: "https://id.webshield.io/com/abc/address/23",
        propName: 'https://abc.com.schema.webshield.io/prop#zipCode',
        jwt: http://jwt id
      }
  }
}

}

  // assumes flatten subjects
  properties:
     https://schema.org/givenName: { istype: scalar_value, node: subject @id, property: } // scalar value - copies a value
     https://schema.org/currentAddress: { istype: scalar_object, node: subject @id, property: .../prop#address} - copies the @id

Property, vertex, edge.

http://schema.org/name, https://id.webshield.io/com/aetna#23, https://schema.org/name
http://schema.org/address, https://id.webshield.io/com/atena#23, https://schema.org/address
https://experian.schema.webshield.io/firstName, https://id.webshield.io/com/aetna#23, https://aetna.schema.webshield.io/first_name

The information model has the instructions on how to create the subject of type
pn data model from the source subjects, it has information on properties and edges.

The syndicated entity information model maps the following
-	Properties – (syndEntityId, property) -> (vertex, property)
-	Edges – (syndEntityId, edge) - > (syndEntityId)

For example
(…synd#1, https://schema.org/familyName), (…aetna#23, https://schema.org/familyName)
(…synd#1, https://schema.org/taxID), (…experian#23, https://experian.schema…/taxID)
(…synd#1, https://schema.org/adddress, (address_synd#2)
(…address_synd#1, https://schema.org/postalCode),(aetna/addres#123, https://schema.org/postalAddress)

*/

const assert = require('assert');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

class SyndicatedEntity {

  constructor(id, props) {
    assert(id, 'SyndicatedEntity - create - id param missing');
    assert(props, 'SyndicatedEntity - create - props param missing');
    assert(props.hostname, util.format('SyndicatedEntity - create - props.hostname param missing:%j', props));
    assert(props.pnDataModelId, util.format('SyndicatedEntity - create - props.dataModelId param missing:%j', props));
    assert(props.jobId, util.format('SyndicatedEntity - create - props.jobId param missing:%j', props));

    this['@id'] = PNDataModel.ids.createSyndicatedEntityId(props.hostname, id);
    this['@type'] = [PN_T.SyndicatedEntity];
    this[PN_P.pnDataModel] = props.pnDataModelId;
    this[PN_P.job] =  props.jobId;
    this[PN_P.properties] = {};
    this[PN_P.subject] = [];
  }

  // create a syndicated entity from a JSON representation
  // yea could have made operations static but wanted to try this approach as more like java
  // not sure if keen on it as yet
  static createFromJSON(se) {
    assert(se['@id'], util.format('SyndicatedEntity - createFromJSON - @id param missing:%j', se));
    assert(se[PN_P.pnDataModel], util.format('SyndicatedEntity - createFromJSON - PN_P.pnDataModel param missing:%j', se));
    assert(se[PN_P.job], util.format('SyndicatedEntity - createFromJSON - PN_P.job param missing:%j', se));
    assert(se[PN_P.properties], util.format('SyndicatedEntity - createFromJSON - PN_P.properties param missing:%j', se));
    assert(se[PN_P.subject], util.format('SyndicatedEntity - createFromJSON - PN_P.subject param missing:%j', se));

    let newSE = new SyndicatedEntity('dont-care', {
      hostname: 'dont-care',
      pnDataModelId: se[PN_P.pnDataModel],
      jobId: se[PN_P.job],
    });

    // fix up
    newSE['@id'] = se['@id'];
    newSE[PN_P.properties] = se[PN_P.properties];
    newSE[PN_P.subject] = se[PN_P.subject];

    return newSE;
  }

  // add a mapped property to the Syndicated entities informatiom model
  addProperty(name, backingSubjectId, subjectPropName, jwtId, optionalParams) {
    assert(name, 'addProperty - name param missing');
    assert(backingSubjectId, 'addProperty - backingSubjectId param missing');
    assert(subjectPropName, 'addProperty - subjectPropName param missing');
    assert(jwtId, 'addProperty - jwtId param missing');

    let ptype = 'string';
    if ((optionalParams) && (optionalParams.ptype)) {
      ptype = optionalParams.ptype;
    }

    this[PN_P.properties][name] = {
      [PN_P.ptype]: ptype,
      [PN_P.node]: backingSubjectId,
      [PN_P.subjectPropName]: subjectPropName,
      [PN_P.jwt]: jwtId,
    };

    // for now do not convert into a map as only 1 or 2 subjects and easier
    // to ensure JSON can go over wire without translation
    if (this[PN_P.subject].length === 0) {
      this[PN_P.subject].push(backingSubjectId);
    } else {
      let found = false;
      for (let i = 0; i < this[PN_P.subject].length; i++) {
        if (this[PN_P.subject][i] === backingSubjectId) {
          found = true;
        }
      }

      if (!found) {
        this[PN_P.subject].push(backingSubjectId);
      }
    }
  }

  addEmbeddedObjectProperty(name, embedName, embedBackNode, embedSubPropName, jwtId, optionalParams) {
    assert(name, 'addEmbeddedObjectProperty - name param missing');
    assert(embedName, 'addEmbeddedObjectProperty - embedName param missing');
    assert(embedBackNode, 'addEmbeddedObjectProperty - embedBackNode param missing');
    assert(embedSubPropName, 'addEmbeddedObjectProperty - embedSubPropName param missing');
    assert(jwtId, 'addProperty - jwtId param missing');

    if (!this[PN_P.properties][name]) {
      // first prop for this embed object
      this[PN_P.properties][name] = {
        [PN_P.ptype]: 'object',
        [PN_P.properties]: {},
      };
    }

    // add the embeded property
    let ptype = 'string';
    if ((optionalParams) && (optionalParams.ptype)) {
      ptype = optionalParams.ptype;
    }

    this[PN_P.properties][name][PN_P.properties][embedName] = {
      [PN_P.ptype]: ptype,
      [PN_P.node]: embedBackNode,
      [PN_P.subjectPropName]: embedSubPropName,
      [PN_P.jwt]: jwtId,
    };
  }

  /*
     Returns a PN Data Model subject from an SE in that same PN Data Model.
     Note as the SE contains the @ids of the backing subjects these need to be
     passed in.

     input
      - type - type wanted can be SubjectQueryRestriction or a PN data Model subject type
      - data model id - the request data model type
      - nodeMap - map of backing subjects and embedded objects by @id.

    output
      - PN data model subject of the passed in type and data model

    process
     1. create base
       1.1 If subject restriction node - create a new base node of type sybject restriction
       1.2 iterate over the flattened subjects to see if one of the requested data model type, if not barf as no base to build
     2. Iterate over the SE im schema
  */
  pnDataModelEntity(type, pnDataModelId, nodeMap, flattendNodes) {
    assert(type, 'pnDataModelEntity - type param missing');
    assert(pnDataModelId, 'pnDataModelEntity - pnDataModelId param missing');
    assert(nodeMap, 'pnDataModelEntity - nodeMap param missing');
    assert(flattendNodes, 'pnDataModelEntity - flattendNodes param missing');

    let rs;
    if (type === PN_T.SubjectQueryRestriction) {
      rs = { '@id': this['@id'], '@type': [PN_T.SubjectQueryRestriction], };
    } else {
      assert(false, 'add code to handle no subject restriction');
    }

    // iterate over properties finding value in backing subject and add
    let keys = Object.keys(this[PN_P.properties]);

    for (let i = 0; i < keys.length; i++) {

      let key = keys[i];

      switch (key) {

        case '@id' : {
          break; // do nothing - note that the jsonld graph processing may had an @id to properties hence need this
        }

        default: {
          let keyDesc = this[PN_P.properties][key];

          switch (keyDesc[PN_P.ptype]) {

            case 'string': {

              // find the backing subject
              let bs = nodeMap.get(keyDesc[PN_P.node]);
              assert(bs, util.format('Could not find node:%s in subjects:%j', keyDesc[PN_P.node], flattendNodes));
              rs[key] = bs[keyDesc[PN_P.subjectPropName]];
              break;
            }

            case 'object': {
              assert(false, 'does not support object yet');

              // if a subject query restriction then all nodes are virtual, so may need to create new node
              // if not already created. See eitemUtils in connector for more.
              break;
            }

            default: {
              assert(false, util.format('key:%s does not support ptype yet', key, keyDesc));
            }
          } // switch ptype
        } // default key
      } // for
    }// switch key

    return rs;

  }

  /*
     Returns a PN Data Model subject from an SE in that same PN Data Model.
     Note as the SE contains the @ids of the backing subjects these need to be
     passed in.

     The following is performed
     1. Pass in subjects and requested output subject type - either from the PN data model or SubjectRestriction
     2. Flatten the subjects and embedded objects, such as address
     3. create base
       3.1 If subject restriction node - create a new base node of type sybject restriction
       3.2 iterate over the flattened subjects to see if one of the requested data model type, if not barf as no base to build
    4. Iterate over the SE im schema
  promisePNDataModelEntity(type, pnDataModelId, subjects) {
    assert(type, 'promisePNDataModelEntity - type param missing');
    assert(pnDataModelId, 'promisePNDataModelEntity - pnDataModelId param missing');
    assert(subjects, 'promisePNDataModelEntity - subject param missing');

    let _this = this;

    return new Promise(function (resolve, reject) {

      // flatten all the subjects
      return JSONLDPromises.flattenCompact(subjects)
      .then(
        function (flattenCompactedSubjects) {

          let objectMap = new Map();
          for (let i = 0; i < flattenCompactedSubjects['@graph'].length; i++) {
            objectMap.set(flattenCompactedSubjects['@graph'][i]['@id'], flattenCompactedSubjects['@graph'][i]);
          }

          let rs;
          if (type === PN_T.SubjectQueryRestriction) {
            rs = { '@id': _this['@id'], '@type': [PN_T.SubjectQueryRestriction], };
          } else {
            assert(false, 'add code to handle no subject restriction');
          }

          // iterate over properties finding value in backing subject and add
          let keys = Object.keys(_this[PN_P.properties]);

          for (let i = 0; i < keys.length; i++) {

            let key = keys[i];
            let keyDesc = _this[PN_P.properties][key];

            switch (keyDesc[PN_P.ptype]) {

              case 'string': {

                // find the backing subject
                let bs = objectMap.get(keyDesc[PN_P.node]);
                assert(bs, util.format('Could not find node:%s in subjects:%j', keyDesc[PN_P.node], subjects));
                rs[key] = bs[keyDesc[PN_P.subjectPropName]];
                break;
              }

              case 'object': {
                assert(false, 'does not support object yet');
                break;
              }

              default: {
                assert(false, util.format('key:%s does not support ptype yet', key, keyDesc));
              }
            } // switch ptype
          } // for

          resolve(rs);
        },

        function (err) {
          console.log('promisePNDataModelEntity - UNEXPECTED-ERR add error handling', err);
          reject(err);
        })
        .catch(function (err) {
          console.log('promisePNDataModelEntity - CATCH-ERR add error handling', err);
          reject(err);
        });
    });
  }*/

} // class

module.exports = SyndicatedEntity;
