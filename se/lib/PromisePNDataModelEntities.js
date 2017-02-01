/*jslint node: true, vars: true */
/*

   Process the set of passed in subjects and syndicated entities to produce concrete
   PN Data Model subject data. Note the syndicated entities contain only the @id of the
   backing subject.

   Takes as input
    - the output subject type
    - the output data model id
    - an array of syndicated entities - each will produce an output PN data model subject
    - an array of PN Data model subjects that are the backing subjects for SEs.

  It outputs
    - an array of subjects of the specified type and data model, one subject per se.

  It perfomrs the following
  1. Flatten the subjects and embedded objects, such as address
  2. Create a map of @id to flatten node
  3. Iterate over the set of passed in SE's asking each one to produce a PN Data Model Subject.
  4. Return results
*/

const assert = require('assert');
const JSONLDPromises = require('jsonld-utils/lib/jldUtils').promises;

class promisePNDataModelEntity {

  static execute(type, pnDataModelId, subjects, ses) {
    assert(type, 'promisePNDataModelEntity.execute - type param missing');
    assert(pnDataModelId, 'promisePNDataModelEntity.execute - pnDataModelId param missing');
    assert(subjects, 'promisePNDataModelEntity.execute - subjects param missing');
    assert(ses, 'promisePNDataModelEntity.execute - syndicated entities param missing');

    return new Promise(function (resolve, reject) {
        return JSONLDPromises.flattenCompact(subjects)
        .then(
          function (flattenedSubjects) {

            let nodeMap = new Map();
            for (let i = 0; i < flattenedSubjects['@graph'].length; i++) {
              nodeMap.set(flattenedSubjects['@graph'][i]['@id'], flattenedSubjects['@graph'][i]);
            }

            let data = [];
            for (let i = 0; i < ses.length; i++) {
              data.push(ses[i].pnDataModelEntity(type, pnDataModelId, nodeMap, flattenedSubjects['@graph']));
            }

            resolve(data);
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
  }

}

module.exports = promisePNDataModelEntity.execute;
