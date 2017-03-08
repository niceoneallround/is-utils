/*jslint node: true, vars: true */
/*

   Process the set of passed in set syndicated entities and thier backing subjects to produce concrete
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
const SyndicatedEntity = require('./SyndicatedEntity');

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

            // The backing subjects are flattened, which creates an array of all the
            // subjects and any embedded objects, such as address. This is used to
            // create a map so can lookup as created the output entity from the syndicated
            // entity. This is done as the syndicated entity just has @id pointers to the
            // actual data in the backing subjects.
            //
            // Note this will also merge any duplicate @id information into a single object
            //

            let nodeMap = new Map();
            for (let i = 0; i < flattenedSubjects['@graph'].length; i++) {
              nodeMap.set(flattenedSubjects['@graph'][i]['@id'], flattenedSubjects['@graph'][i]);
            }

            // if the ses are not already Syndicated Entities then create - sometimes just JSON
            // is passed across the wire so need to make into a class.
            let syndEnts = ses;
            if (!(ses[0] instanceof SyndicatedEntity)) {
              syndEnts = [];
              for (let i = 0; i < ses.length; i++) {
                syndEnts.push(SyndicatedEntity.createFromJSON(ses[i]));
              }
            }

            // iterate across the SEs creating the output subjects that may include properties from more
            // than one backing subject @id for that subject.
            let data = [];
            for (let i = 0; i < syndEnts.length; i++) {
              data.push(syndEnts[i].pnDataModelEntity(type, pnDataModelId, nodeMap, flattenedSubjects['@graph']));
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
