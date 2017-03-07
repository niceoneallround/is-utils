/*jslint node: true */
/*

This file contains values that need to be shared across the canons so that
they link together.

*/

let CONSTANTS = {

  // used in syndicated enities, jwts, etc as the syndication job id
  ALICE_SYNDICATION_JOB_ID: 'http://canon.test.webshield/fake-syndication-job-alice',
  BOB_SYNDICATION_JOB_ID: 'http://canon.test.webshield/fake-syndication-job-bob',
};

module.exports = CONSTANTS;
