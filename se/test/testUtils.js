/*jslint node: true, vars: true */

//
// Utilities to help testing
//
const configFactory = require('connector-utils/config/lib/configFactory');
const fs = require('fs');

let utils = {};
utils.getTestConfig = function getTestConfig() {
  'use strict';

  let file = './default-config.yaml'; // default in image
  console.log('****Configuration File is:%s this can be changed using the CONFIG_FILE env', file);

  let configFile = fs.readFileSync(__dirname + '/' + file).toString();
  let serviceName = 'test-is-se';
  let config = configFactory.createFromYAML(configFile, serviceName);

  return config;
};

module.exports = {
  utils: utils,
};
