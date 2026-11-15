'use strict';

const { runPost } = require('./index');

try {
  runPost();
}
catch (error) {
  console.error(`::error::${error.message}`);
  process.exitCode = 1;
}
