'use strict';

const { buildMockReportData } = require('./mock_data');

async function collectReportData(input) {
  if (input.mock) {
    return buildMockReportData(input);
  }

  validateCookieInputs(input);

  // TODO: Wire real MSS/XDR calls here. Keep this layer responsible only for
  // fetching raw data and normalizing it into the reportData contract.
  throw new Error('Real data source is not implemented yet. Use --mock true for skeleton generation.');
}

function validateCookieInputs(input) {
  if (!input.cookiePath) {
    throw new Error('Real mode requires --cookie-path');
  }
  if (!input.xdrCookiePath) {
    throw new Error('Real mode requires --xdr-cookie-path');
  }
}

module.exports = {
  collectReportData
};

