'use strict';

const assert = require('assert');
const { mergeBranch1ReportPatch, sanitizeBranch1ReportPatch } = require('../src/branch1_adapter');

function main() {
  const baseReport = {
    riskOverview: {
      totalEvents: 12
    },
    summary: {
      internet: {
        exposure: {
          total: 3
        }
      }
    }
  };

  const patch = {
    scoring: {
      total_score: 88.6,
      grade: '良'
    },
    protection_effectiveness: {
      policy_stats: {
        total: 5,
        abnormal_count: 2
      }
    },
    summary: {
      shouldNotOverride: true
    }
  };

  const merged = mergeBranch1ReportPatch(baseReport, patch);
  assert.strictEqual(merged.scoring.total_score, 88.6);
  assert.strictEqual(merged.protection_effectiveness.policy_stats.abnormal_count, 2);
  assert.strictEqual(merged.summary.internet.exposure.total, 3);
  assert.strictEqual(merged.summary.shouldNotOverride, undefined);
  assert.strictEqual(merged.riskOverview.totalEvents, 12);

  const sanitized = sanitizeBranch1ReportPatch({});
  assert.deepStrictEqual(sanitized, {
    scoring: {},
    protection_effectiveness: {}
  });

  console.log('branch1_adapter.test.js passed');
}

main();
