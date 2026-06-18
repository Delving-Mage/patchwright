"""Benchmark harness: measure Patchwright's recall / precision / proven-fix-rate
against a known ground truth, and score competitor tools (Snyk, any SARIF) on the
SAME ground truth for an apples-to-apples head-to-head scorecard.

You cannot credibly claim "beats Snyk" without numbers. This produces them."""
