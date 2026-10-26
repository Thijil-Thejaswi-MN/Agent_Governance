#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/home/thiji/Agent_Governance"
cd "$REPO_ROOT"

PYTHON="/home/thiji/m4_venv/bin/python3"
RESULTS_DIR="$REPO_ROOT/demo/data/evaluation_v3/results"
RECEIPTS_DIR="$RESULTS_DIR/receipts"

mkdir -p "$RECEIPTS_DIR"

echo "=== [$(date -u)] M6.2 Full Evaluation Suite Startup ==="
echo "Working directory: $REPO_ROOT"
echo "Commit: $(git rev-parse HEAD)"

# 1. Run Pre-flight verification
echo "--- Running Pre-flight Checks ---"
$PYTHON scripts/m6_preflight.py

# 2. Model 1: llama3.1:8b (384 trials: 48 scenarios x 4 conditions x 2 repeats)
echo "=== [$(date -u)] Phase 1: llama3.1:8b (384 trials) ==="
$PYTHON demo/security_monitor/evaluate_v3.py \
    --scenarios demo/data/evaluation_v3/scenarios/legit_v3b.jsonl demo/data/evaluation_v3/scenarios/injected_indirect_v3b.jsonl \
    --conditions A,B,C,D \
    --model llama3.1:8b \
    --repeats 2 \
    --output "$RESULTS_DIR/full_v3b_llama3.1_8b.jsonl" \
    --receipts-dir "$RECEIPTS_DIR" \
    --resume

echo "=== [$(date -u)] Phase 1 Complete: llama3.1:8b ==="

# 3. Model 2: qwen2.5:7b (384 trials: 48 scenarios x 4 conditions x 2 repeats)
echo "=== [$(date -u)] Phase 2: qwen2.5:7b (384 trials) ==="
$PYTHON demo/security_monitor/evaluate_v3.py \
    --scenarios demo/data/evaluation_v3/scenarios/legit_v3b.jsonl demo/data/evaluation_v3/scenarios/injected_indirect_v3b.jsonl \
    --conditions A,B,C,D \
    --model qwen2.5:7b \
    --repeats 2 \
    --output "$RESULTS_DIR/full_v3b_qwen2.5_7b.jsonl" \
    --receipts-dir "$RECEIPTS_DIR" \
    --resume

echo "=== [$(date -u)] Phase 2 Complete: qwen2.5:7b ==="
echo "=== [$(date -u)] All 768 trials completed successfully ==="
