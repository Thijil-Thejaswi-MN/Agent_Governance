#!/bin/bash
# M7 v1.1 regression: condition C, gold boundary, qwen2.5:7b (temperature 0, seed 42 are harness defaults).
cd /home/thiji/Agent_Governance || exit 1
R=demo/data/evaluation_v3/results; SC=demo/data/evaluation_v3/scenarios
P=/home/thiji/m4_venv/bin/python; E=demo/security_monitor/evaluate_v3.py
COMMON="--conditions C --model qwen2.5:7b --repeats 1 --boundary-model v1.1 --boundary-source gold --receipts-dir $R/receipts_m7_v1_1"
$P $E --scenarios $SC/injected_indirect_v3b.jsonl $COMMON --output $R/m7_v1_1_injected_C.jsonl > $R/m7_v1_1_injected_C_log.txt 2>&1 &&
$P $E --scenarios $SC/injected_indirect_v3b.jsonl --shell-only $COMMON --output $R/m7_v1_1_e1b_C.jsonl > $R/m7_v1_1_e1b_C_log.txt 2>&1 &&
$P $E --scenarios $SC/legit_v3d.jsonl $COMMON --output $R/m7_v1_1_utility_C.jsonl > $R/m7_v1_1_utility_C_log.txt 2>&1
echo "exit=$? $(date -Is)" > $R/m7_v1_1_DONE.txt
