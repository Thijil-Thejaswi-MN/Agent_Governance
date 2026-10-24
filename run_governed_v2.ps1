Set-Location "C:\Users\thiji\OneDrive\Documents\Projects\A2A"
Start-Transcript -Path ".\governed_v2_run_log.txt" -Append
Get-Date
python demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model llama3.1:8b --repeats 3 --simulated-user-policy oracle --condition b --resume --output demo/data/full_llm_agent_evaluation_results_llama3.1_8b_oracle_N3_governed.json
python demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model qwen2.5:7b --repeats 3 --simulated-user-policy oracle --condition b --resume --output demo/data/full_llm_agent_evaluation_results_qwen2.5_7b_oracle_N3_governed.json
python demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model llama3.1:8b --repeats 1 --simulated-user-policy always_deny --condition b --resume --output demo/data/full_llm_agent_evaluation_results_llama3.1_8b_alwaysdeny_N1.json
python demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model qwen2.5:7b --repeats 1 --simulated-user-policy always_deny --condition b --resume --output demo/data/full_llm_agent_evaluation_results_qwen2.5_7b_alwaysdeny_N1.json
python scripts/merge_and_score_v2.py
Get-Date
Stop-Transcript
