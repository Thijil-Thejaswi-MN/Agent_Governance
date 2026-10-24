Set-Location "C:\Users\thiji\OneDrive\Documents\Projects\A2A"
Start-Transcript -Path ".\overnight_run_log.txt" -Append
Get-Date
$py = "python"
& $py demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model llama3.1:8b --repeats 3 --simulated-user-policy oracle --condition both --resume --output demo/data/full_llm_agent_evaluation_results_llama3.1_8b_oracle_N3.json
& $py demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model qwen2.5:7b --repeats 3 --simulated-user-policy oracle --condition both --resume --output demo/data/full_llm_agent_evaluation_results_qwen2.5_7b_oracle_N3.json
& $py demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model llama3.1:8b --repeats 1 --simulated-user-policy always_deny --governed-only --resume --output demo/data/full_llm_agent_evaluation_results_llama3.1_8b_alwaysdeny_N1.json
& $py demo/security_monitor/evaluate_llm_agent_injection.py --provider ollama --model qwen2.5:7b --repeats 1 --simulated-user-policy always_deny --governed-only --resume --output demo/data/full_llm_agent_evaluation_results_qwen2.5_7b_alwaysdeny_N1.json
& $py demo/security_monitor/score_results.py --input demo/data/full_llm_agent_evaluation_results_llama3.1_8b_oracle_N3.jsonl
& $py demo/security_monitor/score_results.py --input demo/data/full_llm_agent_evaluation_results_qwen2.5_7b_oracle_N3.jsonl
& $py demo/security_monitor/score_results.py --input demo/data/full_llm_agent_evaluation_results_llama3.1_8b_alwaysdeny_N1.jsonl
& $py demo/security_monitor/score_results.py --input demo/data/full_llm_agent_evaluation_results_qwen2.5_7b_alwaysdeny_N1.jsonl
Get-Date
Stop-Transcript
