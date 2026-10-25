# demo/

This directory holds the code, data and reports for the project. For the overview, architecture, status, verified results, limitations and quick start, see the [root README](../README.md).

- `security_monitor/`: the governance code (`app/governance/`, including the OS layer in `app/governance/os_layer/`), the original A2A gateway (`app/gateway/`), the dashboard (`app/dashboard/`), evaluation runners and tests.
- `data/`: scenarios and result files. M5 results are at the top level, and M6 results are in `evaluation_v3/`. The A2A-phase corpus is in `evaluation/` (see `evaluation/RESEARCH_BASELINE.md`). Agent cards, registry snapshots and the testbed description are also here.
- `docs/`: reports from the A2A gateway phase (phases 2–5, stages 2–6). These describe the earlier gateway work, not the current task-scoped governance.

The A2A gateway and its dashboard can still be run on their own:

```bash
cd demo/security_monitor
python -m uvicorn app.gateway.server:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/dashboard
```
