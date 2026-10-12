# Controlled Local Multi-Agent Testbed

This directory documents the local, multi-agent sandbox established for A2A security evaluation and protocol inspection.

---

## 1. Why These Agents Are Controlled Targets

In accordance with responsible security research principles, public registry agents are treated strictly as **read-only discovery metadata** and must never be subjected to unauthorized traffic, fuzzing, or adversarial testing. 

To enable rigorous security evaluation, policy enforcement, and latency benchmarking, we deploy local, fully instrumented agents within our own execution sandbox:
- **Zero External Attack Traffic**: All requests, responses, tasks, and state transitions are contained entirely on `127.0.0.1`.
- **Reproducible Baseline**: Both agents are official open-source reference implementations whose code, runtime behaviors, and state machines are fully known.
- **Heterogeneous Protocols**: The testbed includes both a modern `1.0` agent and a pre-1.0 (`0.3.0`) agent, ensuring our custom security monitor accommodates cross-specification variance.

---

## 2. Testbed Agent Inventory

### Agent A: Official HelloWorld Agent (Port 9999)
- **Source**: `demo/external/a2a-samples/samples/python/agents/helloworld`
- **Role**: Baseline Echo & Connectivity Agent.
- **Local Service URL**: `http://127.0.0.1:9999`
- **Agent Card URL**: `http://127.0.0.1:9999/.well-known/agent-card.json`
- **Saved Agent Card**: [`demo/data/agent_cards/helloworld_agent_card.json`](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/agent_cards/helloworld_agent_card.json)
- **Protocol Version**: `1.0` | **Binding**: `JSONRPC` | **Transport**: `HTTP`
- **Skills**: `echo_bot`

### Agent B: Number Guessing Evaluator (AgentAlice, Port 8001)
- **Source**: `demo/external/a2a-samples/samples/python/agents/number_guessing_game/agent_Alice.py`
- **Role**: State-tracking game evaluator (evaluates guesses against secret number; returns `"Go higher"`, `"Go lower"`, `"correct!"`).
- **Local Service URL**: `http://localhost:8001/a2a/v1`
- **Agent Card URL**: `http://127.0.0.1:8001/.well-known/agent.json`
- **Saved Agent Card**: [`demo/data/agent_cards/agent_alice_agent_card.json`](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/agent_cards/agent_alice_agent_card.json)
- **Protocol Version**: `0.3.0` | **Binding**: `JSONRPC` | **Transport**: `HTTP`
- **Skills**: `number_guess_evaluator`

### Management & Inspection: A2A Protocol Inspector (Port 5001)
- **Source**: `demo/external/a2a-inspector`
- **Local Service URL**: `http://127.0.0.1:5001`
- **Role**: Visual debugger, spec compliance validator, and interactive message console.
- **Connected Targets**: Verified against both `http://127.0.0.1:9999` and `http://127.0.0.1:8001`.

---

## 3. Verification of Normal Communication

1. **HelloWorld (Agent A)**:
   - Verified via official `test_client.py`: Request `"Say hello."` -> Response `"Hello, World! I have received your request (Say hello.)"`.
   - Verified via A2A Inspector on port 5001: Loaded Agent Card, validated spec compliance (`validation_errors: []`), dispatched task `"Hello from A2A Inspector Test!"`, received full state transitions (`submitted` -> `working` -> `artifact-update` -> `completed`).
2. **AgentAlice (Agent B)**:
   - Verified via official SDK client wrapper: Dispatched numeric guess `"50"` -> Agent evaluated secret number and returned hint `"Go higher"` with `TaskState.completed`.
   - Verified via A2A Inspector: Card loaded with status 200, spec compliance passed (`validation_errors: []`).

---

## 4. Foundation for Phase 5 (Security Monitor Integration)

This multi-agent topology serves as the live target environment for Phase 5:
- It provides multiple distinct ports, interfaces, and skills for policy routing.
- It enables measuring baseline vs. mediated latency overhead.
- It allows testing prompt injection, rogue agent card substitution, and unauthenticated parameter tampering safely on local processes without contacting any third party.
