from __future__ import annotations

from typing import Any
from ..core.models import NormalizedAgentCard, NormalizedSkill, AgentStatus, SecurityViolation
from ..storage.db import SQLiteManager


class InMemoryAgentInventory:
    """
    Manages trusted A2A agents, active restrictions, and quarantined identities.
    Backed by SQLite for persistence across monitor process restarts.
    """

    def __init__(self, storage: SQLiteManager | None = None) -> None:
        self.storage = storage or SQLiteManager()
        self._trusted_cards: dict[str, NormalizedAgentCard] = {}
        self._quarantined_identities: dict[str, dict[str, Any]] = {}
        self._restricted_identities: dict[str, dict[str, Any]] = {}
        self._released_identities: set[str] = set()
        self._init_from_storage()

    def _init_from_storage(self) -> None:
        """Load persisted state from SQLite database; seed verified baseline if empty."""
        # 1. Load quarantine
        self._quarantined_identities = self.storage.load_quarantined_records()

        # 2. Load restrictions
        self._restricted_identities = self.storage.load_restriction_records()

        # 3. Load trusted agents
        raw_agents = self.storage.load_agents()
        if raw_agents:
            for aid, cdict in raw_agents.items():
                skills = [
                    NormalizedSkill(
                        id=s.get("id", ""),
                        name=s.get("name", ""),
                        description=s.get("description", ""),
                        tags=s.get("tags", []),
                    )
                    for s in cdict.get("skills", [])
                ]
                self._trusted_cards[aid] = NormalizedAgentCard(
                    name=cdict.get("name", ""),
                    description=cdict.get("description", ""),
                    version=cdict.get("version", "0.0.1"),
                    protocol_version=cdict.get("protocol_version", "1.0"),
                    protocol_binding=cdict.get("protocol_binding", "JSONRPC"),
                    endpoint_url=cdict.get("endpoint_url", ""),
                    skills=skills,
                    security_schemes=cdict.get("security_schemes", {}),
                    raw_card=cdict.get("raw_card", {}),
                )
        else:
            self._seed_baseline()

    def _seed_baseline(self) -> None:
        """Seed verified official HelloWorld and AgentAlice agents into inventory and SQLite."""
        hello_card = NormalizedAgentCard(
            name="Hello World Agent",
            description="Just a hello world agent",
            version="0.0.1",
            protocol_version="1.0",
            protocol_binding="JSONRPC",
            endpoint_url="http://127.0.0.1:9999",
            skills=[
                NormalizedSkill(
                    id="echo_bot",
                    name="Echo Bot",
                    description="An example agent that acknowledges client request and responds with a \"Hello World\" message.",
                    tags=["a2a", "echo-example"],
                )
            ],
            security_schemes={},
            raw_card={"name": "Hello World Agent", "version": "0.0.1"},
        )
        self.register_trusted("helloworld", hello_card)

        alice_card = NormalizedAgentCard(
            name="AgentAlice",
            description="Hosts the number-guessing game by picking a secret number and grading guesses.",
            version="1.0.0",
            protocol_version="0.3.0",
            protocol_binding="JSONRPC",
            endpoint_url="http://127.0.0.1:8001/a2a/v1",
            skills=[
                NormalizedSkill(
                    id="number_guess_evaluator",
                    name="Number Guess Evaluator",
                    description="Evaluates numeric guesses (1-100) against a secret number and replies with guidance (higher/lower/correct).",
                    tags=["game", "demo"],
                )
            ],
            security_schemes={},
            raw_card={"name": "AgentAlice", "version": "1.0.0", "protocolVersion": "0.3.0"},
        )
        self.register_trusted("agentalice", alice_card)

    def register_trusted(self, agent_id: str, card: NormalizedAgentCard) -> None:
        self._trusted_cards[agent_id] = card
        self.storage.save_agent(
            agent_id=agent_id,
            card_dict=card.model_dump(),
            status=AgentStatus.TRUSTED.value,
        )

    def get_trusted_cards(self) -> list[NormalizedAgentCard]:
        return list(self._trusted_cards.values())

    def get_trusted_map(self) -> dict[str, NormalizedAgentCard]:
        return dict(self._trusted_cards)

    def get_trusted_agent(self, agent_id: str) -> NormalizedAgentCard | None:
        return self._trusted_cards.get(agent_id)

    # --- Quarantine Management ---
    def quarantine(self, identity: str, reason: str, violation: SecurityViolation | None = None) -> None:
        key = identity.strip().lower()
        viol_dict = violation.model_dump() if violation else None
        self._quarantined_identities[key] = {
            "identity": identity,
            "reason": reason,
            "violation": viol_dict,
        }
        self.storage.set_quarantine(key, reason, viol_dict)

    def release_quarantine(self, identity: str) -> bool:
        key = identity.strip().lower()
        self._released_identities.add(key)
        existed = key in self._quarantined_identities
        if existed:
            del self._quarantined_identities[key]
        self.storage.release_quarantine(key)
        return existed

    def release_restriction(self, identity: str) -> bool:
        key = identity.strip().lower()
        self._released_identities.add(key)
        existed = key in self._restricted_identities
        if existed:
            del self._restricted_identities[key]
        self.storage.release_restriction(key)
        return existed

    def is_released_or_historical(self, identity: str) -> bool:
        key = identity.strip().lower()
        if key in self._released_identities:
            return True
        try:
            with self.storage.get_connection() as conn:
                row = conn.execute("SELECT 1 FROM quarantine_store WHERE LOWER(identity) = ?", (key,)).fetchone()
                if row:
                    return True
                row_r = conn.execute("SELECT 1 FROM restriction_store WHERE LOWER(identity) = ?", (key,)).fetchone()
                if row_r:
                    return True
        except Exception:
            pass
        return False

    def is_quarantined(self, identity_or_endpoint: str) -> bool:
        key = identity_or_endpoint.strip().lower().rstrip('/')
        if key in self._quarantined_identities:
            return True
        for q_id, q_data in self._quarantined_identities.items():
            if q_id == key:
                return True
            viol = q_data.get("violation")
            if viol and viol.get("candidate_endpoint", "").rstrip('/').lower() == key:
                return True
        return False

    def get_quarantined_records(self) -> list[dict[str, Any]]:
        return list(self._quarantined_identities.values())

    # --- Restriction Management ---
    def restrict(
        self,
        identity: str,
        reason: str,
        allowed_operations: list[str] | None = None,
    ) -> None:
        key = identity.strip().lower()
        ops = allowed_operations if allowed_operations is not None else [
            ".well-known/agent-card.json",
            ".well-known/agent.json",
            "status",
        ]
        self._restricted_identities[key] = {
            "identity": identity,
            "reason": reason,
            "allowed_operations": ops,
        }
        self.storage.set_restriction(key, reason, ops)


    def is_restricted(self, identity: str) -> bool:
        key = identity.strip().lower()
        return key in self._restricted_identities

    def is_operation_allowed_when_restricted(self, identity: str, method_or_path: str) -> bool:
        """
        Check if an operation is permitted for a restricted entity.
        Permits safe read-only/metadata operations (.well-known, status).
        Denies task executions and mutating actions.
        """
        key = identity.strip().lower()
        rec = self._restricted_identities.get(key)
        if not rec:
            return True  # Not restricted

        allowed_ops = [op.lower() for op in rec.get("allowed_operations", [])]
        clean_target = method_or_path.strip().lower().lstrip('/')

        for op in allowed_ops:
            clean_op = op.lstrip('/')
            if clean_target == clean_op or clean_target.startswith(clean_op):
                return True
            if clean_target.endswith(clean_op):
                return True

        return False

    def get_restricted_records(self) -> list[dict[str, Any]]:
        return list(self._restricted_identities.values())

    def summary(self) -> dict[str, Any]:
        return {
            "total_trusted": len(self._trusted_cards),
            "trusted_agents": [
                {
                    "agent_id": k,
                    "name": v.name,
                    "endpoint_url": v.endpoint_url,
                    "version": v.version,
                    "skills_count": len(v.skills),
                }
                for k, v in self._trusted_cards.items()
            ],
            "total_quarantined": len(self._quarantined_identities),
            "quarantined_count": len(self._quarantined_identities),
            "quarantined_identities": list(self._quarantined_identities.keys()),
            "quarantined_agents": list(self._quarantined_identities.keys()),
            "total_restricted": len(self._restricted_identities),
            "restricted_count": len(self._restricted_identities),
            "restricted_identities": list(self._restricted_identities.keys()),
            "restricted_agents": list(self._restricted_identities.keys()),
        }
