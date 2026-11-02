"""Identity, User Roles, and Server-Side Permission Matrix (Console v4).

Roles:
- developer: Lands on /run, scoped to own runs.
- team_lead: Lands on /team, scoped to own team.
- security_reviewer: Lands on /inbox, all runs, approvals and standing rules.
- admin: Lands on /, organization-wide overview, all runs, all permissions.
- auditor: Lands on /records, read-only, verification and CSV export.

Enforces:
1. GOVERNANCE_OPERATOR_TOKEN continues to work and signs in as admin.
2. Optional GOVERNANCE_USERS_FILE (JSON or YAML) storing only token SHA-256 hashes.
   Lookups use constant-time hmac.compare_digest.
3. Server-side permission matrix enforced on every action/mutation endpoint.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from enum import Enum
from pathlib import Path
from typing import Any
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class Role(str, Enum):
    DEVELOPER = "developer"
    TEAM_LEAD = "team_lead"
    SECURITY_REVIEWER = "security_reviewer"
    ADMIN = "admin"
    AUDITOR = "auditor"


ROLE_LANDING_ROUTES = {
    Role.DEVELOPER: "/run",
    Role.TEAM_LEAD: "/team",
    Role.SECURITY_REVIEWER: "/inbox",
    Role.ADMIN: "/",
    Role.AUDITOR: "/records",
}


class UserSession(BaseModel):
    name: str
    role: Role
    team: str | None = None


class UserRecord(BaseModel):
    name: str
    role: Role
    team: str | None = None
    token_sha256: str


def hash_token(raw_token: str) -> str:
    """Hashes a raw bearer token with SHA-256."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def load_users_file(path_str: str | None = None) -> list[UserRecord]:
    """Loads users from the specified file or GOVERNANCE_USERS_FILE env var."""
    filepath = path_str or os.getenv("GOVERNANCE_USERS_FILE")
    if not filepath:
        return []
    p = Path(filepath)
    if not p.is_file():
        logger.warning("GOVERNANCE_USERS_FILE configured but file does not exist: %s", filepath)
        return []

    try:
        content = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                logger.error("PyYAML not installed, cannot read YAML users file: %s", filepath)
                return []
        else:
            data = json.loads(content)

        if not isinstance(data, list):
            logger.error("GOVERNANCE_USERS_FILE root must be a list of user entries")
            return []

        users: list[UserRecord] = []
        for item in data:
            if isinstance(item, dict):
                role_val = str(item.get("role", "")).lower()
                try:
                    role_enum = Role(role_val)
                except ValueError:
                    logger.warning("Skipping user with unknown role '%s'", role_val)
                    continue
                users.append(
                    UserRecord(
                        name=item.get("name", "Unknown"),
                        role=role_enum,
                        team=item.get("team"),
                        token_sha256=str(item.get("token_sha256", "")).lower(),
                    )
                )
        return users
    except Exception as e:
        logger.error("Failed to parse users file %s: %s", filepath, e)
        return []


def authenticate_token(token: str) -> UserSession | None:
    """Authenticates a presented token.
    1. Checks GOVERNANCE_USERS_FILE against token_sha256 using hmac.compare_digest.
    2. Fallback: Checks GOVERNANCE_OPERATOR_TOKEN using hmac.compare_digest; signs in as Admin.
    Tokens are never logged.
    """
    if not token:
        return None

    token_clean = token.strip()
    presented_hash = hash_token(token_clean)

    # 1. Try users file
    users = load_users_file()
    for u in users:
        if hmac.compare_digest(u.token_sha256, presented_hash):
            return UserSession(name=u.name, role=u.role, team=u.team)

    # 2. Try single operator token fallback (Admin)
    op_token = os.getenv("GOVERNANCE_OPERATOR_TOKEN")
    op_name = os.getenv("GOVERNANCE_OPERATOR_NAME", "Admin")
    if op_token and hmac.compare_digest(token_clean, op_token):
        return UserSession(name=op_name, role=Role.ADMIN, team=None)

    return None


class PermissionMatrix:
    """Enforces the server-side role permission matrix:

    Action                  developer   team_lead                           security_reviewer   admin   auditor
    Start/stop a run        own runs    own team                            no                  yes     no
    View runs               own         own team                            all                 all     all
    Approve/deny a request  no          own team, not provenance-escalated  yes                 yes     no
    Batch decisions         no          no                                  yes                 yes     no
    Standing rules          no          no                                  create/expire       c/e     view
    Download/verify records own         own team                            yes                 yes     yes
    """

    @staticmethod
    def can_start_run(user: UserSession) -> bool:
        return user.role in (Role.DEVELOPER, Role.TEAM_LEAD, Role.ADMIN)

    @staticmethod
    def can_stop_run(user: UserSession, task_owner: str | None, task_team: str | None) -> bool:
        if user.role == Role.ADMIN:
            return True
        if user.role == Role.TEAM_LEAD:
            return bool(user.team and task_team and user.team == task_team)
        if user.role == Role.DEVELOPER:
            return bool(task_owner and user.name == task_owner)
        return False

    @staticmethod
    def can_view_run(user: UserSession, task_owner: str | None, task_team: str | None) -> bool:
        if user.role in (Role.ADMIN, Role.SECURITY_REVIEWER, Role.AUDITOR):
            return True
        if user.role == Role.TEAM_LEAD:
            return bool(user.team and task_team and user.team == task_team)
        if user.role == Role.DEVELOPER:
            return bool(task_owner and user.name == task_owner)
        return False

    @staticmethod
    def can_decide_request(
        user: UserSession,
        task_team: str | None,
        escalated_by_provenance: bool = False,
    ) -> bool:
        if user.role in (Role.ADMIN, Role.SECURITY_REVIEWER):
            return True
        if user.role == Role.TEAM_LEAD:
            if escalated_by_provenance:
                return False
            return bool(user.team and task_team and user.team == task_team)
        return False

    @staticmethod
    def can_batch_decide(user: UserSession) -> bool:
        return user.role in (Role.ADMIN, Role.SECURITY_REVIEWER)

    @staticmethod
    def can_manage_standing_rules(user: UserSession) -> bool:
        """Create or expire standing rules."""
        return user.role in (Role.ADMIN, Role.SECURITY_REVIEWER)

    @staticmethod
    def can_view_standing_rules(user: UserSession) -> bool:
        """View standing rules."""
        return user.role in (Role.ADMIN, Role.SECURITY_REVIEWER, Role.AUDITOR)

    @staticmethod
    def can_download_or_verify_record(user: UserSession, task_owner: str | None, task_team: str | None) -> bool:
        if user.role in (Role.ADMIN, Role.SECURITY_REVIEWER, Role.AUDITOR):
            return True
        if user.role == Role.TEAM_LEAD:
            return bool(user.team and task_team and user.team == task_team)
        if user.role == Role.DEVELOPER:
            return bool(task_owner and user.name == task_owner)
        return False
