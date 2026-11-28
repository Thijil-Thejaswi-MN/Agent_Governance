# Remote Outside A2A Agents (Deploy & Verify)

> **Rule: Only agents we own.** Never send tasks, attacks, or probes to third-party agents, including public registry agents. Reading their public cards is fine.

This guide shows how to generate signing keys outside the repository, deploy `demo/outside_agents/` to a host you own (Google Cloud Run, Render, or Hugging Face Spaces), pin the partner's public JWK anchor, and verify calls with `scripts/a2a_remote_check.py`.

---

## 1. Generate a partner key pair (outside the repository)

Never commit private or test keys to Git. Generate keys in a private directory outside the repository:

```bash
mkdir -p ~/.secrets/a2a_partner
python scripts/make_partner_keys.py --out ~/.secrets/a2a_partner/keypair.json > ~/.secrets/a2a_partner/partner.jwk.json
```

`scripts/make_partner_keys.py` sets `chmod 600` on the keypair file and prints only the public JWK to stdout so you can pin `~/.secrets/a2a_partner/partner.jwk.json`.

Extract the private JWK string when configuring your hosting provider's secret/environment variables:

```bash
python -c 'import json; print(json.dumps(json.load(open("'"$HOME"'/.secrets/a2a_partner/keypair.json"))["private_jwk"]))'
```

---

## 2. Deploy to a host you own

The Dockerfile in `demo/outside_agents/` serves an A2A v1.0 partner (`PARTNER_MODE=demo|echo|hostile|hostile_v2`). Keys come strictly from environment variables at deploy time (`PARTNER_PRIVATE_JWK` or `PARTNER_KEY_FILE`), never from the repository.

### Option A: Google Cloud Run

```bash
export PARTNER_PRIVATE_JWK="$(python -c 'import json; print(json.dumps(json.load(open("'"$HOME"'/.secrets/a2a_partner/keypair.json"))["private_jwk"]))')"

gcloud run deploy outside-a2a-partner \
  --source demo/outside_agents \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "PARTNER_MODE=demo"
```

After the first deploy gives you your service HTTPS URL (for example `https://outside-a2a-partner-xxxxx-uc.a.run.app`), set both `PARTNER_PUBLIC_URL` and `PARTNER_PRIVATE_JWK` (via Secret Manager or env update) so the card's `supportedInterfaces` advertises the HTTPS URL:

```bash
gcloud run services update outside-a2a-partner \
  --region us-central1 \
  --set-env-vars "PARTNER_MODE=demo,PARTNER_PUBLIC_URL=https://YOUR_SERVICE.run.app,PARTNER_PRIVATE_JWK=${PARTNER_PRIVATE_JWK}"
```

### Option B: Render

1. Create a new **Web Service** from this repository with **Root Directory** set to `demo/outside_agents` and **Runtime** set to **Docker**.
2. Set environment variables in Render Dashboard:
   - `PARTNER_MODE=demo`
   - `PARTNER_PUBLIC_URL=https://YOUR-SERVICE.onrender.com` (`RENDER_EXTERNAL_URL` is also auto-detected)
   - `PARTNER_PRIVATE_JWK=<compact JSON of private_jwk from keypair.json>`
3. Optional bearer auth on incoming RPC calls: set `PARTNER_BEARER_TOKEN` in Render and store that token in a local file outside the repo (for `--auth-token-file`).

### Option C: Hugging Face Spaces (Docker)

1. Create a **Docker Space**, copy `demo/outside_agents/Dockerfile`, `requirements.txt`, `__init__.py`, `partner_app.py`, `echo_partner.py`, and `hostile_partner.py` into the Space.
2. Add **Space Secrets / Variables**:
   - `PORT=7860`
   - `PARTNER_MODE=demo`
   - `PARTNER_PUBLIC_URL=https://YOUR_USER-YOUR_SPACE.hf.space` (`SPACE_HOST` is also auto-detected)
   - `PARTNER_PRIVATE_JWK=<compact JSON of private_jwk from keypair.json>`

---

## 3. Pin the key & register in Governance API (admin only)

With the Governance Console running and signed in as an `admin`:

```bash
export PARTNER_CARD_URL="https://YOUR_SERVICE_HOST/.well-known/agent-card.json"

python - <<'PY'
import json, os, urllib.request
anchor = json.load(open(os.path.expanduser("~/.secrets/a2a_partner/partner.jwk.json")))
payload = json.dumps({
    "agent_id": "remote_partner",
    "card_url": os.environ["PARTNER_CARD_URL"],
    "jwk_anchor": anchor,
    "allowed_callers": ["planner"],
    "allowed_skills": ["echo", "hotel_prices"],
    "max_label": "internal",
    "auth_type": "none",
}).encode("utf-8")
req = urllib.request.Request(
    "http://127.0.0.1:8000/api/governance/outside-agents",
    data=payload,
    headers={
        "Content-Type": "application/json",
        "X-Operator-Token": os.environ["GOVERNANCE_OPERATOR_TOKEN"],
    },
)
with urllib.request.urlopen(req) as resp:
    print(resp.read().decode("utf-8"))
PY
```

---

## 4. Run the remote check script

Run `scripts/a2a_remote_check.py` against **your own** deployed URL:

```bash
python scripts/a2a_remote_check.py \
  --card-url https://YOUR_SERVICE_HOST/.well-known/agent-card.json \
  --anchor ~/.secrets/a2a_partner/partner.jwk.json
```

If bearer auth is enabled on your partner deployment, keep the token in a file outside the repository (`chmod 600`) and pass `--auth-token-file /path/outside/repo/partner.token`.

Expected output prints:
- registration verification status, `card_kid`, `card_hash`, and any ignored `extra_skills`
- `[benign_call]` outcome, remote task ID, `integrity=untrusted`, and receipt ID (`verified=True`)
- `[hostile_call]` outcome, follow-up `http_post` blocked by Rule 2, and receipt ID (`verified=True`)
