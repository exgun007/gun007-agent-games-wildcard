# GUN007 Wildcard Guard

A small, deterministic **read-only** wallet/contract safety-triage agent built for Agent Games' open Wildcard track. It receives user-supplied risk indicators and returns structured findings, explicitly marking missing information as unknown. It does not claim to audit contracts, query a chain, connect wallets, sign transactions, or move funds.

## Run

```bash
python3 server.py --host 127.0.0.1 --port 8787
```

- `GET /` — agent metadata
- `GET /health` — health check
- `POST /agent` — assess a JSON object

Example request:

```json
{
  "chain": "BSC",
  "contract_address": "0x0000000000000000000000000000000000000001",
  "simulation_failed": false,
  "unlimited_approval": true,
  "owner_can_mint": false,
  "owner_can_pause": null
}
```

Example response includes a `CAUTION` decision, an unlimited-approval warning, a clearly unknown pause-authority result, and explicit `onchain_queries: 0`, `wallet_connected: false`, and `transaction_submitted: false` flags. This is a heuristic based only on provided indicators; unknown is not safe.

## Optional request authentication

For local/private use, set `AGENT_GAMES_HMAC_SECRET` in the server environment. The server checks `x-agent-games-signature` against the hex HMAC-SHA256 of the exact raw JSON request body, and signs the exact compact JSON response body with the same header. Without the variable, signatures are not required. Do not put the competition's rotated secret in a public demo deployment; the Wildcard demo is not the Proof Gatekeeper protocol.

## Verify

```bash
python3 -m unittest discover -s tests -v
```

No external packages are needed (Python 3.10+).

## Safety / limitations

This is a demonstration and preliminary triage aid, not a security audit or financial advice. It has no RPC integration and cannot establish whether any assertion is true. It never submits transactions or interacts with wallets. Verify contracts and transactions independently before acting.

## Track

Agent Games · Wildcard (open-build track). Public demo and use-case explanation are required by the track description; zkVerify proof use is optional.
