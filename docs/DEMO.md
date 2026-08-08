# DemonClaw Reproducible Operator Demo

This demo is intended for an isolated lab VM that you control. Do not intentionally expose the demonstration listener on an untrusted network.

## 1. Start the database and daemon

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export DEMONCLAW_TOKEN="$(openssl rand -hex 32)"
export DEMONCLAW_REQUIRE_ENGAGEMENT=1
export DEMONCLAW_ENGAGEMENT_ID=demo-lab
export DEMONCLAW_MAX_TOOL_LEVEL=passive

docker compose up -d
```

Verify the runtime:

```bash
docker compose exec demonclaw demonclaw doctor
```

## 2. Register a lab target

For a native installation on the lab VM:

```bash
demonclaw target add lab-local --local --tag demo
demonclaw defend baseline lab-local
demonclaw findings list
```

## 3. Introduce controlled drift

On the isolated lab VM, start a temporary listener on a port DemonClaw classifies as high risk:

```bash
python3 -m http.server 6379 --bind 0.0.0.0
```

In another shell:

```bash
demonclaw defend drift lab-local
demonclaw scan vuln lab-local
demonclaw findings list
```

The listener is deliberately not Redis; the point is to demonstrate that the listening-port detector recognizes a new wildcard bind on the Redis port and creates persistent finding state. The finding remains linked to the evidence trail and gains occurrence counts instead of being recreated as unrelated events.

## 4. Inspect operations state

Open the local dashboard at `http://127.0.0.1:3000/dashboard/operations` or use:

```bash
curl -s http://127.0.0.1:3000/api/v1/targets
curl -s http://127.0.0.1:3000/api/v1/findings
```

## 5. Resolve the drift

Stop the temporary listener, then run:

```bash
demonclaw scan vuln lab-local
demonclaw findings list --status resolved
```

The previous finding should transition to `resolved` when it is absent from a subsequent scan of the same target/scope.

## 6. Verify evidence integrity

```bash
demonclaw doctor
curl -s http://127.0.0.1:3000/api/v1/evidence/verify
```

This demonstrates the intended operator loop: register -> baseline -> detect -> persist -> investigate -> resolve -> verify evidence.
