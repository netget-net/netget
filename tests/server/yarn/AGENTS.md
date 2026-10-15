# YARN server E2E tests

`e2e_test.rs` drives the YARN ResourceManager REST endpoints with `reqwest` and asserts the
decoded JSON matches the documented Hadoop `ResourceManagerRest` envelopes — shape-conformance.
`datadog_check_test.rs` is the independent consumer: **Datadog's YARN integration**
(`datadog_checks.yarn`, integrations-core tag `yarn-8.4.2`, installed by
`install_datadog_check.sh` with every file's SHA-256 pinned, run by `datadog_check.py` with
`datadog_checks.base`'s stubs in place of the Agent). It reads `/metrics`, `/apps`, `/nodes` and
`/scheduler` and the test asserts what it submitted. It **fails rather than skips** without
`NETGET_DATADOG_YARN`:

```bash
PYTHON=python3.12 sh tests/server/yarn/install_datadog_check.sh /tmp/datadog-yarn
export NETGET_DATADOG_YARN=/tmp/datadog-yarn
```

It found the scheduler endpoint missing (a static 404 on every Agent run); see
`src/server/yarn/AGENTS.md`. The real Hadoop `yarn` CLI is used by the YARN *client*'s suite
(`tests/client/yarn/`), not here: a CLI that speaks RPC to a ResourceManager cannot be pointed
at a REST server.

## Mock expectations

Default (mocked) mode, no Ollama. Every test ends with `server.verify_mocks().await?`. Mocks match
on the `yarn_request` event's `operation` field so one server handles several endpoints.

## LLM call budget

- `test_yarn_cluster_info_static_and_metrics`: startup (1) + metrics (1). `/ws/v1/cluster/info` is
  **static** — no LLM call. Total 2.
- `test_yarn_apps_list_and_by_id`: startup (1) + apps (1) + app (1). Total 3.
- `test_yarn_submit_application_accepted`: startup (1) + submit (1). Total 2.
- `llm_failure_test`: startup (1) + one unmatched metrics request that forces a 5xx. Total ~2.
- `datadog_check_test`: startup (1) + metrics, apps, nodes, scheduler (4), one rule branching on
  `operation`. Total 5.

Suite total ~14 LLM calls across five independent tests. Localhost only; never contacts external endpoints.

## What each test validates

- Static info banner (`clusterInfo.state == STARTED`, version present) with no model round-trip.
- `send_yarn_metrics` wraps into `{"clusterMetrics":{...}}` and defaults omitted fields to 0.
- `send_yarn_apps`/`send_yarn_app` wrap into `{"apps":{"app":[...]}}` / `{"app":{...}}`.
- `send_yarn_submit_response` accepted → **202 Accepted** with a `Location` header, empty body.
- `llm_failure_test`: LLM failure → 5xx `RemoteException`, never `200 {"apps":null}`.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features yarn \
    --test server -- server::yarn::e2e_test --test-threads=100
```
