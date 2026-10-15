"""Run Datadog's YARN integration once against a ResourceManager REST API and print what it
collected as one JSON line.

The check runs as the Agent would run it, against `resourcemanager_uri`, with the Agent replaced
by `datadog_checks.base`'s own stubs (what Datadog's test suite uses), so every metric, service
check and metadata value it submits is recorded and reported here.

Usage: python -I datadog_check.py <check source dir> <resourcemanager url>
"""

import json
import sys


def main():
    sys.path.insert(0, sys.argv[1])
    url = sys.argv[2]

    from datadog_checks.base.stubs import aggregator, datadog_agent
    from datadog_checks.yarn import YarnCheck

    instance = {
        "resourcemanager_uri": url,
        "cluster_name": "netget",
        # Every application, not only RUNNING ones, so a finished one's metrics are read too.
        "collect_apps_all_states": True,
        "application_tags": {"app_queue": "queue"},
        # The stub aggregator refuses the legacy `cluster_name` tag, as Datadog's own tests do.
        "disable_legacy_cluster_tag": True,
    }
    check = YarnCheck("yarn", {}, [instance])
    check.check_id = "yarn:netget"
    error = check.run()

    metrics = {}
    for name in aggregator.metric_names:
        metrics[name] = [
            {"value": m.value, "tags": sorted(m.tags)} for m in aggregator.metrics(name)
        ]
    service_checks = {}
    for name in aggregator._service_checks:
        service_checks[name] = [
            {"status": s.status, "tags": sorted(s.tags), "message": s.message}
            for s in aggregator.service_checks(name)
        ]
    print(
        json.dumps(
            {
                "error": error,
                "metrics": metrics,
                "service_checks": service_checks,
                "version": datadog_agent._metadata.get(("yarn:netget", "version.raw")),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
