"""The Spark application the Spark client's evidence is read from.

Run by `spark-submit` from the pinned distribution (tests/client/spark/install_peers.sh). It runs
three kinds of work so every resource the client reads has something real in it:

* job group `netget`: a one-stage `count`, then a two-stage `reduceByKey` (a shuffle);
* job group `netget-sql`: a DataFrame `groupBy().count()`, which is also a SQL execution;
* job group `netget-failing`: one job whose only task raises, so a FAILED job and a FAILED
  stage exist.

Then it prints one line, `NETGET-SPARK-READY {json}`, carrying what Spark itself says about that
work, read from `SparkContext.statusTracker()` — the application id, every job's group, status
and stage ids, and every stage's attempt, name and task counts — and either stays up (`serve`:
the live UI keeps answering until the test kills the process group) or stops cleanly (`exit`:
the event log is closed, for the History Server).

Usage: spark-submit evidence_app.py serve|exit
"""

import json
import sys
import time

from pyspark.sql import SparkSession


def fail(_):
    raise ValueError("netget evidence: this task fails on purpose")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "serve"
    spark = SparkSession.builder.appName("netget-evidence").getOrCreate()
    sc = spark.sparkContext

    sc.setJobGroup("netget", "netget evidence jobs")
    counted = sc.parallelize(range(1000), 4).count()
    reduced = (
        sc.parallelize(range(100), 4)
        .map(lambda x: (x % 7, 1))
        .reduceByKey(lambda a, b: a + b, 3)
        .collect()
    )

    sc.setJobGroup("netget-sql", "netget evidence query")
    grouped = spark.range(0, 500, 1, 2).selectExpr("id % 5 AS k").groupBy("k").count().collect()

    sc.setJobGroup("netget-failing", "a job that fails on purpose")
    failed = False
    try:
        sc.parallelize([1], 1).map(fail).collect()
    except Exception:
        failed = True

    tracker = sc.statusTracker()
    jobs = []
    stages = []
    for group in ("netget", "netget-sql", "netget-failing"):
        for job_id in sorted(tracker.getJobIdsForGroup(group)):
            info = tracker.getJobInfo(job_id)
            jobs.append(
                {
                    "jobId": job_id,
                    "group": group,
                    "status": str(info.status),
                    "stageIds": sorted(info.stageIds),
                }
            )
            for stage_id in info.stageIds:
                stage = tracker.getStageInfo(stage_id)
                if stage is not None:
                    stages.append(
                        {
                            "stageId": stage.stageId,
                            "attemptId": stage.currentAttemptId,
                            "name": stage.name,
                            "numTasks": stage.numTasks,
                            "numCompletedTasks": stage.numCompletedTasks,
                            "numFailedTasks": stage.numFailedTasks,
                        }
                    )
    report = {
        "app_id": sc.applicationId,
        "app_name": sc.appName,
        "spark_version": spark.version,
        "counted": counted,
        "reduced": len(reduced),
        "grouped": len(grouped),
        "failed_job_raised": failed,
        "jobs": jobs,
        "stages": stages,
    }
    print("NETGET-SPARK-READY " + json.dumps(report), flush=True)

    if mode == "serve":
        while True:
            time.sleep(3600)
    spark.stop()


if __name__ == "__main__":
    main()
