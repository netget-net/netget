import sys, json, os

src = json.load(open(sys.argv[1]))["prompt"]
out = sys.argv[2]
os.makedirs(out, exist_ok=True)
ERR_DESC_OLD = "Refuse the submission itself with a server ERROR packet instead of running it."
ERR_CODE_OLD = "An error identifier such as queue_full or unknown_function"
FAIL_OLD = "Finish the job as failed (WORK_FAIL), e.g. for a function you do not provide or a workload you cannot process."
EV_OLD = "answer with complete_gearman_job (optionally preceded by send_gearman_status or send_gearman_data), fail_gearman_job, send_gearman_exception, or send_gearman_error."
for s in (ERR_DESC_OLD, ERR_CODE_OLD, FAIL_OLD, EV_OLD):
    assert s in src, s
ERR_DESC_NEW = ("Refuse the submission at the server level with an ERROR packet, for a server condition such as a full queue. "
                "Not for a function you do not provide: that is a failed job (fail_gearman_job). The gearman client exits 0 on ERROR, as if the job had succeeded.")
ERR_CODE_NEW = "An error identifier such as queue_full"
FAIL_NEW = ("Finish the job as failed (WORK_FAIL): the answer for a function you do not provide or a workload you cannot process. "
            "The client reports the job failed.")
EV_NEW = ("answer with complete_gearman_job (optionally preceded by send_gearman_status or send_gearman_data), or with fail_gearman_job "
          "when you do not provide the function or cannot process the workload.")
EV_NOERR = "answer with complete_gearman_job (optionally preceded by send_gearman_status or send_gearman_data), fail_gearman_job, or send_gearman_exception."


def drop_error(t):
    a = t.index("## 10. send_gearman_error")
    b = t.index("## 11. close_connection")
    return t[:a] + t[b:].replace("## 11. close_connection", "## 10. close_connection")


def r(t, *pairs):
    for a, b in pairs:
        t = t.replace(a, b)
    return t


V = {
    "base": src,
    "code": r(src, (ERR_CODE_OLD, ERR_CODE_NEW)),
    "code_desc": r(src, (ERR_CODE_OLD, ERR_CODE_NEW), (ERR_DESC_OLD, ERR_DESC_NEW)),
    "code_desc_fail": r(src, (ERR_CODE_OLD, ERR_CODE_NEW), (ERR_DESC_OLD, ERR_DESC_NEW), (FAIL_OLD, FAIL_NEW)),
    "all": r(src, (ERR_CODE_OLD, ERR_CODE_NEW), (ERR_DESC_OLD, ERR_DESC_NEW), (FAIL_OLD, FAIL_NEW), (EV_OLD, EV_NEW)),
    "ev_only": r(src, (EV_OLD, EV_NEW)),
    "no_error": drop_error(r(src, (EV_OLD, EV_NOERR))),
    "no_error_fail": drop_error(r(src, (EV_OLD, EV_NEW), (FAIL_OLD, FAIL_NEW))),
}
for k, v in V.items():
    open(f"{out}/{k}.txt", "w").write(v)
print(list(V))
