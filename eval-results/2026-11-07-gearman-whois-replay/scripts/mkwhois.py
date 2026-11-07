import json
import os
import sys

src = json.load(open(sys.argv[1]))["prompt"]
out = sys.argv[2]
os.makedirs(out, exist_ok=True)
ERR_OLD = "Send error message for domain not found"
ERR_NEW = ("Answer that the query has no record - no match, not found, not registered. Printed as "
           "`Error: <message>`; say it in the message, e.g. No match for \"example.invalid\". Use this, "
           "not send_whois_record, for a domain with no record: a record printed for it reads as a "
           "registered domain.")
EX_OLD = '{"type":"send_error","message":"Domain not found in database"}'
EX_NEW = '{"type":"send_error","message":"No match for \\"example.invalid\\""}'
REC_OLD = "Send a WHOIS record as standard `Key: value` lines."
REC_NEW = ("Send the WHOIS record of a domain that has one, as standard `Key: value` lines; for a "
           "query with no match use send_error.")
for s in (ERR_OLD, EX_OLD, REC_OLD):
    assert s in src, s


def r(t, *pairs):
    for a, b in pairs:
        t = t.replace(a, b)
    return t


V = {
    "base": src,
    "err": r(src, (ERR_OLD, ERR_NEW)),
    "err_ex": r(src, (ERR_OLD, ERR_NEW), (EX_OLD, EX_NEW)),
    "err_rec": r(src, (ERR_OLD, ERR_NEW), (REC_OLD, REC_NEW)),
    "all": r(src, (ERR_OLD, ERR_NEW), (EX_OLD, EX_NEW), (REC_OLD, REC_NEW)),
}
for k, v in V.items():
    open(f"{out}/{k}.txt", "w").write(v)
print(list(V))
