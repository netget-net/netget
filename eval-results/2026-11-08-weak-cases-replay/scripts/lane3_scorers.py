"""Scorers for lane3-replay.py. Each takes the executed action list, returns bool."""

MEMORY = {"set_memory", "append_memory", "set_connection_memory", "append_connection_memory",
          "append_to_log", "notify_operator", "show_message"}


def wire(acts):
    return [a for a in acts if a.get("type") not in MEMORY]


def dict_nomatch_strict(acts):
    """DEFINE of an unknown word answered 552: send_dict_error 552 or an empty definitions list."""
    w = wire(acts)
    if not w:
        return False
    a = w[0]
    if a.get("type") == "send_dict_error":
        return a.get("code") in (552, "552")
    if a.get("type") == "send_dict_definitions":
        return a.get("definitions") == []
    return False


def dict_nomatch_harness(acts):
    """What the harness accepts: dict(1) prints 'No definitions found' after 552 or 550."""
    w = wire(acts)
    if not w:
        return False
    a = w[0]
    if a.get("type") == "send_dict_error":
        return a.get("code") in (552, "552", 550, "550")
    if a.get("type") == "send_dict_definitions":
        return a.get("definitions") == []
    return False


def dict_define_glimmer(acts):
    """Regression: a known word is defined, mentioning moonlight."""
    w = wire(acts)
    if not w or w[0].get("type") != "send_dict_definitions":
        return False
    return "moonlight" in str(w[0].get("definitions", "")).lower()


def bolt_login_accept(acts):
    w = wire(acts)
    return bool(w) and w[0].get("type") == "accept_bolt_login"


def _bolt_records_ok(a, field, expected):
    """Executor-acceptable records for a single field, whose values equal expected (list)."""
    if a.get("type") != "send_bolt_records" or a.get("fields") != [field]:
        return False
    vals = []
    for r in a.get("records") or []:
        if isinstance(r, list) and len(r) == 1:
            vals.append(r[0])
        elif isinstance(r, dict) and list(r.keys()) == [field]:
            vals.append(r[field])
        else:
            return False
    return vals == expected


def bolt_count(acts):
    w = wire(acts)
    return bool(w) and _bolt_records_ok(w[0], "movies", [42])


def bolt_people(acts):
    w = wire(acts)
    return bool(w) and _bolt_records_ok(w[0], "name", ["Ada", "Grace", "Linus"])


def ftp_pass_230(acts):
    w = wire(acts)
    return bool(w) and w[0].get("type") == "send_ftp_response" and w[0].get("code") in (230, "230")


def docker_ps_ok(acts):
    """Both containers listed, eval-migrate exited with code 0, nothing the executor refuses
    for a blank 'created' is checked here: the scorer reports the model's shape only."""
    w = wire(acts)
    if not w or w[0].get("type") != "send_docker_containers":
        return False
    names = str(w[0].get("containers"))
    return "eval-api" in names and "eval-migrate" in names


def dict_showdb(acts):
    w = wire(acts)
    s = str(w[0]) if w else ""
    return bool(w) and w[0].get("type") == "send_dict_databases" and "Fantasy Lexicon" in s and "Technical Terms" in s


def docker_no_blank_created(acts):
    """True when no container carries a blank created or id (what master refused)."""
    w = wire(acts)
    if not w or w[0].get("type") != "send_docker_containers":
        return False
    for c in w[0].get("containers") or []:
        if isinstance(c, dict) and any(isinstance(c.get(k), str) and not c.get(k).strip() for k in ("created", "id")):
            return False
    return True


def prom_hist_ok(acts):
    """The latency histogram the executor accepts and the instruction describes."""
    w = wire(acts)
    if not w or w[0].get("type") != "send_metrics":
        return False
    for fam in w[0].get("metrics") or []:
        if not isinstance(fam, dict) or fam.get("type") != "histogram":
            continue
        buckets, count = {}, None
        for s in fam.get("samples") or []:
            if not isinstance(s, dict):
                return False
            le = (s.get("labels") or {}).get("le")
            suf = s.get("suffix", "")
            try:
                v = float(s.get("value"))
            except (TypeError, ValueError):
                return False
            if le is not None:
                buckets[float("inf") if le in ("+Inf", "Inf") else float(le)] = v
            elif suf == "_count":
                count = v
        if not buckets:
            return False
        vals = [buckets[k] for k in sorted(buckets)]
        if any(b < a for a, b in zip(vals, vals[1:])):
            return False
        inf = buckets.get(float("inf"))
        if inf is not None and count is not None and inf != count:
            return False
        total = count if count is not None else inf
        return buckets.get(0.1) == 30 and total == 40 and {0.1, 0.5, 1.0} <= set(buckets)
    return False
