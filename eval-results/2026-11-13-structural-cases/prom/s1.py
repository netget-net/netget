#!/usr/bin/env python3
"""Hand-made approximation of the branch's prometheus prompt, from master.txt."""
import json

p = open("/tmp/netget-r3-l4/work/prom/master.txt").read()
old_desc = ("Answer a scrape with this target's metrics. Give structured families; NetGet writes the "
            "exposition text, escapes it, appends _total to counters, sorts histogram buckets and adds "
            "the +Inf bucket and _count if you leave them out. An invalid name or a malformed histogram "
            "is refused and the scrape fails, so keep names to letters, digits, underscores and colons.")
new_desc = ("Answer a scrape with this target's metrics. Give structured families; NetGet writes the "
            "exposition text, escapes it, appends _total to counters, and builds a histogram's "
            "cumulative buckets, +Inf bucket and _count from how many observations fell in each bucket. "
            "An invalid name or a malformed histogram is refused and the scrape fails, so keep names to "
            "letters, digits, underscores and colons.")
old_param = ('"suffix": "_bucket"|"_sum"|"_count"|"_total"|"" , "timestamp_ms": optional integer}]}]. '
             'A histogram\'s _bucket samples carry an "le" label (upper bound, or "+Inf") and are '
             'cumulative; a summary\'s')
new_param = ('"suffix": "_sum"|"_count"|"_total"|"" , "timestamp_ms": optional integer}]}]. A histogram '
             'gives "bucket_counts" instead of samples: each bucket\'s upper bound mapped to how many '
             'observations fell in that bucket alone (above the previous bound), plus "count" (all '
             'observations; any beyond the bucket_counts lie above the largest bound) and "sum" (the '
             'observed values added up); NetGet adds the buckets up into the cumulative _bucket lines. '
             'Give "labels" beside them for a labelled histogram. A summary\'s')
old_ex = ('"samples":[{"suffix":"_bucket","labels":{"le":"0.1"},"value":900},{"suffix":"_bucket","labels":'
          '{"le":"0.5"},"value":1010},{"suffix":"_bucket","labels":{"le":"+Inf"},"value":1030},'
          '{"suffix":"_sum","value":81.4},{"suffix":"_count","value":1030}]}]}')
new_ex = '"bucket_counts":{"0.1":900,"0.5":110,"1":20},"count":1030,"sum":81.4}]}'
for o, n in ((old_desc, new_desc), (old_param, new_param), (old_ex, new_ex)):
    assert p.count(o) == 1, o[:60]
    p = p.replace(o, n)
open("/tmp/netget-r3-l4/work/prom/s1.txt", "w").write(p)
print("ok")
