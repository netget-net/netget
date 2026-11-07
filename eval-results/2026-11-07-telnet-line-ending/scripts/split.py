import re
txt = open('/tmp/telnet-line/replays-f.txt').read()
parts = re.split(r'(TALLY[^\n]*\n)', txt)
for i in range(0, len(parts) - 1, 2):
    body, t = parts[i], parts[i + 1]
    if 'f_F2.py' in t and '00002' in t:
        a = {'LINE': 0, 'TEXT': 0, 'other': 0}
        b = dict(a)
        for m in re.finditer(r'seed +(\d+) (\w+)', body):
            s, c = int(m.group(1)), m.group(2)
            (a if s <= 20 else b)[c] += 1
        print(a, b)
