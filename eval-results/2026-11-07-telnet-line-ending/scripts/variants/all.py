"""Prompt variants for the telnet client's line/no-line-ending choice.

Each is a function master_prompt -> variant_prompt. `replay.py` loads one by name through
`/tmp/telnet-line/variants/v_<name>.py` shims written by `mkshims.py`.
"""
import sys
sys.path.insert(0, '/tmp/telnet-line/variants')
from common import CMD_BLOCK, TEXT_BLOCK, EVENT_DESC, sub

LINE_DESC = ("Send one line to the Telnet server: an answer, a reply, a login name or a command. "
             "The line ending (CRLF) is added for you. This is the normal way to answer anything "
             "the server says.")


def block(name, desc, params, example):
    ps = "\n".join(f"- {p}" for p in params)
    ex = ",\n".join(f'  "{k}": "{v}"' for k, v in example)
    return f'''{name}

{desc}

Parameters:
{ps}

Example:
```json
{{
{ex}
}}
```
'''


CMD_B = block("send_command", LINE_DESC,
              ["command: string (required) - The line to send, without a line ending"],
              [("type", "send_command"), ("command", "ls -la")])
TEXT_B = block("send_text",
               "Send text with NO line ending. A line-based server does not see it until a line "
               "ending follows, so do not use it to answer a question or a prompt; use "
               "send_command. Only for a server that reads single keys or waits for more on the "
               "same line.",
               ["text: string (required) - The characters to send, with nothing added"],
               [("type", "send_text"), ("text", "y")])
TEXT_C = TEXT_B.replace("use send_command", "use send_line")
LINE_C = block("send_line", LINE_DESC,
               ["line: string (required) - The line to send, without a line ending"],
               [("type", "send_line"), ("line", "ls -la")])
LINE_ENDING = ('line_ending: string (optional) - "crlf" (the default) or "none"; "none" sends the '
               'text with nothing after it, only for a server that reads single keys or waits for '
               'more on the same line')
LINE_D = block("send_line", LINE_DESC,
               ["line: string (required) - The line to send, without a line ending", LINE_ENDING],
               [("type", "send_line"), ("line", "ls -la")])
CMD_D2 = block("send_command", LINE_DESC,
               ["command: string (required) - The line to send, without a line ending",
                LINE_ENDING],
               [("type", "send_command"), ("command", "ls -la")])


def ev(text):
    return text + " or wait_for_more if this looks like part of a prompt you have not finished reading."


def hist_rename(p):
    return p.replace('you did: send_command {"command":', 'you did: send_line {"line":')


VARIANTS = {
    # Wording only: same names, line action described as the default answer.
    "B_wording": lambda p: sub(sub(sub(p, CMD_BLOCK, CMD_B), TEXT_BLOCK, TEXT_B), EVENT_DESC,
                               ev("Reply with send_command (one line, the usual answer),")),
    # Only the event description changed.
    "B2_event": lambda p: sub(p, EVENT_DESC, ev("Reply with send_command (one line, the usual answer),")),
    # send_command renamed send_line {line}; send_text kept with the new wording.
    "C_rename": lambda p: hist_rename(sub(sub(sub(p, CMD_BLOCK, LINE_C), TEXT_BLOCK, TEXT_C),
                                          EVENT_DESC, ev("Reply with send_line (one line, the usual answer),"))),
    # One offered send action, send_line {line, line_ending?}.
    "D_one": lambda p: hist_rename(sub(sub(sub(p, CMD_BLOCK, LINE_D), TEXT_BLOCK, ""), EVENT_DESC,
                                       ev("Reply with send_line,"))),
    # One offered send action under the old name.
    "D2_one_keepname": lambda p: sub(sub(sub(p, CMD_BLOCK, CMD_D2), TEXT_BLOCK, ""), EVENT_DESC,
                                     ev("Reply with send_command,")),
    # send_text simply not offered.
    "E_drop": lambda p: sub(sub(p, TEXT_BLOCK, ""), EVENT_DESC, ev("Reply with send_command,")),
}

if __name__ == "__main__":
    base = open('/tmp/telnet-line/q1-prompt-master.txt').read()
    for name, f in VARIANTS.items():
        f(base)
        with open(f'/tmp/telnet-line/variants/v_{name}.py', 'w') as out:
            out.write("import sys\nsys.path.insert(0, '/tmp/telnet-line/variants')\n"
                      f"from all import VARIANTS\ntransform = VARIANTS[{name!r}]\n")
        print(name, "ok")
