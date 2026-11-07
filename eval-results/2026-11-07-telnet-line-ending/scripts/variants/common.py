"""Pieces of the master telnet-client prompt, and replacements for them."""

CMD_BLOCK = '''send_command

Send a text command to the Telnet server (a newline is appended)

Parameters:
- command: string (required) - The command text to send (newline will be appended)

Example:
```json
{
  "type": "send_command",
  "command": "ls -la"
}
```
'''

TEXT_BLOCK = '''send_text

Send raw text to the Telnet server, exactly as given and with no newline added. Use it where the server is waiting mid-line.

Parameters:
- text: string (required) - The text to send

Example:
```json
{
  "type": "send_text",
  "text": "yes"
}
```
'''

EVENT_DESC = ("Reply with send_command or send_text, or wait_for_more if this looks like part "
              "of a prompt you have not finished reading.")


def sub(prompt, old, new):
    assert old in prompt, old[:60]
    return prompt.replace(old, new)
