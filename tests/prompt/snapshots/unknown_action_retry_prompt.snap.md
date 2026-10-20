# ❌ Error: Unknown Action(s)

**The following action(s) do not exist:**
- `send_magic_packet`
- `do_something`

## What Went Wrong

You used action name(s) that are not in the Available Actions list. This is NOT allowed.

**CRITICAL RULES:**
1. You can ONLY use actions explicitly listed in the "Available Actions" section
2. Do NOT invent, guess, or hallucinate action names
3. Pick the closest match from the Valid Actions below; if none fits, return `{"actions": []}`

## Valid Actions

`open_server`, `close_server`, `show_message`

---

**Please retry:** Use ONLY names from the Available Actions list. Return the complete corrected response; no action from the rejected response has been executed.