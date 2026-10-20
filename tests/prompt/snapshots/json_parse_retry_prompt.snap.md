# ❌ Error: Invalid Response Format

**Parse error:** expected `,` or `}` at line 3 column 5

## What Went Wrong

Your response was not one JSON object of the required shape. This usually happens when:
- You included explanatory text before or after the JSON
- You wrapped the JSON in markdown code blocks
- The JSON syntax is incorrect (missing quotes, commas, brackets, etc.)
- You returned valid JSON of another shape, or several objects instead of one

## Required Format

One JSON object, optionally preceded by a `<reasoning>…</reasoning>` block, and nothing else:

```
{"actions": [{"type": "<an action from the Available Actions list>", "param": "value"}]}
```

- Put every action you want performed, in order, into that one `actions` array
- `{"actions": []}` means "do nothing now"
- Use a `tools` key only if the prompt above lists tools
- No markdown formatting

---

**Please retry:** Respond to the original request using the correct JSON format. Nothing from the rejected response was executed.