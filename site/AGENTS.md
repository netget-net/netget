# netget.net — the landing page

`index.html` is the landing page; `demo.html` is the standalone interactive demo. Only the
demo loads xterm.js and the WebAssembly runtime. The Telnet terminal takes focus once, when it
is created on load, and only if nothing else on the page has focus; after that focus belongs to
the visitor: connection, incoming requests, and sending a composer reply must not focus a terminal.

The landing page shows a left-to-right network diagram: Client → NetGet → LLM / Script /
Manual. HTML and CSS keep the diagram visible without JavaScript and preserve the direction
on narrow screens. The hub shows a few protocol examples and links its count to the full
protocol table. Check that count against `python3 scripts/site_protocol_stacks.py --check`
when updating the diagram. The generated `js/protocol-stacks.js` still comes from both
registries and their `stack_name()` declarations, including platform-gated protocols;
deployment refreshes it before hashing the assets. The older `js/protocol-landscape.js`
stack renderer is no longer loaded by the landing page.
Without JavaScript, the fixed stacks, protocol links, examples and install commands remain
available; Copy/theme buttons are hidden until their handlers are installed. The demo's
`noscript` preview uses actual desktop/mobile screenshots in `demo/preview*.png`.

`css/`, `js/`, `favicon.svg`, and `demo/pkg/` — the NetGet-in-the-browser
bundle, which is the one thing here that is built: `./web/build.sh` from the repository root
writes it (gitignored), `web/README.md` explains it, and `./deploy.sh` refuses to run
without it. `./deploy.sh` is the whole publishing pipeline.

`js/demo.js` is the demo page's script and `js/composer.js` the "Respond on behalf of LLM"
answer form it opens for each model request (a single prefilled field with Advanced for the
full form built from the request's offered `actions`; see `web/README.md`). `composer.js`'s pure half is imported by `web/test/smoke.mjs`, so keep
DOM access out of module top level. `js/thinking.js` splits a thinking model's streamed
`<think>` block from its answer for the LLM panel; it is pure and `smoke.mjs` imports it too.

What is in this directory is public, with one exception: `deploy.sh` and every `*.md` —
this file included — are excluded from the sync, because this one names infrastructure IDs.
The internal planning documents under `docs/` are not part of the site at all. Adding a
non-markdown file here publishes it, so check before you do.

## Hosting

S3 + CloudFront in AWS account `750984813907` (`AWS_PROFILE=smotana`), the same shape as
the maintainer's other static sites (`zisk.ca`, `ollisten.com`, `matusnomin.com`):

| Piece | Value |
|---|---|
| S3 bucket | `netget.net`, us-east-1, **private** — public access fully blocked, no website config |
| Distribution | `E2LPP647KD7BN2` → `d3m64zfgzk3tzs.cloudfront.net` |
| Aliases | `netget.net`, `*.netget.net` |
| Origin access | OAC `E2IVTMAHEQBL57` (sigv4, always); the bucket policy allows only `cloudfront.amazonaws.com` for this distribution |
| Certificate | ACM us-east-1 `e514d390-7946-4243-8a4d-4e3374aa68de`, DNS-validated, auto-renews |
| Cache policy | Managed-CachingOptimized (`658327ea-…`), compression on |
| Errors | 403 → `/index.html` with status 200 (S3 returns 403, not 404, for a missing key when the OAC has no `ListBucket`) |

The bucket is reachable **only** through CloudFront. A direct
`https://netget.net.s3.amazonaws.com/index.html` returns 403, and that is correct.

## DNS

At **Porkbun** (the registrar is also the nameserver — there is no Route 53 zone for this
domain, and there should not be one):

| Record | Type | Value |
|---|---|---|
| `netget.net` | ALIAS | `d3m64zfgzk3tzs.cloudfront.net` |
| `www.netget.net` | CNAME | `d3m64zfgzk3tzs.cloudfront.net` |
| `_fd521527ba3e64edae0b9e8c783a9628` | CNAME | ACM validation — **do not delete**, the certificate stops renewing without it |

Porkbun's ALIAS flattens at the edge, which is what lets the apex point at CloudFront.

To change DNS from a script: `source ~/bin/porkbun-env`, then POST to
`https://api.porkbun.com/api/json/v3/dns/…` with `apikey` + `secretapikey` in the JSON body.
The apex record's `name` is the empty string, not `@`. The domain must have API access
enabled in the Porkbun panel (Domain Management → netget.net → Details → API ACCESS);
netget.net was not opted in until September 2026.

## What this replaced

GitHub Pages served `docs/` at netget.net via `docs/CNAME`. That stopped being an option
when the repository went private — Pages on a private repository needs a paid plan, and the
site's own links to `github.com/netget-net/netget` are public-facing links into a private
repository regardless of where the page is hosted.

## Deploying

```bash
./deploy.sh
```

**Caching is by URL.** `css/`, `js/` and `demo/` are published under `v/<hash>/`, where
`<hash>` comes from their contents, with `max-age=31536000, immutable`; both `index.html` and
`demo.html` are rewritten to point at that prefix and go up with `no-cache`. So a browser always loads one
deploy's files together. Publishing them at fixed URLs with a week's `max-age` let a browser pair
a fresh `demo.js` and `netget_web.js` with the previous deploy's `.wasm`, which fails at load
with `wasm.<export> is not a function` — seen on 28 September 2026. Keep new assets inside one of
the versioned directories, or add the directory to `VERSIONED_DIRS`.

Order matters and the script keeps it: versioned assets first, then both HTML pages, then the
invalidation (`/`, `/index.html`, `/demo.html`, `/favicon.svg` — the versioned paths are new, so nothing needs
invalidating there). Old `v/<hash>/` prefixes stay so a page already open keeps loading its
modules; only the newest five are kept. The root sync uses `--delete` with `v/*` excluded, so a
file removed from this directory is removed from the bucket — except an excluded one, which
`--delete` also skips. Deleting `deploy.sh` or a `*.md` from the bucket is a manual
`aws s3 rm`.

`DRY_RUN=1 ./deploy.sh` stages everything and prints what would be uploaded or deleted, changing
nothing; `STAGE_DIR=<dir>` keeps the staged copy — serve it to test the exact layout that ships.

## Third-party scripts carry subresource integrity

`demo.html` loads xterm.js and its fit addon from jsdelivr with `integrity="sha384-…"` and
`crossorigin="anonymous"`: the browser refuses the file unless its hash matches the one
computed from the pinned, immutable version, so a CDN compromise or an interception on the
way fails the load rather than running someone else's script on netget.net (jsdelivr sends
`access-control-allow-origin: *`, which SRI needs). Bumping either version means
recomputing the hash — the comment above the tags has the command. WebLLM is a dynamic
`import()` from esm.run, which rebundles on the CDN, so no hash can describe it; the only
way to pin it is to self-host the bundle under `demo/`, which `deploy.sh` already versions
by content hash. Neither page ships a Content-Security-Policy yet: one would have to allow
`'wasm-unsafe-eval'`, the inline theme script, esm.run, Hugging Face model downloads and
blob workers, and a policy that is wrong breaks the demo silently, so it belongs with a
headless-Chromium run of `web/test/page_composer.py`, not in a text edit.
