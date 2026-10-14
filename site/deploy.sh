#!/bin/bash
# Publish netget.net — the static landing page in this directory — to S3 + CloudFront.
#
#   S3 bucket:    netget.net (us-east-1, private; CloudFront reads it through an OAC)
#   Distribution: E2LPP647KD7BN2  (netget.net, *.netget.net)
#   Certificate:  ACM us-east-1, DNS-validated
#   DNS:          Porkbun — apex ALIAS + www CNAME to the CloudFront domain
#
# The files here are the site, plus demo/pkg/, which ./web/build.sh writes (the
# NetGet-in-the-browser bundle; gitignored) and which must exist before this runs.
#
# Caching is by URL, not by lifetime. css/, js/ and demo/ are published under
# v/<hash>/, where <hash> is taken from their contents, and are immutable there;
# HTML pages are rewritten to point at that prefix and are never cached. A browser
# therefore always gets a set of files from one deploy. Publishing them at fixed
# URLs with a week's max-age let a browser pair a fresh demo.js and netget_web.js
# with the previous deploy's .wasm, which fails at load with
# "wasm.<export> is not a function".
#
# Older v/<hash>/ prefixes stay in the bucket, so a page already open keeps
# loading its own modules; only the newest KEEP_VERSIONS are kept.
#
# DRY_RUN=1 stages the site and prints what would be uploaded without changing
# anything; STAGE_DIR=<dir> keeps the staged copy there for inspection.

set -euo pipefail

export AWS_PROFILE=smotana

BUCKET=netget.net
DISTRIBUTION_ID=E2LPP647KD7BN2
KEEP_VERSIONS=5
VERSIONED_DIRS=(css js demo)
HTML_PAGES=(index.html demo.html)

cd "$(dirname "$0")"

python3 ../scripts/site_protocol_stacks.py

if [ ! -f demo/pkg/netget_web_bg.wasm ]; then
  echo "demo/pkg/netget_web_bg.wasm is missing: run ./web/build.sh first" >&2
  exit 1
fi

DRYRUN=()
if [ "${DRY_RUN:-}" = 1 ]; then DRYRUN=(--dryrun); fi

version=$(find "${VERSIONED_DIRS[@]}" -type f ! -name '.DS_Store' ! -name '*.md' -print0 \
  | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | cut -c1-12)

stage=${STAGE_DIR:-$(mktemp -d)}
mkdir -p "$stage/v/$version"
cp "${HTML_PAGES[@]}" favicon.svg "$stage/"
cp -R "${VERSIONED_DIRS[@]}" "$stage/v/$version/"
find "$stage" \( -name '.DS_Store' -o -name '*.md' \) -delete

# Point each HTML page at the versioned prefix. Every reference to these directories in
# the pages is an attribute value starting with the directory name; the modules they
# load (demo.js -> ../demo/pkg/, composer.js) are relative and move with them.
for page in "${HTML_PAGES[@]}"; do
  sed -E -i.bak \
    -e "s#(href|src)=\"(css|js|demo)/#\\1=\"v/$version/\\2/#g" \
    "$stage/$page"
  rm "$stage/$page.bak"
  if grep -nE '(href|src)="(css|js|demo)/' "$stage/$page"; then
    echo "$page still references an unversioned asset (above)" >&2
    exit 1
  fi
done
echo "version: $version (staged in $stage)"

set -x

# 1. The versioned assets, immutable. Uploaded before index.html points at them.
aws s3 sync "$stage/v/$version" "s3://$BUCKET/v/$version/" ${DRYRUN[@]+"${DRYRUN[@]}"} \
  --exclude 'demo/pkg/netget_web_bg.wasm' \
  --cache-control "public, max-age=31536000, immutable"
# The AWS CLI guesses content types from the extension and does not know .wasm;
# without application/wasm the browser falls back to a slower, non-streaming compile.
aws s3 cp "$stage/v/$version/demo/pkg/netget_web_bg.wasm" \
  "s3://$BUCKET/v/$version/demo/pkg/netget_web_bg.wasm" ${DRYRUN[@]+"${DRYRUN[@]}"} \
  --content-type application/wasm --cache-control "public, max-age=31536000, immutable"

# 2. The unversioned files. --delete also removes the fixed-URL css/, js/ and demo/
#    earlier deploys published; v/ is managed below.
aws s3 sync "$stage" "s3://$BUCKET/" --delete ${DRYRUN[@]+"${DRYRUN[@]}"} \
  --exclude 'v/*' --exclude '*.html' \
  --cache-control "max-age=86400"
for page in "${HTML_PAGES[@]}"; do
  aws s3 cp "$stage/$page" "s3://$BUCKET/$page" ${DRYRUN[@]+"${DRYRUN[@]}"} \
    --cache-control "no-cache"
done

set +x

# 3. Keep the newest KEEP_VERSIONS prefixes (by upload time of their index-referenced
#    wasm), and always the one just published.
old_versions=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix v/ \
    --query "Contents[?ends_with(Key, 'netget_web_bg.wasm')].[LastModified, Key]" --output text \
  | sort -r | awk '{split($2, p, "/"); print p[2]}' | grep -vx "$version" \
  | tail -n +"$KEEP_VERSIONS" || true)
for old in $old_versions; do
  aws s3 rm "s3://$BUCKET/v/$old/" --recursive ${DRYRUN[@]+"${DRYRUN[@]}"}
done

if [ ${#DRYRUN[@]} -eq 0 ]; then
  aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" \
    --paths '/' '/index.html' '/demo.html' '/favicon.svg'
fi

if [ -z "${STAGE_DIR:-}" ]; then rm -rf "$stage"; fi
