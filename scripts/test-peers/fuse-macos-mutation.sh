#!/bin/sh
# Mutation checks for the FUSE server's macOS (FUSE-T) backend, run by the fuse-macos pair job:
# break one mechanism on purpose, run the test that exists to catch it, and require that test to
# FAIL. The source is restored with `git checkout` whatever happens.
#
# These mount through FUSE-T, so they run only on CI's throwaway macOS VM (a FUSE-T mount is an
# NFS mount, and Apple's NFS client can panic the host: FUSE-T issue #109, Apple FB23527406).
# The startup refusal's mutation needs no mount and is checked locally (see the FUSE AGENTS.md).
#
# Usage: sh scripts/test-peers/fuse-macos-mutation.sh <mutation> [--informational]
#   no-unmount-on-stop  Mount's Drop does nothing (control socket and relay kept, no unmount):
#                       the busy-stop test must fail.
#   no-watchdog         spawn_watchdog never starts the watchdog: the killed-daemon test fails
#                       unless FUSE-T's own cleanup on its stream closing is enough on its own,
#                       which is why the job runs this one --informational.
#   refusal-ignored     a model refusal is applied as an allow: the tools test must fail.
#   fail-open           a failed or late decision is applied as an allow: the slow-model test
#                       must fail.
set -eu
name=${1:?name a mutation}
mode=${2:-}
case "$name" in
no-unmount-on-stop)
    file=src/server/fuse/macos.rs
    filter=server::fuse::macos_bounds_test::stop_unmounts_even_while_the_mount_is_busy_on_macos
    perl -0pi -e 's/(impl Drop for Mount \{\n    fn drop\(&mut self\) \{\n)/$1        \/* MUTATION *\/ if let Some(m) = self.monitor.take() { std::mem::forget(m); } if let Some(r) = self.relay.take() { std::mem::forget(r); } if true { return; }\n/' "$file"
    ;;
no-watchdog)
    file=src/server/fuse/macos.rs
    filter=server::fuse::macos_bounds_test::a_killed_daemon_leaves_no_mount_behind_on_macos
    perl -0pi -e 's/(fn spawn_watchdog\(mount_point: &Path\) -> std::io::Result<Child> \{\n)/$1    \/* MUTATION *\/ if true { return Err(std::io::Error::other("mutation")); }\n/' "$file"
    ;;
refusal-ignored)
    file=src/server/fuse/mod.rs
    filter=server::fuse::macos_tools_test
    perl -pi -e 's/Ok\(a\) if a\["type"\] == actions::ALLOW => Ok\(\(\)\),/Ok(_) => Ok(()), \/* MUTATION *\//' "$file"
    ;;
fail-open)
    file=src/server/fuse/mod.rs
    filter=server::fuse::macos_bounds_test::a_slow_model_is_eio_at_the_deadline_on_macos
    perl -0pi -e 's/(&format!\("\{\}; answered \{\}", f\.detail\(\), tree::errno_name\(f\.errno\(\)\)\),\n                \);\n                )Err\(f\.errno\(\)\)/${1}Ok(()) \/* MUTATION *\//' "$file"
    ;;
*)
    echo "unknown mutation: $name" >&2
    exit 2
    ;;
esac
trap 'git checkout -- "$file"' EXIT
if ! grep -q 'MUTATION' "$file"; then
    echo "::error::the $name mutation did not apply to $file; its anchor text has changed"
    exit 1
fi
log="${RUNNER_TEMP:-/tmp}/fuse-macos-mutation-$name.log"
set +e
cargo test --locked --no-default-features --test server -- "$filter" --test-threads=1 \
    > "$log" 2>&1
status=$?
set -e
grep -E '^test |test result' "$log" || true
if [ "$status" -eq 0 ]; then
    if [ "$mode" = "--informational" ]; then
        echo "mutation $name SURVIVED (informational): the test passed with it applied"
        exit 0
    fi
    echo "::error::mutation $name survived: $filter passed with it applied"
    exit 1
fi
if ! grep -q 'test result: FAILED' "$log"; then
    echo "::error::mutation $name: the test binary did not run to a result (build failure?)"
    tail -40 "$log"
    exit 1
fi
echo "mutation $name KILLED: $filter failed with it applied"
