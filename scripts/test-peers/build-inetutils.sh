#!/bin/sh
# Build GNU inetutils 2.8's r-services: the clients rsh, rlogin and rexec (independent peers
# for the rsh, rlogin and rexec servers) and the daemons rshd, rlogind and rexecd (independent
# peers for the clients). Ubuntu stopped packaging all six; Homebrew's inetutils 2.8 bottle has
# them, under the same g-prefixed names this build uses (`brew install inetutils`), though the
# daemons need Linux root to be useful.
#
# The release tarball is checked against a pinned SHA-256 (the one Homebrew's formula pins).
# Only the six programs are built, without PAM or Kerberos, so rshd and rlogind check
# .rhosts/hosts.equiv with iruserok and rexecd checks the shadow file itself.
#
# Build dependencies (Ubuntu 24.04): build-essential libcrypt-dev
#
# Usage: sh scripts/test-peers/build-inetutils.sh /absolute/owned/directory
# Installs <dir>/install/bin/{grsh,grlogin,grexec} and
# <dir>/install/libexec/{grshd,grlogind,grexecd}, and prints both directories.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
version=2.8
sha256=57b3cf4f77555992881e5ba2a09a63b05aa2c56342a60ed4305b5f45938390b5
url="https://ftp.gnu.org/gnu/inetutils/inetutils-$version.tar.gz"
mkdir -p "$base"
tarball="$base/inetutils-$version.tar.gz"
if [ ! -f "$tarball" ]; then
    curl -fsSL -o "$tarball" "$url"
fi
if command -v sha256sum >/dev/null 2>&1; then
    echo "$sha256  $tarball" | sha256sum -c -
else
    echo "$sha256  $tarball" | shasum -a 256 -c -
fi
rm -rf "$base/src"
mkdir -p "$base/src"
tar -xzf "$tarball" -C "$base/src" --strip-components=1
prefix="$base/install"
cd "$base/src"
./configure --prefix="$prefix" --program-prefix=g \
    --disable-servers --disable-clients \
    --enable-rsh --enable-rlogin --enable-rexec \
    --enable-rshd --enable-rlogind --enable-rexecd \
    --disable-dependency-tracking >/dev/null
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null
# inetutils installs rsh and rlogin setuid root (`install -o root`), which only root can do. As
# an ordinary user with passwordless sudo (a CI runner) install through sudo and take the tree
# back; the tests run these clients as root anyway, since they bind reserved source ports.
if [ "$(id -u)" -ne 0 ] && sudo -n true 2>/dev/null; then
    sudo make install >/dev/null
    sudo chown -R "$(id -u):$(id -g)" "$prefix"
else
    make install >/dev/null
fi
for p in bin/grsh bin/grlogin bin/grexec libexec/grshd libexec/grlogind libexec/grexecd; do
    test -x "$prefix/$p" || { echo "inetutils did not install $p" >&2; exit 1; }
done
"$prefix/bin/grexec" --version | head -1
echo "INETUTILS_BIN=$prefix/bin"
echo "INETUTILS_LIBEXEC=$prefix/libexec"
