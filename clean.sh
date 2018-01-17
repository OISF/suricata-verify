#! /bin/sh
#
# Remove output directory from all tests.

set -e

prefix=$(dirname $0)

if ! test -e "${prefix}/run.py" -a -d "${prefix}/tests"; then
    echo "error: this doesn't look like a suricata-verify directory."
    exit 1
fi

# Remove the output directories.
find "${prefix}/tests" -type d -name output -print0 | xargs -0 rm -rf

# Remove emacs backup files.
find "${prefix}" -name \*~ -print0 | xargs -0 rm -f
