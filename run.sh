#! /bin/sh
#
# Just a wrapper for run.sh now.

set -e

prefix=$(dirname $0)
exec $prefix/run.py $@
