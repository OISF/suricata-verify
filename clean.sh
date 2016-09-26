#! /bin/sh

prefix=$(dirname $0)

find "${prefix}" -type d -name output -print0 | xargs -0 rm -rf
find "${prefix}" -name \*~ -print0 | xargs -0 rm -f
