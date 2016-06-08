#! /bin/sh

set -e

prefix=$(dirname $0)
tests=$(find ${prefix}/* -maxdepth 0 -type d)

export ASAN_OPTIONS="detect_leaks=${DETECT_LEAKS:=1},disable_core=1"
export LSAN_OPTIONS="suppressions=qa/lsan.suppress"

check() {
    dir="$1"
    for filename in $(find ${dir}/expected/ -type f); do
	echo -n "===> $(basename $1): checking $(basename ${filename}): "
	if ! cmp -s ${dir}/expected/$(basename ${filename}) \
	     ${dir}/output/$(basename ${filename}); then
	    echo "FAIL"
	    return 1
	fi
	echo "OK"
    done
}

verify() {
    name="$(basename $1)"
    echo "===> ${name}"
    dir=${prefix}/${name}
    if [ ! -e ${dir} ]; then
	echo "error: test ${name} does not exist"
	exit 1
    fi

    # Cleanup and prep.
    rm -rf ${dir}/output
    mkdir -p ${dir}/output

    set +e
    ./src/suricata -c ${dir}/suricata.yaml \
		   -r ${dir}/input.pcap \
		   -k none \
		   -S /dev/null \
		   --runmode=single \
		   -l ${dir}/output \
		   > ${dir}/output/stdout \
		   2> ${dir}/output/stderr
    if [ $? -ne 0 ]; then
	echo "***> ${name}: FAIL: non-zero exit (see: $1/output/stderr)."
	exit 1
    else
	if check ${dir}; then
	    echo "===> ${name}: PASS"
	else
	    echo "***> ${name}: FAIL"
	    exit 1
	fi
    fi
    set -e
}

for t in ${tests}; do
    if [ "$1" = "" ]; then
	match=yes
    elif echo ${t} | grep -q "$1"; then
	match=yes
    else
	match=no
    fi
    test "${match}" = "yes" && verify $t
done

