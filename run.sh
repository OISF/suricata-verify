#! /bin/sh

set -e

prefix=$(dirname $0)

# Find all the tests.
tests=$(find ${prefix}/* -type f -name input.pcap -exec dirname {} \;)

if [ -e ./src/suricata ]; then
    SURICATA=./src/suricata
else
    SURICATA=suricata
fi

export ASAN_OPTIONS="detect_leaks=${DETECT_LEAKS:=1},disable_core=1"
export LSAN_OPTIONS="suppressions=qa/lsan.suppress"

RUNMODE=${RUNMODE:=single}

check() {
    dir="$1"

    if ! test -e ${dir}/expected; then
	echo "FAIL: expected directory does not exist."
	return 1
    fi

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

    args=""

    if [ -e ${dir}/suricata.yaml ]; then
	args="${args} -c ${dir}/suricata.yaml"
    else
	args="${args} -c ./suricata.yaml"
    fi

    if [ -e ${dir}/test.rules ]; then
	args="${args} -S ${dir}/test.rules"
    fi

    set +e
    ${SURICATA} ${args} \
        -r ${dir}/input.pcap \
	-k none \
	--runmode=${RUNMODE} \
	-l ${dir}/output \
	--set "classification-file=${dir}/../etc/classification.config" \
	--set "reference-config-file=${dir}/../etc/reference.config" \
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

