#! /bin/sh

set -e

prefix=$(dirname $0)
tests=$(find ${prefix}/* -maxdepth 0 -type d)

# Disable leak checks.
export ASAN_OPTIONS="detect_leaks=0"

check() {
    dir="$1"
    for filename in $(find ${dir}/expected/ -type f); do
	echo "===> $(basename $1): checking $(basename ${filename})"
	if ! cmp ${dir}/expected/$(basename ${filename}) \
	     ${dir}/output/$(basename ${filename}); then
	    return 1
	fi
    done
}

verify() {
    name="$1"
    echo "===> $(basename ${name})"
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
		   #> ${dir}/output/stdout \
		   #2> ${dir}/output/stderr
    if [ $? -ne 0 ]; then
	echo "***> $(basename ${name}) FAIL: non-zero exit."
    else
	if check ${dir}; then
	    echo "===> $(basename ${name}): PASS"
	else
	    echo "***> $(basename ${name}): FAIL"
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

