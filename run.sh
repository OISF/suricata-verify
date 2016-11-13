#! /bin/sh

set -e

prefix=$(dirname $0)

# Setting force to yes with "-f" or "--force" will force tests that
# would otherwise be skipped.
force=no

# If not verbose, output will be redirected to files.
stdout=
stderr=

for arg in $@; do
    case "${arg}" in
	-v|--verbose)
	    stdout=/dev/stdout
	    stderr=/dev/stderr
	    shift
	    ;;
	-f|--force)
	    force=yes
	    shift
	    ;;
	-)
	    echo "error: unknown argument: ${arg}"
	    exit 1
	    ;;
    esac
done

# The remaining args are the patterns to test.
patterns="$@"

# Find all non-private tests.
tests=$(cd ${prefix} && find * -maxdepth 0 -type d | grep -v '^private$')

# And the private tests.
if [ -e "${prefix}/private" ]; then
    private=$(cd ${prefix} && find private/* -maxdepth 0 -type d)
    tests="${tests} ${private}"
fi

export ASAN_OPTIONS="detect_leaks=${DETECT_LEAKS:=1},disable_core=1"
export LSAN_OPTIONS="suppressions=qa/lsan.suppress"

run_test() {
    t="$1"
    tdir="${prefix}/${t}"

    logdir="${tdir}/output"

    pcap=$(find "${tdir}" -name \*.pcap)
    if [ "${pcap}" = "" ]; then
	echo "error: no pcaps exists"
	exit 1
    fi
    if [ $(echo "${pcap}" | wc -l) -gt 1 ]; then
	echo "error: more than one pcap exists"
	exit 1
    fi

    args="-vvv -l ${logdir} -r ${pcap}"

    # If "ips" exists in the test name, then simulate ips.
    if echo "${tname}" | grep -q "ips"; then
    	args="${args} --simulate-ips"
    fi

    if [ -e "${tdir}/suricata.yaml" ]; then
	args="${args} -c ${tdir}/suricata.yaml"
    else
	args="${args} -c ./suricata.yaml"
    fi

    # If test specific rules are not provided then use /dev/null to
    # avoid loading any.
    if [ -e "${tdir}/test.rules" ]; then
	args="${args} -S ${tdir}/test.rules"
    else
	args="${args} -S /dev/null"
    fi

    # If stderr and stdout are not set, redirect the outputs to a file.
    if [ "${stderr}" = "" ]; then
	_stderr="${logdir}/stderr"
    else
	_stderr="${stderr}"
    fi
    if [ "${stdout}" = "" ]; then
	_stdout="${logdir}/stdout"
    else
	_stdout="${stdout}"
    fi

    if [ -e "${tdir}/vars.sh" ]; then
	. "${tdir}/vars.sh"

	if [ "${SIMULATE_IPS}" = "yes" ]; then
	    args="${args} --simulate-ips"
	fi

	if [ "${RUNMODE}" != "" ]; then
	    args="${args} --runmode=${RUNMODE}"
	fi
    fi
    
    # Cleanup existing output directory.
    rm -rf "${logdir}"
    mkdir -p "${logdir}"

    args="${args} --set classification-file=./classification.config"
    args="${args} --set reference-config-file=./reference.config"

    ./src/suricata --init-errors-fatal ${args} \
		   > ${_stdout} 2> ${_stderr}
    return "$?"
}

# Check the name of the test against the patterns past on the command
# line to determine if the test should run. No patterns means run all
# tests.
check_patterns() {
    tname="$1"

    if [ "${patterns}" = "" ]; then
	return 0
    fi

    for pattern in ${patterns}; do
	if echo "${tname}" | grep -q "${pattern}"; then
	    return 0
	fi
    done

    return 1
}

# Check if a test should be skipped.
check_skip() {
    t="$1"
    tdir="${prefix}/${t}"

    if [ -e "${tdir}/skip" ]; then
	return 0
    fi

    if [ -e "${tdir}/skipcheck.sh" ]; then
	if "${tdir}/skipcheck.sh"; then
	    return 0
	fi
    fi

    return 1
}

# Generic verification script. For any file in the expected directory,
# a comparison is done with the actual output.
generic_verify() {
    if [ ! -e "expected" ]; then
	echo "error: test does not have a directory of expected output"
	exit 1
    fi
    for filename in $(find expected/ -type f); do
	if ! cmp -s ${filename} output/$(basename ${filename}); then
	    echo "FAIL: output/$(basename ${filename})"
	    exit 1
	fi
    done
}

# Verify the output of Suricata. If a test doesn't provide its own
# verification script, then the generic file compare will be
# performed.
verify() {
    t="$1"

    (
	cd ${prefix}/${t}
	
	if [ -e "verify.sh" ]; then
	    if ! ./verify.sh; then
		exit 1
	    fi
	else
	    if ! generic_verify; then
		exit 1
	    fi
	fi
    )
    return $?
}

# Run Suricata and verify the output.
run_and_verify() {
    t="${1}"
    tdir="${prefix}/${t}"

    # If test has its own run script, just use that.
    if [ -e "${tdir}/run.sh" ]; then
	if ! "${tdir}/run.sh"; then
	    echo "===> ${t}: FAIL"
	    return 1
	fi
	echo "===> ${t}: OK"
	return 0
    fi
    
    if ! (run_test "${t}"); then
	echo "===> ${t}: FAIL with non-zero exit (see ${tdir}/output/stderr)"
	return 1
    fi
    if ! (verify "${t}"); then
	echo "===> ${t}: FAIL with verification error"
	return 1
    fi
    echo "===> ${t}: OK"
}

for t in ${tests}; do

    # These are not tests, but helper directories.
    if [ "${t}" = "etc" ]; then
	continue
    fi

    if check_patterns ${t}; then
	if test "${force}" = "no" && check_skip "${t}"; then
	    echo "===> ${t}: SKIPPED"
	    continue
	fi
	echo "===> Running ${t}."
	if ! (run_and_verify "${t}"); then
	    exit 1
	fi
    fi
done
