#! /bin/sh

run() {
    if ! ${SRCDIR}/src/suricata -T -c ${TEST_DIR}/suricata.yaml -vvv \
	 -l ${TEST_DIR}/output --set default-rule-path="${TEST_DIR}"; then
	exit 1
    fi
}

mkdir -p ${TEST_DIR}/output
run

exit 0
