#! /bin/sh

run() {
    if ! ./src/suricata -T -c ${TEST_DIR}/suricata.yaml -vvv \
	 -l ${TEST_DIR}/output --set default-rule-path="${TEST_DIR}"; then
	exit 1
    fi
}

mkdir -p ${TEST_DIR}/output
run > ${TEST_DIR}/output/stdout 2> ${TEST_DIR}/output/stderr

exit 0
