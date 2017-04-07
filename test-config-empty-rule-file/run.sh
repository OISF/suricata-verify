#! /bin/sh

run() {
    mkdir -p ${TEST_DIR}/output
    if ! ./src/suricata -T -c ${TEST_DIR}/suricata.yaml -vvv \
	 -l ${TEST_DIR}/output --set default-rule-path="${TEST_DIR}"; then
	exit 1
    fi
}

run

exit 0
