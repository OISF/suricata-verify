#! /bin/sh

run() {
    if ! ./src/suricata -T -c ${TEST_DIR}/suricata.yaml -vvv \
	 --set default-rule-path="${TEST_DIR}"; then
	exit 1
    fi
}

run

exit 0
