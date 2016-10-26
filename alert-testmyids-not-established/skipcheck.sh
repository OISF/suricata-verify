#! /bin/sh

strings ./src/suricata | grep -q 'not_established'
