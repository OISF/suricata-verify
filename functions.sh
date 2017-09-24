jq_count() {
    cat "$1" | jq -c "$2" | wc -l | xargs
}

assert_eq() {
    if ! test "$1" = "$2"; then
	echo "fail: expected $1; got $2: $3"
	exit 1
    fi
}
