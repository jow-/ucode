#!/usr/bin/env bash

line='........................................'

extract_section() {
	local file=$1
	local tag=$2

	sed -ne '/^-- '"$tag"' --$/ { :n; n; /^-- End --$/b; p; b n }' "$file"
}

run_test() {
	local file=$1
	local name=${file##*/}
	local res

	printf "%s %s " "$name" "${line:${#name}}"

	extract_section "$file" "Expect stdout" >"/tmp/$$.expout"
	extract_section "$file" "Expect stderr" >"/tmp/$$.experr"
	extract_section "$file" "Testcase" >"/tmp/$$.in"

	./utpl -i "/tmp/$$.in" >"/tmp/$$.out" 2>"/tmp/$$.err"

	local rc=$?

	if ! cmp -s "/tmp/$$.err" "/tmp/$$.experr"; then
		printf "FAILED:\n"
		diff -u --color=always --label="Expected stderr" --label="Resulting stderr" "/tmp/$$.experr" "/tmp/$$.err"
		printf -- "---\n"
		res=1
	elif ! cmp -s "/tmp/$$.out" "/tmp/$$.expout"; then
		printf "FAILED:\n"
		diff -u --color=always --label="Expected stdout" --label="Resulting stdout" "/tmp/$$.expout" "/tmp/$$.out"
		printf -- "---\n"
		res=1
	#elif [ "$rc" != 0 ]; then
	#	local err="$(cat "/tmp/$$.err")"
	#	printf "FAILED:\n"
	#	printf "Terminated with exit code %d:\n%s\n---\n" $rc "${err:-(no error output)}"
	#	res=1
	else
		printf "OK\n"
		res=0
	fi

	rm -f "/tmp/$$.in" "/tmp/$$.out" "/tmp/$$.err" "/tmp/$$.expout" "/tmp/$$.experr"

	return $res
}


n_tests=0
n_fails=0

for catdir in tests/[0-9][0-9]_*; do
	[ -d "$catdir" ] || continue

	printf "\n##\n## Running %s tests\n##\n\n" "${catdir##*/[0-9][0-9]_}"

	for testfile in "$catdir/"[0-9][0-9]_*; do
		[ -f "$testfile" ] || continue

		n_tests=$((n_tests + 1))
		run_test "$testfile" || n_fails=$((n_fails + 1))
	done
done

printf "\nRan %d tests, %d okay, %d failures\n" $n_tests $((n_tests - n_fails)) $n_fails
