#!/usr/bin/env bash

if greadlink -f . &>/dev/null; then
	readlink=greadlink
else
	readlink=readlink
fi

export LC_ALL=C

testdir=$(dirname "$0")
topdir=$($readlink -f "$testdir/../..")

line='........................................'
export ucode_bin=${UCODE_BIN:-"$topdir/ucode"}
export ucode_lib=${UCODE_LIB:-"$topdir"}

extract_sections() {
	local file=$1
	local dir=$2
	local count=0
	local tag line outfile

	while IFS= read -r line; do
		case "$line" in
			"-- Args --")
				tag="args"
				count=$((count + 1))
				outfile=$(printf "%s/%03d.args" "$dir" $count)
				printf "" > "$outfile"
			;;
			"-- Vars --")
				tag="vars"
				count=$((count + 1))
				outfile=$(printf "%s/%03d.vars" "$dir" $count)
				printf "" > "$outfile"
			;;
			"-- Testcase --")
				tag="test"
				count=$((count + 1))
				outfile=$(printf "%s/%03d.in" "$dir" $count)
				printf "" > "$outfile"
			;;
			"-- Expect stdout --"|"-- Expect stderr --"|"-- Expect exitcode --")
				tag="${line#-- Expect }"
				tag="${tag% --}"
				count=$((count + 1))
				outfile=$(printf "%s/%03d.%s" "$dir" $count "$tag")
				printf "" > "$outfile"
			;;
			"-- File "*" --")
				tag="file"
				outfile="${line#-- File }"
				outfile="$(echo "${outfile% --}" | xargs)"
				outfile="$dir/files$($readlink -m "/${outfile:-file}")"
				mkdir -p "$(dirname "$outfile")"
				printf "" > "$outfile"
			;;
			"-- End (no-eol) --")
				truncate -s -1 "$outfile"
				tag=""
				outfile=""
			;;
			"-- End --")
				tag=""
				outfile=""
			;;
			*)
				if [ -n "$tag" ]; then
					printf "%s\\n" "$line" >> "$outfile"
				fi
			;;
		esac
	done < "$file"

	return $(ls -l "$dir/"*.in 2>/dev/null | wc -l)
}

run_testcase() {
	local num=$1
	local dir=$2
	local in=$3
	local out=$4
	local err=$5
	local code=$6
	local args=$7
	local vars=$8
	local fail=0

	(
		cd "$dir"

		IFS=$'\n'

		local var
		for var in $vars; do
			case "$var" in
				*=*) export "$var" ;;
			esac
		done

		IFS=$' \t\n'

		$ucode_bin -T"," -L "$ucode_lib/*.so" -D TESTFILES_PATH="$($readlink -f "$dir/files")" $args - <"$in" >"$dir/res.out" 2>"$dir/res.err"
	)

	printf "%d\n" $? > "$dir/res.code"
	touch "$dir/empty"

	sed -i -e "s#$dir#.#g" "$dir/res.out" "$dir/res.err"

	if ! cmp -s "$dir/res.err" "${err:-$dir/empty}"; then
		[ $fail = 0 ] && printf "!\n"
		printf "Testcase #%d: Expected stderr did not match:\n" $num
		diff -au --color=always --label="Expected stderr" --label="Resulting stderr" "${err:-$dir/empty}" "$dir/res.err"
		printf -- "---\n"
		fail=1
	fi

	if ! cmp -s "$dir/res.out" "${out:-$dir/empty}"; then
		[ $fail = 0 ] && printf "!\n"
		printf "Testcase #%d: Expected stdout did not match:\n" $num
		diff -au --color=always --label="Expected stdout" --label="Resulting stdout" "${out:-$dir/empty}" "$dir/res.out"
		printf -- "---\n"
		fail=1
	fi

	if [ -n "$code" ] && ! cmp -s "$dir/res.code" "$code"; then
		[ $fail = 0 ] && printf "!\n"
		printf "Testcase #%d: Expected exit code did not match:\n" $num
		diff -au --color=always --label="Expected code" --label="Resulting code" "$code" "$dir/res.code"
		printf -- "---\n"
		fail=1
	fi

	return $fail
}

run_test() {
	local file=$1
	local name=${file##*/}
	local res ecode eout eerr ein eargs tests
	local testcase_first=0 failed=0 count=0

	printf "%s %s " "$name" "${line:${#name}}"

	dir_4_test=$($readlink -f $(mktemp  -d /tmp/rt.XXXX ))
	
	extract_sections "$file" "${dir_4_test}"
	tests=$?

	[ -f "${dir_4_test}/001.in" ] && testcase_first=1

	for res in "${dir_4_test}/"[0-9]*; do
		case "$res" in
			*.in)
				count=$((count + 1))

				if [ $testcase_first = 1 ]; then
					# Flush previous test
					if [ -n "$ein" ]; then
						run_testcase $count "${dir_4_test}" "$ein" "$eout" "$eerr" "$ecode" "$eargs" "$evars" || failed=$((failed + 1))
						eout=""
						eerr=""
						ecode=""
						eargs=""
						evars=""
					fi

					ein=$res
				else
					run_testcase $count "${dir_4_test}" "$res" "$eout" "$eerr" "$ecode" "$eargs" "$evars" || failed=$((failed + 1))

					eout=""
					eerr=""
					ecode=""
					eargs=""
					evars=""
				fi

			;;
			*.stdout) eout=$res ;;
			*.stderr) eerr=$res ;;
			*.exitcode) ecode=$res ;;
			*.args) eargs=$(cat "$res") ;;
			*.vars) evars=$(cat "$res") ;;
		esac
	done

	# Flush last test
	if [ $testcase_first = 1 ] && [ -n "$eout$eerr$ecode" ]; then
		run_testcase $count "${dir_4_test}" "$ein" "$eout" "$eerr" "$ecode" "$eargs" "$evars" || failed=$((failed + 1))
	fi

	if [ $failed = 0 ]; then
		printf "OK\n"
		rm -r "${dir_4_test}"
	else
		printf "%s %s FAILED (%d/%d)\ntemp dir was %s\n" "$name" "${line:${#name}}" $failed $tests $dir_4_test
	fi

	return $failed
}


n_tests=0
n_fails=0

select_tests="$@"

use_test() {
	local input="$($readlink -f "$1")"
	local test

	[ -f "$input" ] || return 1
	[ -n "$select_tests" ] || return 0

	for test in "$select_tests"; do
		test="$($readlink -f "$test")"

		[ "$test" != "$input" ] || return 0
	done

	return 1
}

for catdir in "$testdir/"[0-9][0-9]_*; do
	[ -d "$catdir" ] || continue

	printf "\n##\n## Running %s tests\n##\n\n" "${catdir##*/[0-9][0-9]_}"

	for testfile in "$catdir/"[0-9][0-9]_*; do
		use_test "$testfile" || continue

		n_tests=$((n_tests + 1))
		run_test "$testfile" || n_fails=$((n_fails + 1))
	done
done

printf "\nRan %d tests, %d okay, %d failures\n" $n_tests $((n_tests - n_fails)) $n_fails
exit $n_fails
