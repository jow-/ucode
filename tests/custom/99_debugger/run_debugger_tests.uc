#!/usr/bin/env -S ucode -S

// Debugger Interactive CLI Test Runner (Standalone)
// =================================================
// Standalone test runner for the interactive debugger that doesn't rely
// on the cram-style test infrastructure.

import * as fs from 'fs';

let testdir = sourcepath(0, true);
let topdir = fs.realpath(`${testdir}/..`);
let tmpdir = '/tmp/debugger_test.' + system('echo $$');

let ucode_bin = getenv('UCODE_BIN') || '/home/jow/devel/ucode.git/build-debug/ucode';

// Test result tracking
let n_tests = 0;
let n_passed = 0;
let n_failed = 0;
let n_crashed = 0;
let n_timeout = 0;

// Test timeout in seconds
let TEST_TIMEOUT = 10;

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function mkdir_p(path) {
	let parts = split(rtrim(path, '/') || '/', /\/+/);
	let current = '';
	for (let part in parts) {
		current += part + '/';
		if (!fs.access(current)) {
			fs.mkdir(current);
		}
	}
}

// Send commands to debugger and capture output
function run_debugger(source_code, commands, timeout_sec) {
	if (timeout_sec == null) timeout_sec = TEST_TIMEOUT;
	mkdir_p(tmpdir);
	
	let stdin_file = `${tmpdir}/stdin.in`;
	let stdout_file = `${tmpdir}/stdout.out`;
	let stderr_file = `${tmpdir}/stderr.err`;
	let source_file = `${tmpdir}/source.uc`;
	
	// Write source code (no wrapper needed - -x flag starts debugger)
	fs.writefile(source_file, source_code);
	
	// Write commands (each on new line, with final quit -f)
	let cmd_lines = [ ...commands, 'quit -f', '' ];
	fs.writefile(stdin_file, join('\n', cmd_lines) + '\n');
	
	// Build command
	let libdir = fs.dirname(ucode_bin);
	let cmd = sprintf(
		'cd %s && timeout %d bash -c "export LD_LIBRARY_PATH=%s && %s -L %s -x %s < %s > %s 2> %s 2>&1" ; echo "EXIT:$?"',
		topdir,
		timeout_sec,
		libdir,
		ucode_bin,
		libdir,
		source_file,
		stdin_file,
		stdout_file,
		stderr_file
	);
	
	// Run and capture exit code
	let exitcode = system(cmd);
	
	// Read outputs
	let stdout = fs.access(stdout_file) ? fs.readfile(stdout_file) ?? '' : '';
	let stderr = fs.access(stderr_file) ? fs.readfile(stderr_file) ?? '' : '';
	
	// Strip ANSI codes from stdout for comparison
	stdout = replace(stdout, /\x1b\[[0-9;]*[a-zA-Z]/g, '');
	stdout = replace(stdout, /\x1b\[[0-9;]*m/g, '');
	
	// Check for timeout
	if (exitcode == 124) {
		return { stdout, stderr, exitcode: -1, timed_out: true };
	}
	
	return { stdout: stdout, stderr: stderr, exitcode: exitcode, timed_out: false };
}

// Run a single debugger test
function run_test(name, source_code, commands, expectations) {
	n_tests++;
	
	let result = run_debugger(source_code, commands);
	let failed = false;
	let exp = expectations ?? {};
	
	// Check for crash
	if (result.exitcode < 0 || result.exitcode > 128) {
		if (exp.no_crash) {
			printf("FAIL %s: Crashed (exit code %d)\n", name, result.exitcode);
			printf("  stderr: %s\n", substr(result.stderr, 0, 200));
			n_failed++;
			n_crashed++;
			return false;
		}
	}
	
	// Check for timeout
	if (result.timed_out) {
		if (exp.no_timeout) {
			printf("FAIL %s: Timed out after %ds\n", name, TEST_TIMEOUT);
			n_failed++;
			n_timeout++;
			return false;
		}
	}
	
	// Check stdout expectations
	if (exp.stdout_contains) {
		for (let pattern in exp.stdout_contains) {
			// Convert string to regex if needed
			let re = (type(pattern) == 'string') ? regexp(pattern) : pattern;
			if (!match(result.stdout, re)) {
				printf("FAIL %s: stdout does not contain '%s'\n", name, pattern);
				printf("  Got: %s\n", substr(result.stdout, 0, 200));
				failed = true;
			}
		}
	}
	
	if (exp.stdout_not_contains) {
		for (let pattern in exp.stdout_not_contains) {
			let re = (type(pattern) == 'string') ? regexp(pattern) : pattern;
			if (match(result.stdout, re)) {
				printf("FAIL %s: stdout unexpectedly contains '%s'\n", name, pattern);
				failed = true;
			}
		}
	}
	
	// Check stderr expectations  
	if (exp.stderr_contains) {
		for (let pattern in exp.stderr_contains) {
			let re = (type(pattern) == 'string') ? regexp(pattern) : pattern;
			if (!match(result.stderr, re)) {
				printf("FAIL %s: stderr does not contain '%s'\n", name, pattern);
				failed = true;
			}
		}
	}
	
	// Check exit code expectation
	if (exp.exitcode !== null && exp.exitcode !== undefined) {
		if (result.exitcode != expectations.exitcode) {
			printf("FAIL %s: exit code %d != expected %d\n", name, result.exitcode, expectations.exitcode);
			failed = true;
		}
	}
	
	if (!failed) {
		printf("PASS %s\n", name);
		n_passed++;
		return true;
	} else {
		n_failed++;
		return false;
	}
}

// ============================================================================
// TEST SUITES
// ============================================================================

function test_basic_breakpoint() {
	printf("\n## Basic Breakpoint Tests\n\n");
	
	run_test("break_at_line",
		`print("hello");
print("world");
print("done");`,
		['break 2', 'continue'],
		{ stdout_contains: ['Paused'], no_crash: true }
	);
	
	run_test("break_function",
		`function test() {
	print("in test");
}
test();`,
		['break test', 'continue'],
		{ stdout_contains: ['Paused'], no_crash: true }
	);
	
	run_test("break_multiple",
		`print("a");
print("b");
print("c");`,
		['break 1', 'break 2', 'list', 'continue'],
		{ stdout_contains: ['1', '2'], no_crash: true }
	);
	
	run_test("delete_breakpoint",
		`print("a");
print("b");`,
		['break 1', 'delete 1', 'list', 'continue'],
		{ no_crash: true }
	);
}

function test_execution_control() {
	printf("\n## Execution Control Tests\n\n");
	
	run_test("step_command",
		`let x = 1;
let y = 2;
let z = x + y;`,
		['step', 'step', 'step', 'continue'],
		{ stdout_contains: ['Paused'], no_crash: true }
	);
	
	run_test("next_command",
		`function inner() { return 1; }
function outer() { return inner() + 1; }
outer();`,
		['break outer', 'continue', 'next', 'next', 'continue'],
		{ stdout_contains: ['Paused'], no_crash: true }
	);
	
	run_test("continue_command",
		`print("a");
print("b");
print("c");`,
		['break 2', 'continue', 'continue'],
		{ stdout_contains: ['a', 'Paused', 'b', 'c'], no_crash: true }
	);
	
	run_test("return_command",
		`function inner() { return 1; }
function outer() { return inner() + 1; }
outer();`,
		['break inner', 'continue', 'return', 'continue'],
		{ stdout_contains: ['Paused'], no_crash: true }
	);
	
	run_test("quit_command",
		`print("a");
print("b");
print("c");`,
		['quit'],
		{ no_crash: true }
	);
}

function test_variable_inspection() {
	printf("\n## Variable Inspection Tests\n\n");
	
	run_test("print_simple_var",
		`let x = 42;
let y = "hello";`,
		['break 1', 'continue', 'print x', 'print y', 'continue'],
		{ stdout_contains: ['42', 'hello'], no_crash: true }
	);
	
	run_test("print_expression",
		`let a = 10;
let b = 20;
print(a + b);`,
		['break 1', 'continue', 'continue', 'print a + b', 'continue'],
		{ stdout_contains: ['30'], no_crash: true }
	);
	
	run_test("print_object",
		`let obj = { foo: "bar", num: 123 };`,
		['break 1', 'continue', 'print obj', 'continue'],
		{ stdout_contains: ['foo', 'bar'], no_crash: true }
	);
	
	run_test("print_array",
		`let arr = [1, 2, 3, 4, 5];`,
		['break 1', 'continue', 'print arr', 'continue'],
		{ stdout_contains: ['1', '2', '3'], no_crash: true }
	);
	
	run_test("variables_command",
		`let x = 1;
let y = 2;
let z = 3;`,
		['continue', 'quit -f'],
		{ no_crash: true }
	);
	
	run_test("print_nested",
		`let obj = { nested: { deep: "value" } };`,
		['break 1', 'continue', 'print obj.nested.deep', 'continue'],
		{ stdout_contains: ['value'], no_crash: true }
	);
}

function test_stack_tracing() {
	printf("\n## Stack Tracing Tests\n\n");
	
	run_test("backtrace_simple",
		`function level3() { return 3; }
function level2() { return level3(); }
function level1() { return level2(); }
level1();`,
		['break level3', 'continue', 'backtrace', 'continue'],
		{ stdout_contains: ['level3', 'level2', 'level1'], no_crash: true }
	);
	
	run_test("backtrace_full",
		`function callee() { return 1; }
function caller() { return callee(); }
caller();`,
		['break callee', 'continue', 'backtrace full', 'continue'],
		{ stdout_contains: ['callee', 'caller'], no_crash: true }
	);
	
	run_test("bt_alias",
		`print("test");`,
		['break 1', 'continue', 'bt', 'continue'],
		{ no_crash: true }
	);
}

function test_source_view() {
	printf("\n## Source Viewing Tests\n\n");
	
	run_test("lines_current",
		`// line 1
// line 2
// line 3
print("test");`,
		['break 4', 'continue', 'lines 4', 'continue'],
		{ stdout_contains: ['print'], no_crash: true }
	);
	
	run_test("lines_with_context",
		`// 1
// 2
// 3
// 4
// 5
print("test");`,
		['break 6', 'continue', 'lines 6', 'continue'],
		{ stdout_contains: ['print'], no_crash: true }
	);
	
	run_test("sources_command",
		`print("test");`,
		['break 1', 'continue', 'sources', 'continue'],
		{ no_crash: true }
	);
}

function test_disassembly() {
	printf("\n## Disassembly Tests\n\n");
	
	run_test("disasm_current",
		`let x = 1 + 2;`,
		['break 1', 'continue', 'disasm', 'continue'],
		{ stdout_contains: ['LOAD'], no_crash: true }
	);
	
	run_test("disasm_function",
		`function test() {
	return 42;
}
test();`,
		['break test', 'continue', 'disasm test', 'continue'],
		{ stdout_contains: ['test', 'LOAD8'], no_crash: true }
	);
	
	run_test("disasm_alias",
		`print("test");`,
		['break 1', 'continue', 'disasm', 'continue'],
		{ stdout_contains: ['LOAD'], no_crash: true }
	);
}

function test_help_and_misc() {
	printf("\n## Help and Miscellaneous Tests\n\n");
	
	run_test("help_command",
		`print("test");`,
		['break 1', 'continue', 'help', 'continue'],
		{ stdout_contains: ['break', 'continue', 'step', 'next'], no_crash: true }
	);
	
	run_test("list_command",
		`print("a");
print("b");`,
		['break 1', 'break 2', 'list', 'continue'],
		{ stdout_contains: ['#1', '#2'], no_crash: true }
	);
	
	run_test("ls_alias",
		`print("test");`,
		['break 1', 'continue', 'ls', 'continue'],
		{ no_crash: true }
	);
	
	run_test("src_alias",
		`print("test");`,
		['break 1', 'continue', 'src', 'continue'],
		{ no_crash: true }
	);
	
	run_test("invalid_command",
		`print("test");`,
		['break 1', 'continue', 'invalidcmd', 'continue'],
		{ stdout_contains: ['Unrecognized'], no_crash: true }
	);
}

function test_debug_api() {
	printf("\n## Debug API Tests\n\n");
	
	run_test("traceback_function",
		`function level3() { return debug.traceback(); }
function level2() { return level3(); }
function level1() { return level2(); }
let result = level1();
print("done");
print(result);`,
		['continue'],
		{ stdout_contains: ['done', 'level3', 'level2', 'level1'], no_crash: true }
	);
	
	run_test("sourcepos_function",
		`function test() {
	let pos = debug.sourcepos();
	print("line", pos.line);
}
test();`,
		['continue'],
		{ stdout_contains: ['line'], no_crash: true }
	);
	
	run_test("getinfo_function",
		`function test() { return 1; }
let info = debug.getinfo(test);
print("done");`,
		['continue'],
		{ stdout_contains: ['done'], no_crash: true }
	);
	
	run_test("debugger_api",
		`function test() {
	print("inside test");
}
test();
print("after");`,
		['break test', 'continue', 'continue'],
		{ stdout_contains: ['inside test', 'after'], no_crash: true }
	);
}

function test_edge_cases() {
	printf("\n## Edge Cases and Bug Tests\n\n");
	
	// Test for segfault on empty input
	run_test("empty_commands",
		`print("test");`,
		[],
		{ no_crash: true }
	);
	
	// Test rapid breakpoint setting
	run_test("rapid_breakpoints",
		`print("a");
print("b");
print("c");
print("d");
print("e");`,
		['break 1', 'break 2', 'break 3', 'break 4', 'break 5', 'list', 'continue'],
		{ no_crash: true }
	);
	
	// Test breakpoint at non-existent line
	run_test("invalid_breakpoint",
		`print("test");`,
		['break 999', 'continue'],
		{ no_crash: true }
	);
	
	// Test delete non-existent breakpoint
	run_test("delete_invalid",
		`print("test");`,
		['delete 999', 'continue'],
		{ no_crash: true }
	);
	
	// Test print undefined variable
	run_test("print_undefined",
		`print("test");`,
		['break 1', 'continue', 'print undefined_var', 'continue'],
		{ no_crash: true }
	);
	
	// Test deep recursion
	run_test("deep_recursion",
		`function recurse(n) {
	if (n <= 0) return 0;
	return recurse(n - 1) + 1;
}
recurse(100);`,
		['break recurse', 'continue'],
		{ no_crash: true, no_timeout: true }
	);
	
	// Test large object
	run_test("large_object",
		`let obj = {};
for (let i = 0; i < 100; i++) {
	obj["key" + i] = i;
}`,
		['break 1', 'continue', 'print obj', 'continue'],
		{ no_crash: true }
	);
	
	// Test closure with upvalues
	run_test("closure_upvalues",
		`function makeCounter() {
	let count = 0;
	return function() { count++; return count; };
}
let counter = makeCounter();
counter();`,
		['break counter', 'continue', 'print counter()', 'continue'],
		{ no_crash: true }
	);
	
	// Test exception handling
	run_test("exception_in_debug",
		`try {
	die("test error");
} catch (e) {
	print("caught");
}`,
		['continue'],
		{ stdout_contains: ['caught'], no_crash: true }
	);
}

function test_memory_safety() {
	printf("\n## Memory Safety Tests\n\n");
	
	// Test repeated variable inspection
	run_test("repeated_inspection",
		`let x = 1;
let y = 2;
let z = 3;`,
		['break 1', 'continue', 'print x', 'print y', 'print z', 'print x', 'print y', 'continue'],
		{ no_crash: true }
	);
	
	// Test disassembly of various constructs
	run_test("disasm_variants",
		`let a = 1;
let b = "str";
let c = [1, 2, 3];
let d = { x: 1 };
function f() { return 1; }`,
		['break 1', 'continue', 'disasm', 'disasm f', 'continue'],
		{ no_crash: true }
	);
	
	// Test backtrace with mixed C and ucode frames
	run_test("mixed_frames",
		`replace("test", "t", function(m) {
	return m.toUpperCase();
});`,
		['continue'],
		{ no_crash: true }
	);
}

// ============================================================================
// MAIN
// ============================================================================

printf('\n##\n## Running Debugger Tests\n##\n\n');

try {
	mkdir_p(tmpdir);
	
	test_basic_breakpoint();
	test_execution_control();
	test_variable_inspection();
	test_stack_tracing();
	test_source_view();
	test_disassembly();
	test_help_and_misc();
	test_debug_api();
	test_edge_cases();
	test_memory_safety();
}
catch (e) {
	warn(`Test runner error: ${e.type}: ${e.message}\n${e.stacktrace[0].context}\n`);
}

// Cleanup
system(['rm', '-rf', tmpdir]);

printf('\n##\n## Test Summary\n##\n\n');
printf('Ran %d tests: %d passed, %d failed', n_tests, n_passed, n_failed);
if (n_crashed > 0) printf(' (%d crashes)', n_crashed);
if (n_timeout > 0) printf(' (%d timeouts)', n_timeout);
printf('\n');

exit(n_failed > 0 ? 1 : 0);
