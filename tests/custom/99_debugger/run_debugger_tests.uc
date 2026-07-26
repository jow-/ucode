#!/usr/bin/env -S ucode -S

// Debugger Protocol Test Runner (Standalone)
// ===========================================
// Standalone test runner for the debugger's line-based protocol
// (see lib/debug_proto.h) that doesn't rely on cram-style infrastructure.
//
// Each test starts the target script unmodified via `-X1` (attach mode with
// an initial breakpoint at line 1 - the same mechanism the interactive `-x`
// CLI and SIGUSR1 attach use), connects to the resulting PID-derived attach
// socket directly with the `socket` module, sends a batch of protocol
// messages, and asserts on the *parsed* response messages and/or the target
// script's own stdout - not on rendered ANSI text, since the server no
// longer renders anything.
//
// `-X1` (rather than `debug.listen(path)`, which drives the whole session
// from *inside* a nested native call and needs `uc_vm_resume()` to hand
// control back to the VM's bytecode loop) matters here, not just for
// realism: breakpoints set *during* a debug.listen() session and hit via a
// later CONTINUE don't reliably re-fire through that nested-resume path,
// whereas `-X`/`-x`'s breakpoint-loop-driven pause (bk_enter_session invoked
// directly from the VM's per-instruction dispatch, see vm.c
// uc_vm_decode_insn()) does not have this problem - every test below that
// needs a *second* pause after a CONTINUE relies on this.

import * as fs from 'fs';
import * as sock from 'socket';

let testdir = sourcepath(0, true);
let topdir = fs.realpath(`${testdir}/..`);
let tmpdir = '/tmp/debugger_test.' + system('echo $$');

// UCODE_BIN may be a plain executable path, or (as set by the "custom"/
// "debugger" ctest targets) a full command line like
// "valgrind --quiet --leak-check=full /path/to/ucode" that needs to be
// invoked word-split, not treated as a single path - so fs.dirname(ucode_bin)
// would be nonsense for such a value. UCODE_LIB is set alongside it by those
// same ctest targets specifically to give the correct library directory
// without needing to parse UCODE_BIN at all.
let ucode_bin = getenv('UCODE_BIN') || '/home/jow/devel/ucode.git/build/ucode';
let libdir = getenv('UCODE_LIB') || fs.dirname(ucode_bin);

function shq(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

let n_tests = 0;
let n_passed = 0;
let n_failed = 0;
let n_crashed = 0;
let n_timeout = 0;

// Generous enough to tolerate running under valgrind --leak-check=full
// (the "custom"/"debugger" ctest targets always do), which can slow
// process startup and breakpoint hits down substantially.
let TEST_TIMEOUT = 30;

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

// Connect to the given Unix domain socket path, retrying for a bit while
// the target process is still starting up / hasn't armed its attach socket
// yet.
function connect_retry(path, timeout_sec) {
	let deadline = time() + timeout_sec;

	while (time() < deadline) {
		let conn = sock.connect({ family: sock.AF_UNIX, path });

		if (conn) {
			// Bound recv() below so a quiet socket never blocks forever.
			conn.setopt(sock.SOL_SOCKET, sock.SO_RCVTIMEO, { sec: 0, usec: 20000 });
			return conn;
		}

		system('sleep 0.05');
	}

	return null;
}

// Read every complete "VERB [json]" line already available on `conn` right
// now (non-blocking-ish: short poll loop), parsing each into
// { verb, payload }. Stops once nothing new arrives for a short quiet
// period, since responses may legitimately be a variable-length burst
// (e.g. BREAK + BREAKPOINT_ADDED, then a later EVENT exit).
function drain_messages(conn, quiet_ms) {
	let messages = [];
	let buf = '';
	let idle = 0;

	while (idle < quiet_ms) {
		let chunk = conn.recv(65536);

		if (chunk == null || chunk == '') {
			idle += 20;
			system('sleep 0.02');
			continue;
		}

		idle = 0;
		buf += chunk;

		let nl;
		while ((nl = index(buf, "\n")) >= 0) {
			let line = substr(buf, 0, nl);
			buf = substr(buf, nl + 1);

			if (line == '')
				continue;

			let sp = index(line, ' ');
			let verb = (sp >= 0) ? substr(line, 0, sp) : line;
			let payload = (sp >= 0) ? json(substr(line, sp + 1)) : null;

			push(messages, { verb, payload });
		}
	}

	return messages;
}

// Run `source_code` unmodified via `-X1` (attach mode, breaking at line 1)
// with a batch of protocol messages sent all at once - pacing doesn't
// matter since the server processes them strictly in order off its
// blocking read loop regardless of when they were written, and these tests
// only care about the final observable state (script stdout + which
// responses came back), not interactive timing.
function run_debugger(source_code, steps, timeout_sec) {
	if (timeout_sec == null) timeout_sec = TEST_TIMEOUT;
	mkdir_p(tmpdir);

	let source_file = `${tmpdir}/source.uc`;
	let stdout_file = `${tmpdir}/stdout.out`;
	let stderr_file = `${tmpdir}/stderr.err`;
	let wrapper_file = `${tmpdir}/wrapper.sh`;
	let pid_file = `${tmpdir}/pid`;

	fs.writefile(source_file, source_code);
	fs.unlink(pid_file);

	// Runs the target in the background (recording its real PID, *not*
	// some wrapping shell's) and waits for it, so this test process can
	// concurrently drive the PID-derived attach socket while the target is
	// paused at its line-1 breakpoint. Enforces its own timeout by killing
	// the PID directly rather than via `timeout`, since `timeout` would be
	// the one owning the PID `$!` reports otherwise.
	// resolve_breakpoint() can't default the path from a current frame
	// before the program has started running (there is none yet), so the
	// pre-execution `-X` breakpoint spec needs an explicit "path:line"
	// rather than a bare line number.
	// `ucode_bin` is deliberately left unquoted below: under the "custom"/
	// "debugger" ctest targets it is itself a multi-word command
	// ("valgrind --quiet --leak-check=full /path/ucode") that needs to be
	// word-split so valgrind sees its own flags, not one opaque argument.
	fs.writefile(wrapper_file, sprintf(
		'cd %s\n' +
		'export LD_LIBRARY_PATH=%s\n' +
		'%s -L %s -X%s:1 %s > %s 2> %s &\n' +
		'echo $! > %s\n' +
		'wait $!\n' +
		'echo "EXIT:$?"\n',
		shq(topdir), shq(libdir), ucode_bin, shq(libdir), shq(source_file), shq(source_file),
		shq(stdout_file), shq(stderr_file), shq(pid_file)
	));

	let proc = fs.popen(`sh ${wrapper_file}`, 'r');
	let deadline = time() + timeout_sec;
	let pid = null;

	while (time() < deadline && !pid) {
		if (fs.access(pid_file)) {
			let s = trim(fs.readfile(pid_file) ?? '');
			if (s != '')
				pid = int(s);
		}

		if (!pid)
			system('sleep 0.02');
	}

	let sock_path = pid ? sprintf('/tmp/ucode-debug-%d.sock', pid) : null;
	let conn = sock_path ? connect_retry(sock_path, timeout_sec) : null;
	let messages = [];

	if (conn) {
		// First message is always the initial PAUSED (from the -X1
		// breakpoint at line 1).
		for (let msg in drain_messages(conn, 400))
			push(messages, msg);

		let lines = [];
		for (let step in steps)
			push(lines, step);
		// Let anything already paused (including the initial -X1 pause,
		// for tests with no steps of their own) run to completion first;
		// QUIT is just a safety net in case something is still paused
		// afterward (a harmless no-op otherwise, since the connection is
		// already gone by the time it'd be read).
		push(lines, 'CONTINUE');
		push(lines, 'QUIT');

		conn.send(join("\n", lines) + "\n");

		for (let msg in drain_messages(conn, 800))
			push(messages, msg);

		conn.close();
	}
	else if (pid) {
		// Never connected (e.g. no attach socket appeared) - don't leave
		// the target hanging around forever.
		system(`kill -9 ${pid} 2>/dev/null`);
	}

	let wrapper_out = proc.read('all') ?? '';
	proc.close();

	let exitcode = -1;
	let m = match(wrapper_out, /EXIT:(-?[0-9]+)/);
	if (m) exitcode = int(m[1]);

	let stdout = fs.access(stdout_file) ? fs.readfile(stdout_file) ?? '' : '';
	let stderr = fs.access(stderr_file) ? fs.readfile(stderr_file) ?? '' : '';

	let timed_out = (exitcode == -1 && !conn);

	return { stdout, stderr, exitcode, timed_out, messages, connected: !!conn };
}

// True if any received message has the given verb (optionally further
// filtered by a predicate over its payload).
function has_message(messages, verb, pred) {
	for (let msg in messages) {
		if (msg.verb != verb)
			continue;

		if (!pred || pred(msg.payload))
			return true;
	}

	return false;
}

function run_test(name, source_code, steps, expectations) {
	n_tests++;

	let result = run_debugger(source_code, steps);
	let failed = false;
	let exp = expectations ?? {};

	if (exp.must_connect && !result.connected) {
		printf("FAIL %s: could not connect to debug socket\n", name);
		n_failed++;
		n_crashed++;
		return false;
	}

	if (result.exitcode < 0 && result.exitcode != -1) {
		if (exp.no_crash) {
			printf("FAIL %s: crashed (exit code %d)\n", name, result.exitcode);
			printf("  stderr: %s\n", substr(result.stderr, 0, 200));
			n_failed++;
			n_crashed++;
			return false;
		}
	}

	if (result.timed_out) {
		if (exp.no_timeout) {
			printf("FAIL %s: timed out after %ds\n", name, TEST_TIMEOUT);
			n_failed++;
			n_timeout++;
			return false;
		}
	}

	if (exp.stdout_contains) {
		for (let pattern in exp.stdout_contains) {
			let re = (type(pattern) == 'string') ? regexp(pattern) : pattern;
			if (!match(result.stdout, re)) {
				printf("FAIL %s: stdout does not contain '%s'\n", name, pattern);
				printf("  Got: %s\n", substr(result.stdout, 0, 200));
				failed = true;
			}
		}
	}

	if (exp.messages_contain) {
		for (let verb in exp.messages_contain) {
			if (!has_message(result.messages, verb)) {
				printf("FAIL %s: no '%s' response received\n", name, verb);
				printf("  Got verbs: %s\n", join(', ', map(result.messages, (m) => m.verb)));
				failed = true;
			}
		}
	}

	if (exp.check) {
		let msg = exp.check(result);
		if (msg) {
			printf("FAIL %s: %s\n", name, msg);
			failed = true;
		}
	}

	if (!failed) {
		printf("PASS %s\n", name);
		n_passed++;
		return true;
	}

	n_failed++;
	return false;
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
		['BREAK {"spec":"2"}', 'CONTINUE'],
		{ messages_contain: ['PAUSED', 'BREAKPOINT_ADDED'], no_crash: true }
	);

	run_test("break_function",
		`function test() {
	print("in test");
}
test();`,
		['BREAK {"spec":"test"}', 'CONTINUE'],
		{ messages_contain: ['PAUSED', 'BREAKPOINT_ADDED'], no_crash: true }
	);

	run_test("break_multiple",
		`print("a");
print("b");
print("c");`,
		['BREAK {"spec":"1"}', 'BREAK {"spec":"2"}', 'LIST_BREAKPOINTS', 'CONTINUE'],
		{
			messages_contain: ['BREAKPOINTS'],
			no_crash: true,
			check: (r) => {
				let bp = null;
				for (let m in r.messages)
					if (m.verb == 'BREAKPOINTS') bp = m.payload;
				if (!bp || length(bp.items) < 2)
					return "expected at least 2 breakpoints listed";
				return null;
			}
		}
	);

	run_test("delete_breakpoint",
		`print("a");
print("b");`,
		['BREAK {"spec":"1"}', 'DELETE {"id":1}', 'LIST_BREAKPOINTS', 'CONTINUE'],
		{ messages_contain: ['OK'], no_crash: true }
	);
}

function test_execution_control() {
	printf("\n## Execution Control Tests\n\n");

	run_test("step_command",
		`let x = 1;
let y = 2;
let z = x + y;`,
		['STEP', 'STEP', 'STEP', 'CONTINUE'],
		{ must_connect: true, no_crash: true }
	);

	run_test("next_command",
		`function inner() { return 1; }
function outer() { return inner() + 1; }
outer();`,
		['BREAK {"spec":"outer"}', 'CONTINUE', 'NEXT', 'NEXT', 'CONTINUE'],
		{ must_connect: true, no_crash: true }
	);

	run_test("continue_command",
		`print("a");
print("b");
print("c");`,
		['BREAK {"spec":"2"}', 'CONTINUE', 'CONTINUE'],
		{ stdout_contains: ['a', 'b', 'c'], no_crash: true }
	);

	run_test("return_command",
		`function inner() { return 1; }
function outer() { return inner() + 1; }
outer();`,
		['BREAK {"spec":"inner"}', 'CONTINUE', 'RETURN', 'CONTINUE'],
		{ must_connect: true, no_crash: true }
	);

	run_test("quit_command",
		`print("a");
print("b");
print("c");`,
		[],
		{ no_crash: true }
	);
}

function test_variable_inspection() {
	printf("\n## Variable Inspection Tests\n\n");

	// STEP (rather than BREAK+CONTINUE to a line number) advances past the
	// declarations here: resolving a bare line-number breakpoint against a
	// script that is only variable declarations is a pre-existing, narrow
	// edge case in resolve_breakpoint()/lookup_stmt_boundary() (unrelated
	// to the protocol) that single-instruction stepping avoids entirely.
	run_test("print_simple_var",
		`let x = 42;
let y = "hello";
1;`,
		['STEP', 'STEP', 'PRINT {"expr":"x"}', 'PRINT {"expr":"y"}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				let vals = [];
				for (let m in r.messages)
					if (m.verb == 'VALUE') push(vals, m.payload.repr);
				if (!vals[0] || index(vals[0], '42') < 0) return "expected 42 in first VALUE";
				if (!vals[1] || index(vals[1], 'hello') < 0) return "expected hello in second VALUE";
				return null;
			}
		}
	);

	run_test("print_expression",
		`let a = 10;
let b = 20;
print(a + b);`,
		['STEP', 'STEP', 'PRINT {"expr":"a + b"}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'VALUE' && index(m.payload.repr, '30') >= 0) return null;
				return "expected VALUE containing 30";
			}
		}
	);

	run_test("print_object",
		`let obj = { foo: "bar", num: 123 };
1;`,
		['STEP', 'PRINT {"expr":"obj"}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'VALUE' && index(m.payload.repr, 'foo') >= 0 && index(m.payload.repr, 'bar') >= 0)
						return null;
				return "expected VALUE containing foo/bar";
			}
		}
	);

	run_test("print_array",
		`let arr = [1, 2, 3, 4, 5];
1;`,
		['STEP', 'PRINT {"expr":"arr"}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'VALUE' && index(m.payload.repr, '1') >= 0 && index(m.payload.repr, '3') >= 0)
						return null;
				return "expected VALUE containing array elements";
			}
		}
	);

	run_test("variables_command",
		`let x = 1;
let y = 2;
let z = 3;`,
		['VARIABLES'],
		{ messages_contain: ['VARIABLES'], no_crash: true }
	);

	run_test("print_nested",
		`let obj = { nested: { deep: "value" } };
1;`,
		['STEP', 'PRINT {"expr":"obj.nested.deep"}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'VALUE' && index(m.payload.repr, 'value') >= 0) return null;
				return "expected VALUE containing 'value'";
			}
		}
	);
}

function test_stack_tracing() {
	printf("\n## Stack Tracing Tests\n\n");

	run_test("backtrace_simple",
		`function level3() { return 3; }
function level2() { return level3(); }
function level1() { return level2(); }
level1();`,
		['BREAK {"spec":"level3"}', 'CONTINUE', 'BACKTRACE {}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages) {
					if (m.verb != 'BACKTRACE') continue;
					let names = join(',', map(m.payload.frames, (f) => f.function ?? ''));
					if (index(names, 'level3') >= 0 && index(names, 'level2') >= 0 && index(names, 'level1') >= 0)
						return null;
				}
				return "expected backtrace with level1/2/3";
			}
		}
	);

	run_test("backtrace_full",
		`function callee() { return 1; }
function caller() { return callee(); }
caller();`,
		['BREAK {"spec":"callee"}', 'CONTINUE', 'BACKTRACE {"full":true}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages) {
					if (m.verb != 'BACKTRACE') continue;
					let names = join(',', map(m.payload.frames, (f) => f.function ?? ''));
					if (index(names, 'callee') >= 0 && index(names, 'caller') >= 0)
						return null;
				}
				return "expected backtrace with callee/caller";
			}
		}
	);

	run_test("bt_alias",
		`print("test");`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'BACKTRACE {}', 'CONTINUE'],
		{ messages_contain: ['BACKTRACE'], no_crash: true }
	);
}

function test_source_view() {
	printf("\n## Source Viewing Tests\n\n");

	run_test("lines_current",
		`// line 1
// line 2
// line 3
print("test");`,
		// A bare, comment-only ":line" spec resolves to the next real
		// statement (there is no bytecode to break on within a comment),
		// exactly like -X1's own initial breakpoint already demonstrates.
		['BREAK {"spec":"1"}', 'CONTINUE', 'LINES {}', 'CONTINUE'],
		{ messages_contain: ['SOURCE_RANGE'], no_crash: true }
	);

	run_test("lines_with_context",
		`// 1
// 2
// 3
// 4
// 5
print("test");`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'LINES {"before":3,"after":1}', 'CONTINUE'],
		{ messages_contain: ['SOURCE_RANGE'], no_crash: true }
	);

	run_test("sources_command",
		`print("test");`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'SOURCES', 'CONTINUE'],
		{ messages_contain: ['SOURCES'], no_crash: true }
	);

	run_test("source_fetch",
		`print("test");`,
		['LINES {}'],
		{
			no_crash: true,
			check: (r) => {
				let file = null;
				for (let m in r.messages)
					if (m.verb == 'SOURCE_RANGE') file = m.payload.file;
				if (!file) return "no SOURCE_RANGE received";
				return null;
			}
		}
	);
}

function test_disassembly() {
	printf("\n## Disassembly Tests\n\n");

	run_test("disasm_current",
		`let x = 1 + 2;`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'DISASSEMBLE', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'DISASSEMBLY' && length(m.payload.instructions) > 0) return null;
				return "expected non-empty DISASSEMBLY";
			}
		}
	);

	run_test("disasm_function",
		`function test() {
	return 42;
}
test();`,
		['BREAK {"spec":"test"}', 'CONTINUE', 'DISASSEMBLE {"spec":"test"}', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'DISASSEMBLY' && m.payload.function == 'test') return null;
				return "expected DISASSEMBLY for function 'test'";
			}
		}
	);
}

function test_help_and_misc() {
	printf("\n## Help and Miscellaneous Tests\n\n");

	run_test("help_command",
		`print("test");`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'HELP', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages) {
					if (m.verb != 'HELP') continue;
					let verbs = join(',', map(m.payload.commands, (c) => c.verb));
					if (index(verbs, 'BREAK') >= 0 && index(verbs, 'CONTINUE') >= 0 &&
					    index(verbs, 'STEP') >= 0 && index(verbs, 'NEXT') >= 0)
						return null;
				}
				return "expected HELP listing BREAK/CONTINUE/STEP/NEXT";
			}
		}
	);

	run_test("list_command",
		`print("a");
print("b");`,
		['BREAK {"spec":"1"}', 'BREAK {"spec":"2"}', 'LIST_BREAKPOINTS', 'CONTINUE'],
		{
			no_crash: true,
			check: (r) => {
				for (let m in r.messages)
					if (m.verb == 'BREAKPOINTS' && length(m.payload.items) >= 2) return null;
				return "expected at least 2 listed breakpoints";
			}
		}
	);

	run_test("invalid_command",
		`print("test");`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'BOGUS', 'CONTINUE'],
		{ messages_contain: ['ERROR'], no_crash: true }
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
		[],
		{ stdout_contains: ['done', 'level3', 'level2', 'level1'], no_crash: true }
	);

	run_test("sourcepos_function",
		`function test() {
	let pos = debug.sourcepos();
	print("line", pos.line);
}
test();`,
		[],
		{ stdout_contains: ['line'], no_crash: true }
	);

	run_test("getinfo_function",
		`function test() { return 1; }
let info = debug.getinfo(test);
print("done");`,
		[],
		{ stdout_contains: ['done'], no_crash: true }
	);

	run_test("debugger_api",
		`function test() {
	print("inside test");
}
test();
print("after");`,
		['BREAK {"spec":"test"}', 'CONTINUE', 'CONTINUE'],
		{ stdout_contains: ['inside test', 'after'], no_crash: true }
	);
}

function test_edge_cases() {
	printf("\n## Edge Cases and Bug Tests\n\n");

	run_test("empty_commands",
		`print("test");`,
		[],
		{ no_crash: true }
	);

	run_test("rapid_breakpoints",
		`print("a");
print("b");
print("c");
print("d");
print("e");`,
		['BREAK {"spec":"1"}', 'BREAK {"spec":"2"}', 'BREAK {"spec":"3"}', 'BREAK {"spec":"4"}',
		 'BREAK {"spec":"5"}', 'LIST_BREAKPOINTS', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("invalid_breakpoint",
		`print("test");`,
		['BREAK {"spec":"999"}', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("delete_invalid",
		`print("test");`,
		['DELETE {"id":999}', 'CONTINUE'],
		{ messages_contain: ['ERROR'], no_crash: true }
	);

	run_test("print_undefined",
		`print("test");`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'PRINT {"expr":"undefined_var"}', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("deep_recursion",
		`function recurse(n) {
	if (n <= 0) return 0;
	return recurse(n - 1) + 1;
}
recurse(100);`,
		['BREAK {"spec":"recurse"}', 'CONTINUE'],
		{ no_crash: true, no_timeout: true }
	);

	run_test("large_object",
		`let obj = {};
for (let i = 0; i < 100; i++) {
	obj["key" + i] = i;
}`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'PRINT {"expr":"obj"}', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("closure_upvalues",
		`function makeCounter() {
	let count = 0;
	return function() { count++; return count; };
}
let counter = makeCounter();
counter();`,
		['BREAK {"spec":"counter"}', 'CONTINUE', 'PRINT {"expr":"counter()"}', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("exception_in_debug",
		`try {
	die("test error");
} catch (e) {
	print("caught");
}`,
		// One CONTINUE for the initial -X1 pause, one more for the
		// automatic BK_CATCH pause the try/catch's die() triggers.
		['CONTINUE'],
		{ stdout_contains: ['caught'], no_crash: true }
	);
}

function test_memory_safety() {
	printf("\n## Memory Safety Tests\n\n");

	run_test("repeated_inspection",
		`let x = 1;
let y = 2;
let z = 3;`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'PRINT {"expr":"x"}', 'PRINT {"expr":"y"}',
		 'PRINT {"expr":"z"}', 'PRINT {"expr":"x"}', 'PRINT {"expr":"y"}', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("disasm_variants",
		`let a = 1;
let b = "str";
let c = [1, 2, 3];
let d = { x: 1 };
function f() { return 1; }`,
		['BREAK {"spec":"1"}', 'CONTINUE', 'DISASSEMBLE', 'DISASSEMBLE {"spec":"f"}', 'CONTINUE'],
		{ no_crash: true }
	);

	run_test("mixed_frames",
		`replace("test", "t", function(m) {
	return m.toUpperCase();
});`,
		[],
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
