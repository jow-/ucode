# UCode Debugger

## Overview

The ucode interpreter includes source-level debugging support: breakpoints,
stepping, stack inspection, and runtime expression evaluation. The
implementation is split into a **server** (the debug core, `lib/debug.c` +
`lib/debug_remote.c` + `lib/debug_proto.c`, loaded as the `debug` module) and
a **client** (`udbg`, at the repository root) that talks to it over a simple,
line-based text protocol.

The server never renders anything - no ANSI escapes, no syntax highlighting,
no formatted columns. It only emits and consumes structured protocol
messages (see "Wire Protocol" below). All rendering, source buffer handling
and interactive line editing live in the client. This split exists so that
alternative clients - IDE integrations, editor plugins, other tooling - can
drive the exact same debug core without reimplementing any of its logic, and
so the client can be tested and evolved independently of the VM-side
breakpoint machinery.

There is exactly one way a session is driven, regardless of how it was
reached: a connected file descriptor is handed to `bk_enter_session()`
(`lib/debug.c`), which writes a `PAUSED` message and then reads and dispatches
protocol commands until the client tells it to resume or quit. Three things
differ only in *how that fd is obtained*:

- **Local (`ucode -x script.uc`)** - `uc_debugger()` creates a `socketpair()`,
  forks, and execs `udbg --fd 3` in the child with one end of the pair on fd
  3; the parent (running the script) keeps the other end as the session fd.
  The child owns the real controlling terminal and is the interactive
  client; the parent never touches its own stdin/stdout for protocol
  traffic.
- **Remote, explicit path (`debug.listen(path)`)** - accepts a single
  connection on an arbitrary, caller-chosen Unix domain socket path and hands
  it to the same session driver.
- **Remote, SIGUSR1 attach (`ucode -X`, `debug.attach()`, `debug.listen()`
  with no path)** - arms a breakpoint and/or a `SIGUSR1` handler; once
  triggered, waits (up to 30s) for a client to connect to the PID-derived
  attach socket `/tmp/ucode-debug-<pid>.sock`, then hands off the accepted fd
  the same way. `udbg <pid>` automates sending the signal and connecting.

---

## Wire Protocol

One message per line, `\n`-terminated: an uppercase **VERB**, optionally
followed by a single space and a JSON object payload.

```
PAUSED {"reason":"breakpoint","file":"script.uc","line":12,"col":3,"function":"main","breakpoint_id":1}
BREAK {"spec":"script.uc:12"}
BREAKPOINT_ADDED {"id":1}
```

A payload, when present, is always a JSON *object* (never a bare
array/string/number), so new fields can be added without breaking existing
clients. `file` fields are the source's display path exactly as the server
resolves it (repository-relative when the source lives under the current
working directory, absolute otherwise) - clients should treat it as an
opaque key for the `SOURCE` verb, not derive anything from its shape.

### Client → server commands

| Verb | Payload | Response |
|---|---|---|
| `BREAK` | `{"spec":"path[:line[:col]]"\|"expr"}` | `BREAKPOINT_ADDED {"id"}` or `ERROR` |
| `DELETE` | `{"id":N}` (omit for the current breakpoint) | `OK` or `ERROR` |
| `LIST_BREAKPOINTS` | none | `BREAKPOINTS {"items":[{"id"?,"kind","file"?,"line"?,"col"?,"function"?}]}` |
| `NEXT` | none | none synchronously - see "No synchronous step acks" below |
| `STEP` | none | none synchronously |
| `CONTINUE` | none | none synchronously |
| `RETURN` | none | none synchronously |
| `BACKTRACE` | `{"full":bool}` | `BACKTRACE {"frames":[...]}` (see below) |
| `VARIABLES` | none | `VARIABLES {"vars":[...]}` (see below) |
| `SOURCES` | none | `SOURCES {"items":[{"index","file"}]}` |
| `PRINT` | `{"expr":"..."}` | `VALUE {"repr"}` or `ERROR` |
| `LINES` | `{"spec"?,"before"?,"after"?}` | `SOURCE_RANGE {"file","from","to","cursor"?}` - no source text, see "Source Resolution" |
| `THROW` | `{"type"?,"message"}` | raises the exception; no direct response |
| `DISASSEMBLE` | `{"spec"?}` | `DISASSEMBLY {"function","instructions":[...]}` |
| `SOURCE` | `{"file"}` | `SOURCE {"file","text"\|null,"error"?}` |
| `HELP` | `{"command"?}` | `HELP {"commands":[{"verb","help"}]}` |
| `QUIT` | none | terminates the debugged program (like `exit()`); no confirmation prompt - a client that wants one must ask the user itself before sending this |

`BACKTRACE` frame shape: `{"kind":"script"|"native","index","file"?,"line"?,
"col"?,"insn"?,"function"?,"module"?,"variables"?}` - `variables` is only
present when `full:true` was requested, and has the same shape as
`VARIABLES`'s `vars` array.

`VARIABLES`/backtrace-`variables` entry shape: `{"name","kind":"this"|
"local"|"internal"|"upvalue","value_repr"}` - `value_repr` is a pre-rendered
string (via the same formatter `print()`/`printf()` use) since ucode values
include closures, resources and regexes that don't round-trip through JSON;
there is no separate machine-typed `value` field.

### Server → client events

| Verb | Payload |
|---|---|
| `PAUSED` | `{"reason":"entry"\|"breakpoint"\|"step"\|"exception"\|"uncaught","file"?,"line"?,"col"?,"function"?,"breakpoint_id"?,"exception_type"?,"exception_message"?}` |
| `EVENT` | `{"event":"exception"\|"exit"\|"signal", ...}` - unsolicited, can arrive at any time (e.g. right before the process exits) |
| `ERROR` | `{"message"}` - the uniform failure shape for every command above |

### No synchronous step acks

`NEXT`/`STEP`/`CONTINUE`/`RETURN` do not get an immediate acknowledgement.
The next thing a client sees is whatever actually happens next: a new
`PAUSED` if execution hits another breakpoint/step boundary, an `EVENT`
carrying `"event":"exit"` if the program ends, or nothing further for a
while if it just keeps running. This mirrors the real control flow exactly
- there is no "done stepping" moment to report before that.

### Source resolution

The server resolves `{file, line, col}` locations from the running program's
debug info, but **never sends rendered or highlighted source text** for a
`PAUSED`/`SOURCE_RANGE`/backtrace frame - only the coordinates. A client
that wants to display source has two options:

- **It already has the file** - the common case either way debugging is
  actually done: fully locally (client and target share a filesystem, e.g.
  `-x`/`udbg <pid>` on the same box) or from a development checkout against
  a remote target (the *client*, not the target, has the real/better
  source access - think a stripped production device). Either way the
  client should try reading the file itself first, keyed by the `file`
  string from any location payload, and never needs a round-trip to the
  server for it. `udbg` does this (see `-s`/`--srcdir` below for path
  mapping when the reported path doesn't exist as-is locally).
- **It doesn't** (no local access at all) - send `SOURCE {"file":"..."}`
  and use the returned raw `text`. If the server itself has no source
  available either (running precompiled bytecode with no embedded source
  and no matching local file), `text` is `null` and `error` explains why.

`udbg` implements this as: try the exact reported path; if that fails and
`-s DIR`/`--srcdir DIR` was given, try `DIR/<basename of the reported
path>`; only then fall back to asking the server.

---

## Debugger API (`module:debug`)

| Function | Description |
|----------|-------------|
| `debug.memdump(path)` | Dump VM heap state to file for analysis |
| `debug.traceback([level])` | Get current call stack trace (structured data, not the CLI's `BACKTRACE` output) |
| `debug.sourcepos()` | Get current source position (filename, line, byte) |
| `debug.getinfo(value)` | Query internal value information |
| `debug.getlocal(level, var)` / `debug.setlocal(level, var, value)` | Get/set a local variable |
| `debug.getupval(target, var)` / `debug.setupval(target, var, value)` | Get/set an upvalue |
| `debug.debugger([target])` | Local interactive session: forks and execs `udbg --fd N` over a socketpair, then pauses (immediately, or at entry to `target` if given) |
| `debug.attach(mainfn)` | Arm `SIGUSR1`-triggered attach and break on entry to `mainfn` |
| `debug.break()` | Pause execution right here, waiting for an attach-socket client |
| `debug.breakpoint(spec[, mainfn])` | Install a breakpoint from a location spec, usable before the program starts running |
| `debug.listen([wait\|path])` | Enable remote debugging - explicit path, `SIGUSR1`-armed, or block-until-attached (see below) |

`debug.listen()` usage:

```ucode
import { listen } from 'debug';

// Arm SIGUSR1-triggered remote debugging on /tmp/ucode-debug-<pid>.sock,
// matching what -X and `udbg <pid>` expect, and keep running.
listen();

// ...or pause right here, synchronously, until a debugger attaches (or a
// 30s timeout elapses) - also arms SIGUSR1 for later, same as above.
listen(true);

// ...or bind an arbitrary, caller-chosen socket path and block
// indefinitely until a client connects on it, independent of SIGUSR1.
listen("/tmp/ucode-debug.sock");
```

This is the primary way to enable remote debugging in a host application
that embeds the ucode VM directly (uhttpd, uwsd, ...) and therefore has no
`-X` flag of its own. `debug.listen()`'s `SIGUSR1` handling is dispatched
through ucode's own `signal()` builtin (`uc_vm_signal_dispatch()`, itself
only ever called from *within* the VM's per-instruction loop) rather than
the `-X` flag's `uc_vm_break_request()`/`STATUS_BREAK` mechanism, since the
latter unwinds the *entire* C call stack back to whoever called
`uc_vm_execute()` - fine for `main.c`'s own `-X` loop, but not safe for a
host calling `uc_vm_call()` from its own request-handling code, which would
have no way to handle an unexpected `STATUS_BREAK` bubbling out of what it
thought was a normal call.

---

## `udbg` Client

`udbg` is a typed-command protocol client with ANSI source rendering (the
original interactive debugger's exact ucode/utpl syntax highlighter and
statement/header-bar styling, ported into `debug_highlight.c` - see below)
but no line-editing or history yet; that's follow-up work that can be built
against this same protocol without touching the server again.

```
udbg [-s DIR] <pid>           # SIGUSR1-attach to a running `-X` process, gdb -p style
udbg [-s DIR] <socket-path>   # connect to an explicit debug.listen(path) socket
udbg [-s DIR] --fd <n>        # use an inherited, already-connected fd (internal, used by `-x`)
```

`-s DIR`/`--srcdir DIR` gives a local directory to also look for source
files under (by basename) when the server-reported path doesn't exist
as-is on this machine - see "Source resolution" above.

Typed commands at the `dbg >` prompt map directly onto the protocol verbs
above (`break <spec>`, `delete [id]`, `list`, `next`, `step`, `continue`,
`return`, `backtrace [full]`, `variables`, `sources`, `print <expr>`,
`lines [spec] [before] [after]`, `throw [type] <message>`, `disassemble
[spec]`, `source <file>`, `help [verb]`, `quit`).

---

## Breakpoint Location Syntax

Used by `BREAK`'s `spec` field, `debug.breakpoint()`, and the `-x`/`-X`
command-line breakpoint argument:

```
path[:line[:col]]   # File and line number (path optional if a frame is active)
line[:col]          # Line in the current file (requires an active frame)
expression          # ucode expression evaluating to a function (e.g. obj.method)
(expression)        # Parens to disambiguate an expression from a bare path
```

A `path`/`line` spec resolves to the next real bytecode statement at or
after that position - breaking on a comment-only or blank line lands on the
next actual statement, not an error.

---

## Building on the Protocol: Local `-x` Wiring

`uc_debugger()` (`lib/debug.c`) does the following once, on first call:

1. `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)`.
2. `fork()`; the child `dup2(sv[1], 3)` and `execlp("udbg", "udbg", "--fd",
   "3", NULL)`.
3. The parent closes its copy of `sv[1]`, keeps `sv[0]` as the session fd
   (`debug_remote_set_active_fd()`), and proceeds exactly like the
   remote-attach case from here on.

Neither process ever manipulates the *debuggee's* own stdin/stdout for
protocol traffic - the child (client) inherits the real controlling
terminal for its own I/O, and the parent (VM) only ever reads/writes the
socketpair fd. If the client process dies or disconnects, this is treated
like a remote client dropping the connection: the script is resumed
unattended rather than left hanging.

---

## Testing

`tests/custom/99_debugger/run_debugger_tests.uc` is a standalone (non-cram)
integration suite that starts real target scripts via `ucode -X<file>:1`
(the same attach-socket mechanism `-X`/`udbg` use), connects to the
resulting PID-derived Unix domain socket with the `socket` module, sends
batches of protocol messages, and asserts on the *parsed* JSON responses
and/or the target script's own stdout - never on rendered text, since
nothing is rendered server-side. Run it directly with:

```bash
UCODE_BIN=/path/to/build/ucode ./build/ucode -L build tests/custom/99_debugger/run_debugger_tests.uc
```

Note for anyone writing new cases: a bare line-number `BREAK`/`-X` spec
against a script that is *only* variable declarations (no function calls or
other statements) is a narrow, pre-existing edge case in
`resolve_breakpoint()`/`lookup_stmt_boundary()` that doesn't always resolve
reliably - prefer `STEP` to advance past declarations, or target a function
name instead, both of which are unaffected.
