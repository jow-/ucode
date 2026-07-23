# UCode Interactive Debugger Implementation Status

## Overview

The UCode interpreter includes a fully-featured interactive command-line debugger implemented in `lib/debug.c` (~6,500 lines of code). The debugger provides source-level debugging capabilities with breakpoints, stepping, stack inspection, and runtime value evaluation.

---

## Architecture

### Core Components

#### 1. Breakpoint System (`include/ucode/types.h`)

```c
typedef struct uc_breakpoint {
    uint8_t *ip;                    // Instruction pointer where breakpoint is set
    void (*cb)(uc_vm_t *, struct uc_breakpoint *);  // Callback when hit
} uc_breakpoint_t;

uc_declare_vector(uc_breakpoints_t, uc_breakpoint_t *);
```

Breakpoints are stored in the VM structure:
```c
struct uc_vm {
    ...
    uc_breakpoints_t breakpoints;   // Active breakpoints
    ...
};
```

#### 2. Breakpoint Kinds

```c
typedef enum {
    BK_ONCE,     // Single-use breakpoint
    BK_USER,     // User-defined breakpoint
    BK_STEP,     // Internal step breakpoint
    BK_CATCH,    // Exception catch breakpoint
} debug_breakpoint_kind_t;
```

#### 3. Debug Breakpoint Structure

```c
typedef struct debug_breakpoint {
    uc_breakpoint_t bk;             // Base breakpoint
    uc_function_t *fn;              // Function containing breakpoint
    size_t depth;                   // Call stack depth
    debug_breakpoint_kind_t kind;   // Breakpoint type
} debug_breakpoint_t;
```

---

## Debugger API (module:debug)

### Functions

| Function | Description |
|----------|-------------|
| `debug.memdump(path)` | Dump VM heap state to file for analysis |
| `debug.traceback([level])` | Get current call stack trace |
| `debug.sourcepos()` | Get current source position (filename, line, byte) |
| `debug.getinfo(value)` | Query internal value information |
| `debug.getlocal(level, var)` | Get local variable value |
| `debug.setlocal(level, var, value)` | Set local variable value |
| `debug.getupval(target, var)` | Get upvalue (closure variable) |
| `debug.setupval(target, var, value)` | Set upvalue |
| `debug.debugger([target])` | Launch interactive debugger |
| `debug.attach(mainfn)` | Break on entry to `mainfn`, driven by a local terminal or the SIGUSR1 attach socket |
| `debug.break()` | Pause execution right here and launch the local terminal CLI |
| `debug.listen([wait\|path])` | Enable remote debugging (see "Remote Debugging" below) |

### Data Types

#### StackTraceEntry
```javascript
{
    callee: function,      // Called function
    this: *,               // 'this' context
    mcall: boolean,        // Method call flag
    strict: boolean,       // Strict mode flag (ucode only)
    filename: string,      // Source file
    line: number,          // Source line
    byte: number,          // Byte offset
    context: string        // Source context snippet
}
```

#### SourcePosition
```javascript
{
    filename: string,
    line: number,
    byte: number
}
```

#### UpvalRef
```javascript
{
    name: string,          // Variable name
    closed: boolean,       // Is upvalue closed?
    value: *,              // Current value
    slot: number           // Stack slot (if open)
}
```

#### ValueInformation
```javascript
{
    type: string,          // Type name
    value: *,              // The value
    tagged: boolean,       // Tagged pointer?
    mark: boolean,         // GC mark bit
    refcount: number,      // Reference count
    unsigned: boolean,     // Unsigned integer?
    address: number,       // Memory address
    length: number,        // String/array length
    count: number,         // Element count
    constant: boolean,     // Immutable?
    prototype: *,          // Prototype object
    ...
}
```

---

## Interactive Debugger Commands

### Navigation Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `next` | - | Execute next statement, step over function calls |
| `step` | - | Execute next statement, step into function calls |
| `continue` | - | Continue execution until next breakpoint |
| `return` | - | Continue until current function returns |
| `quit` | - | Terminate program execution |

### Breakpoint Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `break` | - | Set breakpoint at location |
| `delete` | - | Delete breakpoint (current or by index) |
| `list` | ls | List all breakpoints |

### Inspection Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `backtrace` | bt | Print call stack trace |
| `variables` | - | Show local variables and values |
| `print` | - | Evaluate and print expression |
| `lines` | ln | Show source code around location |
| `sources` | src | List loaded source buffers |
| `disassemble` | disasm | Disassemble function to bytecode |
| `throw` | - | Raise exception at current position |
| `help` | - | Show command help |

### Breakpoint Location Syntax

```
break <location>

Locations can be:
  - file.uc:line[:column]    # File and line number
  - line[:column]            # Line in current file
  - expression               # Function expression (e.g., obj.method)
  - (expression)             # Disambiguated expression
  - #offset                  # Instruction offset
```

### Line Display Syntax

```
lines [location] [before] [after]

Examples:
  lines              # Current location
  lines foo 5 8      # 5 lines before, 8 after function foo
  lines +0 3 3       # 3 lines before and after current
  lines -5           # 5 lines before current
  lines +3           # 3 lines after current
```

---

## Implementation Details

### Main Entry Point

The debugger is invoked via `debug.debugger()`:

```c
static uc_value_t *uc_debugger(uc_vm_t *vm, size_t nargs)
{
    // 1. Setup signal handlers (SIGINT, SIGWINCH)
    // 2. Configure terminal for raw input
    // 3. Install breakpoint at target function or current location
    // 4. Transfer control to CLI loop
}
```

### CLI Loop

```c
static void bk_enter_cli(uc_vm_t *vm, uc_breakpoint_t *bk)
{
    term_isig(false);                    // Disable signals
    print_location(vm, "Paused in ", dbk);

    while ((argc = term_getline("dbg > ", ...)) > -1) {
        // Parse command
        // Dispatch to command handler
        // Execute command callback
        // Check if should proceed
    }

    // Cleanup breakpoint if BK_ONCE
    term_isig(true);                     // Re-enable signals
}
```

### Breakpoint Callbacks

| Callback | Purpose |
|----------|---------|
| `bk_enter_cli` | Main debugger CLI entry |
| `bk_enter_function` | Step into function entry |
| `bk_leave_function` | Step at function return |
| `bk_follow_jump` | Step across jumps |
| `bk_handle_catch` | Catch exception at handler |

### Terminal Handling

The debugger implements a custom terminal interface with:

- **Raw mode input** - Direct character reading without line buffering
- **Command history** - Up to 100 commands with arrow key navigation
- **Tab completion** - Command and expression completion
- **ANSI color output** - Syntax highlighting for values and source
- **Line wrapping** - Multi-line output support
- **SIGWINCH handling** - Terminal resize detection

### Expression Evaluation

The `print` command evaluates ucode expressions in the current context:

```c
// Parses expression
// Executes in VM with current scope
// Formats result with type-aware printing
```

### Source Code Display

```c
// Resolves location to source buffer
// Retrieves line content
// Highlights current position
// Displays context lines
```

---

## Integration with VM

### Instruction Execution Hook

Breakpoints are checked in `uc_vm_decode_insn()`:

```c
uc_vm_decode_insn(uc_vm_t *vm, uc_callframe_t *frame, uc_chunk_t *chunk)
{
    uc_breakpoints_t *bks = &vm->breakpoints;

    for (size_t i = 0; i < bks->count; i++) {
        uc_breakpoint_t *bk = bks->entries[i];
        if (bk->ip == frame->ip)
            bk->cb(vm, bk);  // Invoke breakpoint handler
    }
    ...
}
```

### Signal Integration

- **SIGINT** - Invokes debugger at current location
- **SIGWINCH** - Refreshes terminal display on resize

---

## Recent Changes (from origin/debugger)

The remote branch contains 11 commits with improvements:

1. **Source position tracking simplification** - Removed redundant `prev_endpos/curr_endpos` fields
2. **Line context argument processing fix** - Improved relative line navigation
3. **Require function memory access fix** - Fixed potential invalid access in `uc_require_ucode()`
4. **Instruction format table export** - Made `uc_vm_insn_format` available for disassembly

---

## Limitations and TODO Areas

1. **Conditional breakpoints** - Not yet implemented
2. **Watch expressions** - No automatic value watching
3. **Multi-thread debugging** - Single VM focus only
4. **Source maps** - No support for transpiled code
5. **Reverse debugging** - No time-travel debugging

---

## Remote Debugging (`-X`, `udbg`)

In addition to the local interactive debugger, `ucode -X script.uc` runs the
script with break infrastructure enabled but without launching the CLI
directly. Sending `SIGUSR1` to the process (e.g. via `udbg <pid>`, which does
this automatically) makes the VM pause at the next instruction boundary and
open a Unix domain socket at `/tmp/ucode-debug-<pid>.sock`.

The same thing is available from script code via `debug.listen()`, without
needing `-X` at all - this is the primary way to enable remote debugging in
a host application that embeds the ucode VM directly (uhttpd, uwsd, ...) and
therefore has no `-X` flag of its own:

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

### Full command parity, not a reduced protocol

A client such as `udbg` connects to that socket and gets the *exact same*
interactive session as the local terminal debugger: all 16 commands (`help`,
`break`, `delete`, `list`/`ls`, `next`, `step`, `continue`, `return`,
`backtrace`/`bt`, `variables`, `sources`/`src`, `print`, `lines`/`ln`,
`throw`, `disassemble`/`disasm`, `quit`), including tab completion, arrow-key
history navigation, and the same ANSI-highlighted source/backtrace output.

This works because the interactive CLI (`term_getline`/`term_printf` in
`lib/debug.c`) only ever does plain `read()`/`write()` on `STDIN_FILENO`/
`STDOUT_FILENO` - once a client connects, the accepted socket fd is `dup2`'d
onto both for the duration of the session
(`debug_cli_run_remote_session()`), and the exact same `bk_enter_cli()`
dispatcher used locally handles it. The only tty-specific calls
(`tcgetattr`/`tcsetattr` for local raw-mode setup) are skipped for remote
sessions via a `termstate.remote` flag, since a socket has no line
discipline to configure - the remote peer is expected to put its own local
terminal into raw mode and forward bytes verbatim in both directions, which
is exactly what `udbg` does (`enable_raw_mode()` + a transparent two-way
byte pump). No real PTY is required: raw single-key reads, ANSI escape
rendering and history/tab-completion all work identically over a plain
socket once the tty ioctls are skipped.

Breakpoints set during a session (`break`, `next`, `step`) work transparently
across a `continue`: they are dispatched directly from
`uc_vm_execute_chunk()`'s per-instruction breakpoint check (see `vm.c`),
nested inside the `uc_vm_resume()` call that `debug_cli_run_remote_session()`
makes after the initial `bk_enter_cli()` call returns, so they reenter the
CLI using the very same file descriptors.

### Asynchronous push notifications

On top of the interactive session, the server can push unsolicited
notification lines at any time, prefixed with `EVENT `, so a client does not
need to poll:

- `EVENT exception <Type>: <message>` - an uncaught exception propagated to
  the top of the call stack while the program was running (e.g. after
  `continue`). The process exits after sending this.
- `EVENT signal SIGUSR1 received (already attached, ignoring)` - a second
  `SIGUSR1` arrived while a debugger client was already attached; the
  process keeps running/waiting for commands as before instead of pausing
  again.

`udbg` forwards raw bytes bidirectionally without interpreting them, so any
`EVENT ` line simply appears inline in the terminal output as soon as it
arrives.

When the client disconnects (or the 30s connect timeout elapses without a
connection), the debug server tears itself down and the script resumes
running unattended - this is the "detach" behavior.

### Safe to use from an embedding host application

`-X`'s `SIGUSR1` handling works by setting `vm->break_requested`, which
`uc_vm_execute_chunk()` checks per-instruction and, if set, unwinds the
*entire* C call stack back to whoever called `uc_vm_execute()`/
`uc_vm_resume()` by returning `STATUS_BREAK`. That is fine for `main.c`'s own
`-X` loop, which knows what to do with it, but a host application that calls
`uc_vm_call()`/`uc_vm_execute()` directly from its own request-handling code
(uhttpd, uwsd, ...) has no way to handle an unexpected `STATUS_BREAK`
bubbling out of what it thought was a normal call - it would very likely be
treated as an error and abort the request or the whole process.

`debug.listen()`'s `SIGUSR1` handling therefore does *not* use that
mechanism. Instead it registers a handler through ucode's own `signal()`
builtin, which is dispatched from `uc_vm_signal_dispatch()` - itself only
ever called from *within* `uc_vm_execute_chunk()`'s per-instruction loop,
nested inside whatever `uc_vm_call()`/`uc_vm_execute()` invocation is
currently running. It never unwinds the host's C call stack, and returns
normally, exactly like any other completed call, once the debug session
ends. See `uc_debug_listen_sigusr1_handler()` in `lib/debug.c`, which mirrors
`debug.attach()`'s existing `uc_debug_sigusr1_attach_handler()`.

This depends on the VM's signal self-pipe and dispatch machinery actually
being initialized, which normally only happens when the embedding host opts
in via `uc_parse_config_t.setup_signal_handlers`. Hosts that just call
`uc_vm_init(vm, NULL)` (uwsd, uhttpd) get that flag unset by default -
without further changes, installing a handler through `signal()` in that
case would silently end up with a `NULL`/`SIG_DFL` disposition for the
signal, **terminating the process** the next time that signal is delivered,
instead of invoking the handler. `debug_setup()` in `lib/debug.c` therefore
calls the new `uc_vm_signal_handlers_ensure()` (`vm.c`) unconditionally at
debug module load time, lazily wiring up the self-pipe and handler array
regardless of what the host originally configured - and `uc_vm_signal_dispatch()`
checks whether that pipe actually exists rather than re-checking the
original config flag, so signals raised this way get properly dispatched
too. This fixes not just `debug.listen()` but also `debug.attach()` and the
memory-dump signal handler (`UCODE_DEBUG_MEMDUMP_SIGNAL`, `SIGUSR2` by
default), which had the exact same latent crash for any host with
`setup_signal_handlers` unset.

Verified end-to-end against a real `uwsd` worker process (which embeds the
VM via `uc_vm_init(&ctx.vm, NULL)` and drives request handlers through
`uc_vm_call()` from its own uloop event loop, with no `-X` flag or CLI of
its own): a `debug.listen()`-armed handler script paused mid-request on
`SIGUSR1`, `udbg` attached and ran `backtrace`/`continue` against it,
showing the real `onBody(request=<uwsd.connection ...>, data=...)` call
stack, and the worker process resumed and remained healthy afterwards.

---

## File Structure

```
lib/debug.c        - Main debugger implementation (6,511 lines)
include/ucode/types.h - Breakpoint and VM structures
include/ucode/chunk.h - Debug variable lookup API
include/ucode/lib.h - Source context formatting API
include/ucode/program.h - Source position API
include/ucode/vm.h - VM breakpoint vector declaration
main.c             - Debugger CLI argument handling
```

---

## Usage Example

```javascript
// Start program with debugger
$ ucode -d script.uc

// Or from code:
debug.debugger();           // Launch immediately
debug.debugger(myFunc);     // Break when myFunc is called

// At debugger prompt:
dbg > break script.uc:42    # Set breakpoint
dbg > continue              # Run until breakpoint
dbg > variables             # Inspect locals
dbg > print myVar           # Evaluate expression
dbg > lines +5 -5           # Show context
dbg > backtrace             # View call stack
dbg > step                  # Step to next line
dbg > quit                  # Exit
```

---

## Testing

Debug functionality can be tested via:

1. **Integration tests** in `tests/custom/99_debugger/run_debugger_tests.uc` (45 test cases)
2. Manual testing with `-x` flag
3. Unit tests for debug API functions

### Current Test Results

```
Ran 45 tests: 17 passed, 28 failed
```

**Passing tests:**
- `delete_breakpoint` - Delete breakpoint by number
- `quit_command` - Quit debugger
- `empty_commands` - Handle empty commands
- `rapid_breakpoints` - Set multiple breakpoints quickly
- `invalid_breakpoint` - Handle invalid breakpoint syntax
- `delete_invalid` - Delete invalid breakpoint
- `print_undefined` - Print undefined variable
- `deep_recursion` - Handle deep recursion
- `large_object` - Inspect large objects
- `closure_upvalues` - Inspect closure upvalues
- `repeated_inspection` - Repeated variable inspection
- `disasm_variants` - Disassembly variants
- `mixed_frames` - Mixed frame types

**Known issues affecting tests:**
- Terminal raw mode causes input buffering issues when running from pipes
- ANSI color codes in output need stripping for text comparison
- `debug.traceback()` returns structured data (array), not formatted string

### Build and Run Tests

```bash
# Build debug version
mkdir build-debug && cd build-debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)

# Run debugger tests
./ucode -L build-debug tests/custom/99_debugger/run_debugger_tests.uc
```

---

## Known Issues and Limitations

### Current Issues

1. **Non-interactive input** - The debugger uses terminal raw mode which causes input buffering issues when reading from pipes or redirected input. For scripted testing, use `quit -f` flag to force quit without confirmation.

2. **ANSI color codes** - Output contains ANSI escape sequences for syntax highlighting. Test frameworks need to strip these codes for text comparison.

3. **debug.traceback() API** - Returns structured data (array of stack frames) rather than formatted string. Use `backtrace` CLI command for formatted output.

4. **Terminal requirements** - Requires a proper terminal (TTY) for full functionality. Features like tab completion, history, and color output may not work correctly in non-interactive environments.

### Planned Enhancements

1. **Non-interactive mode** - Add `--batch` or similar flag for scripted debugging sessions
2. **Machine-readable output** - Add JSON output format for programmatic access
3. **Remote debugging** - Add network protocol support for remote debugging
4. **Source maps** - Support for transpiled code debugging
5. **Reverse debugging** - Time-travel debugging capabilities

---

*Document generated from codebase inspection. Last updated: $(date)*
