# ffi - LibFFI-based FFI Module for ucode

A Foreign Function Interface (FFI) module for the ucode scripting language,
providing seamless integration with C libraries through a LuaJIT-inspired API.

## Features

- **C Declaration Parsing** - Parse C type declarations at runtime
- **LibFFI Integration** - Call C functions using libffi for all platform ABI handling
- **C Data Objects** - Create and manipulate C structs, arrays, and primitives
- **Function Wrapping** - Wrap C function pointers into callable ucode functions
- **Type Information** - Query sizeof, alignof, and offsetof at runtime

## Usage

```javascript
import * as ffi from 'ffi';

// Declare C types and functions
ffi.cdef(`
    size_t strlen(const char *);
    int strcmp(const char *, const char *);
`);

// Wrap and call C functions
let strlen = ffi.C.wrap('size_t strlen(const char *)');
let result = strlen("hello").get();  // => 5

// Create C data instances
ffi.cdef('struct point { int x; int y; };');
let p = ffi.ctype('struct point', 10, 20);
print(p.get('x'), p.get('y'));  // => 10 20

// Query type information
print(ffi.sizeof('int'));      // => 4
print(ffi.alignof('double'));  // => 8

// Load external libraries
let libc = ffi.dlopen('c');
let atoi = libc.wrap('int atoi(const char *)');
print(atoi("42").get());  // => 42
```

## API Reference

See the inline documentation in [ffi.c](ffi.c) for the complete API reference.

## Attribution

This project contains code derived from **LuaJIT**, created by Mike Pall.
The FFI implementation is adapted from LuaJIT's FFI system.

### Copyright Notice

- **LuaJIT FFI Code**: Copyright (C) 2005-2025 Mike Pall
- **ucode Integration**: Copyright (C) 2023-2026 Jo-Philipp Wich

This project is released under the ISC License. See [LICENSE](../../LICENSE) for details.

For complete attribution information, see:
- [NOTICE](NOTICE) - Third-party dependencies and licensing
- [ATTRIBUTION.md](ATTRIBUTION.md) - Detailed attribution and modifications

### Key Modifications from LuaJIT

- LuaJIT's own call infrastructure replaced with **libffi exclusively**
- Adapted VM interactions to use **ucode's API** instead of LuaJIT's
- Removed JIT-specific code and dependencies
- Consolidated library loading logic

This project adapted the C parser concept from LuaJIT FFI but does not
aim to provide native machine code generation or JIT compilation. It is
essentially libffi with the C parser functionality bolted on top for a
seamless usage experience.

## Resources

- ucode Homepage: https://ucode.mein.io/
- ucode Repository: https://github.com/jow-/ucode
- LuaJIT: https://luajit.org/
- libffi: https://github.com/libffi/libffi
