# Attribution and License

## Original Work

This project is based on **LuaJIT**, created by Mike Pall. The FFI
(Foreign Function Interface) implementation in LuaJIT is a sophisticated
system for calling C functions and working with C data types from Lua
code.

## License

LuaJIT is released under the MIT license. The original LuaJIT license text:

```
Copyright (C) 2005-2025 Mike Pall

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Implementation

The ucode FFI module (currently called `ffi`) is **heavily inspired**
by LuaJIT's FFI implementation. In many cases, the code structure,
algorithms, and even specific implementations have been taken
**verbatim** from LuaJIT's source code, with necessary adaptations
to work with the ucode virtual machine.

### What Has Been Taken from LuaJIT

- **C Parser** (`lj_cparse.c`): The frontend for parsing C declarations
- **Type System** (`lj_ctype.c`): The CTState registry and
  CType representations
- **Value Conversions** (`lj_cconv.c`): The machinery for converting
  between ucode and C values
- **C Data Objects** (`lj_cdata.c`): Allocation and access
  to C data objects

### What Has Been Changed

- LuaJIT's own call infrastructure (`lj_ccall.c`, `lj_ccallback.c`)
  has been replaced with **libffi** exclusively
- LuaJIT's arithmetic operations (`lj_carith.c`) have been removed
- Library loading logic has been consolidated into the main FFI module
- All VM interactions have been adapted to use ucode's API
  (`uc_vm_t *`, `uc_vm_raise_exception()`, etc.)
- JIT-specific code and dependencies have been removed

## Acknowledgment

Mike Pall and the LuaJIT community created the FFI implementation that
inspired this work. The LuaJIT FFI provided the C parser concept and
code structure that was adapted for ucode.

This project does not aim to provide native machine code generation or
JIT compilation. It is essentially libffi with the C parser functionality
bolted on top, providing a seamless usage experience similar to LuaJIT's
FFI interface.

## Transparency

This project maintains this attribution file to be completely
transparent about its origins. Any code that resembles LuaJIT's
implementation is either:

1. Directly adapted from LuaJIT's source code (with proper attribution
   in comments where applicable)
2. Reimplemented based on the same design principles and algorithms

All modifications are intended to integrate with ucode and remove
dependencies on LuaJIT-specific infrastructure.

---

**Last updated:** 2026-04-06