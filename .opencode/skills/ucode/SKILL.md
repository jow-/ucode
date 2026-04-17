---
name: ucode
description: Build, test, and execute ucode programs using cmake, the ucode compiler, and the custom test suite
metadata:
  audience: developers
  workflow: development
---

## What I do

I handle the common workflows for working with the ucode scripting language project: building from source, running tests, and executing ucode with libraries.

## Build

Configure the build (run this first if CMake files changed):
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
```

Compile:
```bash
make -C build
```

## Test

Run the entire test suite:
```bash
./tests/custom/run_tests.uc
```

Run tests in a specific directory (note the trailing wildcard pattern):
```bash
./tests/custom/run_tests.uc tests/custom/17_lib_ffi/*
```

## Execute

Run a ucode snippet with a loaded library:
```bash
./build/ucode -L build -l ffi -e 'print(ffi.C.dlsym("size_t"))'
```

Key flags:
- `-L <path>` — prepend path to library search directory
- `-l <name>` — preload a library (e.g. `ffi`, `json`, `uci`)
- `-e '<expr>'` — execute an expression inline

## When to use me

Use this skill when the user wants to:
- Build or rebuild the ucode project
- Run the test suite (all or specific subdirectories)
- Execute ucode code snippets with or without loading custom libraries
- Debug ucode issues by running code interactively
