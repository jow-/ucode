// helpers.uc - Common utilities for FFI examples

import * as ffi from 'ffi';

export let stringToBytes = function(str) {
    let len = length(str);
    let arr = ffi.ctype('char[' + (len + 1) + ']');
    ffi.copy(arr.ptr(), str, len + 1);
    return arr;
};

export let cstr = function(str) {
    return ffi.ctype('const char *', stringToBytes(str));
};

export let createBuffer = function(size) {
    let buf = ffi.ctype('char[' + size + ']');
    ffi.fill(buf, size, 0);
    return buf;
};

export let checkCode = function(code, expected, message) {
    if (code !== expected)
        die(message + ": error code " + code);
};
