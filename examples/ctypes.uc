const c = require("ctypes");
const struct = require("struct");

const sizeof = (abbreviation) => length(struct.pack(abbreviation));

const abbreviation_to_ffi = {
  i: c.ffi_type.sint,
  P: c.ffi_type.pointer,
  N: c.ffi_type["uint" + sizeof("N") * 8],
};

function attach(dl_handle, fun) {
  const params_list = split(fun.params, "");
  const cif = c.prep(
    c.const.FFI_DEFAULT_ABI,
    ...map(params_list, (a) => abbreviation_to_ffi[a])
  );
  return function (...args) {
    const packed = struct.pack(fun.params, 0, ...args);
    const return_buffer = c.ptr(packed);
    const s = c.symbol(dl_handle, fun.name);
    assert(s != null);
    assert(cif.call(s, return_buffer));
    return struct.unpack(
      substr(fun.params, 0, 1),
      return_buffer.ucv_string_new()
    )[0];
  };
}

const libc = {};
for (fun in [
  { name: "dlopen", params: "PPi" },
  { name: "strlen", params: "NP" },
]) {
  libc[fun.name] = attach(c.const.RTLD_DEFAULT, fun);
}

function dlopen(library_name) {
  const library_name_copy = c.ptr(library_name);
  const return_ptr = libc.dlopen(library_name_copy.as_int(), c.const.RTLD_NOW);
  assert(library_name_copy.drop());
  assert(return_ptr != 0);
  return c.ptr(return_ptr);
}

const c_sqlite_version = attach(dlopen("libsqlite3.so.0"), {
  name: "sqlite3_libversion",
  params: "P",
});
function sqlite_version() {
  const return_ptr = c_sqlite_version();
  const len = libc.strlen(return_ptr);
  return c.ptr(return_ptr).ucv_string_new(len);
}

print("sqlite version: ", sqlite_version(), "\n");
