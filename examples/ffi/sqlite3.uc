// sqlite3.uc - SQLite3 FFI wrapper example
// Demonstrates FFI with complex structs, callbacks, and memory management

import * as ffi from 'ffi';

// Constants
const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_ERROR = 1;

// ============================================================================
// run - Complete SQLite3 FFI Demo
//
// Demonstrates FFI usage with SQLite3, covering: dynamic library loading,
// struct and pointer types, prepared statements, parameter binding, result
// column extraction, and error handling. Shows how persistent ctype buffers
// are required for string arguments since native ucode string memory may not
// remain valid across native calls.
//
// Steps performed:
//   1. Load sqlite3 library from system paths (tries x86_64, i386, then PATH)
//   2. Query library version info (libversion, libversion_number)
//   3. Open an in-memory database using sqlite3_open()
//   4. Create a users table with CREATE TABLE via sqlite3_exec()
//   5. Insert two rows using prepared statements with parameter binding
//      - Uses ffi.string() to create persistent char[N] ctype buffers, then
//        passes .ptr() to bind_text() so the memory outlives the call
//   6. Execute SELECT with step/column extraction via prepared statements
//   7. Demonstrate error handling with an invalid query via sqlite3_exec()
//   8. Report error details using sqlite3_errmsg() and sqlite3_errcode()
//   9. Close the database via sqlite3_close()
//
// Usage:
//   ucode examples/ffi/sqlite3.uc
//
// Dependencies: libsqlite3 installed on the system
// ============================================================================

function run() {
    print("=== SQLite3 FFI Demo ===\n");

    // Load sqlite3 library with cdefs
    print("Loading sqlite3 library...\n");
    let sqlite3lib = null;

    let cdefs = `
        typedef struct sqlite3 sqlite3;
        typedef struct sqlite3_stmt sqlite3_stmt;
        typedef void sqlite3_destructor_type;

        const char *sqlite3_libversion(void);
        int sqlite3_libversion_number(void);
        int sqlite3_open(const char *, void **);
        int sqlite3_close(void *);
        int sqlite3_exec(void *, const char *, int, int, int);
        int sqlite3_prepare_v2(void *, const char *, int, void **, const char **);
        int sqlite3_reset(void *);
        int sqlite3_finalize(void *);
        int sqlite3_step(void *);
        int sqlite3_bind_text(void *, int, const char *, int, int);
        int sqlite3_bind_int(void *, int, int);
        const unsigned char *sqlite3_column_text(void *, int);
        int sqlite3_column_int(void *, int);
        double sqlite3_column_double(void *, int);
        const char *sqlite3_errmsg(void *);
        int sqlite3_errcode(void *);
        int sqlite3_changes(void *);
    `;

    try {
        sqlite3lib = ffi.dlopen('/usr/lib/x86_64-linux-gnu/libsqlite3.so.0', false, cdefs);
    } catch (e) {
        try {
            sqlite3lib = ffi.dlopen('/usr/lib/i386-linux-gnu/libsqlite3.so.0', false, cdefs);
        } catch (e2) {
            try {
                sqlite3lib = ffi.dlopen('sqlite3', false, cdefs);
            } catch (e3) {
                sqlite3lib = null;
            }
        }
    }

    if (!sqlite3lib) {
        print("Could not load sqlite3 library. Install libsqlite3-dev to run this demo.\n");
        print("Skipping demo.\n");
        return;
    }

    print("Library loaded successfully.\n\n");

    // 1. Version info
    let version_ptr = sqlite3lib.sqlite3_libversion();
    let version = ffi.string(version_ptr);
    print("SQLite version: ", version, "\n");
    print("Version number: ", sqlite3lib.sqlite3_libversion_number(), "\n\n");

    // 2. Create in-memory database
    print("Creating in-memory database...\n");
    let db = ffi.ctype('void *', null);
    let rc = sqlite3lib.sqlite3_open(':memory:', db.ptr());
    if (rc !== SQLITE_OK)
        die("Failed to open database: error " + rc);

    // 3. Create schema
    print("Creating tables...\n");
    let createSQL = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT)";
    rc = sqlite3lib.sqlite3_exec(db, createSQL, 0, 0, 0);
    if (rc !== SQLITE_OK)
        die("Failed to create users table");

    // 4. Insert data
    print("Inserting users...\n");
    let insertSQL = "INSERT INTO users (name, email) VALUES (?, ?)";
    let stmtPtr = ffi.ctype('void *', null);
    rc = sqlite3lib.sqlite3_prepare_v2(db, insertSQL, -1, stmtPtr.ptr(), null);
    if (rc !== SQLITE_OK)
        die("Failed to prepare insert");
    let insertStmt = stmtPtr;

    // Insert Alice
    let aliceName = ffi.string('Alice');
    let aliceEmail = ffi.string('alice@example.com');
    sqlite3lib.sqlite3_bind_text(insertStmt, 1, aliceName.ptr(), -1, 0);
    sqlite3lib.sqlite3_bind_text(insertStmt, 2, aliceEmail.ptr(), -1, 0);
    rc = sqlite3lib.sqlite3_step(insertStmt);
    if (rc !== SQLITE_DONE)
        die("Insert Alice failed");

    // Insert Bob
    sqlite3lib.sqlite3_reset(insertStmt);
    let bobName = ffi.string('Bob');
    let bobEmail = ffi.string('bob@example.com');
    sqlite3lib.sqlite3_bind_text(insertStmt, 1, bobName.ptr(), -1, 0);
    sqlite3lib.sqlite3_bind_text(insertStmt, 2, bobEmail.ptr(), -1, 0);
    rc = sqlite3lib.sqlite3_step(insertStmt);
    if (rc !== SQLITE_DONE)
        die("Insert Bob failed");

    sqlite3lib.sqlite3_finalize(insertStmt);
    print("Inserted ", sqlite3lib.sqlite3_changes(db), " rows\n\n");

    // 5. Query data
    print("Querying users...\n");
    let selectSQL = "SELECT id, name, email FROM users ORDER BY id";
    rc = sqlite3lib.sqlite3_prepare_v2(db, selectSQL, -1, stmtPtr.ptr(), null);
    let selectStmt = stmtPtr;
    while (sqlite3lib.sqlite3_step(selectStmt) === SQLITE_ROW) {
        let id = sqlite3lib.sqlite3_column_int(selectStmt, 0);
        let name_ptr = sqlite3lib.sqlite3_column_text(selectStmt, 1);
        let email_ptr = sqlite3lib.sqlite3_column_text(selectStmt, 2);
        let name = ffi.string(name_ptr);
        let email = ffi.string(email_ptr);
        print("  User: ", id, " - ", name, " <", email, ">\n");
    }
    sqlite3lib.sqlite3_finalize(selectStmt);

    // 6. Error handling demo
    print("\n=== Error Handling Demo ===\n");
    rc = sqlite3lib.sqlite3_exec(db, "SELECT * FROM nonexistent_table", 0, 0, 0);
    if (rc !== SQLITE_OK) {
        let errmsg_ptr = sqlite3lib.sqlite3_errmsg(db);
        let errmsg = ffi.string(errmsg_ptr);
        print("Caught error: ", errmsg, "\n");
        print("Error code: ", sqlite3lib.sqlite3_errcode(db), "\n");
    }

    // Clean up
    sqlite3lib.sqlite3_close(db);

    print("\n=== Demo Complete ===\n");
}

// Run demo
run();
