// sqlite3.uc - SQLite3 FFI wrapper example
// Demonstrates FFI with complex structs, callbacks, and memory management

import * as ffi from 'ffi';

// C type declarations
ffi.cdef(`
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
`);

// Constants
const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_ERROR = 1;

// ============================================================================
// Demo Function
// ============================================================================

function run() {
    print("=== SQLite3 FFI Demo ===\n");

    // Load sqlite3 library
    print("Loading sqlite3 library...\n");
    let sqlite3lib = null;

    try {
        sqlite3lib = ffi.dlopen('/usr/lib/x86_64-linux-gnu/libsqlite3.so.0');
    } catch (e) {
        try {
            sqlite3lib = ffi.dlopen('/usr/lib/i386-linux-gnu/libsqlite3.so.0');
        } catch (e2) {
            try {
                sqlite3lib = ffi.dlopen('sqlite3');
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

    // Wrap sqlite3 functions - use void * for opaque pointers
    let sqlite3_libversion = sqlite3lib.wrap('sqlite3_libversion');
    let sqlite3_libversion_number = sqlite3lib.wrap('sqlite3_libversion_number');
    let sqlite3_open = sqlite3lib.wrap('sqlite3_open');
    let sqlite3_close = sqlite3lib.wrap('sqlite3_close');
    let sqlite3_exec = sqlite3lib.wrap('sqlite3_exec');
    let sqlite3_prepare_v2 = sqlite3lib.wrap('sqlite3_prepare_v2');
    let sqlite3_reset = sqlite3lib.wrap('sqlite3_reset');
    let sqlite3_finalize = sqlite3lib.wrap('sqlite3_finalize');
    let sqlite3_step = sqlite3lib.wrap('sqlite3_step');
    let sqlite3_bind_text = sqlite3lib.wrap('sqlite3_bind_text');
    let sqlite3_bind_int = sqlite3lib.wrap('sqlite3_bind_int');
    let sqlite3_column_text = sqlite3lib.wrap('sqlite3_column_text');
    let sqlite3_column_int = sqlite3lib.wrap('sqlite3_column_int');
    let sqlite3_column_double = sqlite3lib.wrap('sqlite3_column_double');
    let sqlite3_errmsg = sqlite3lib.wrap('sqlite3_errmsg');
    let sqlite3_errcode = sqlite3lib.wrap('sqlite3_errcode');
    let sqlite3_changes = sqlite3lib.wrap('sqlite3_changes');

    // 1. Version info
    let version_ptr = sqlite3_libversion();
    let version = ffi.string(version_ptr);
    print("SQLite version: ", version, "\n");
    print("Version number: ", sqlite3_libversion_number(), "\n\n");

    // 2. Create in-memory database
    print("Creating in-memory database...\n");
    let db = ffi.ctype('void *', null);
    let rc = sqlite3_open(':memory:', db.ptr());
    if (rc !== SQLITE_OK)
        die("Failed to open database: error " + rc);

    // 3. Create schema
    print("Creating tables...\n");
    let createSQL = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT)";
    rc = sqlite3_exec(db, createSQL, 0, 0, 0);
    if (rc !== SQLITE_OK)
        die("Failed to create users table");

    // 4. Insert data
    print("Inserting users...\n");
    let insertSQL = "INSERT INTO users (name, email) VALUES (?, ?)";
    let stmtPtr = ffi.ctype('void *', null);
    rc = sqlite3_prepare_v2(db, insertSQL, -1, stmtPtr.ptr(), null);
    if (rc !== SQLITE_OK)
        die("Failed to prepare insert");
    let insertStmt = stmtPtr;

    // Insert Alice
    let aliceName = ffi.string('Alice');
    let aliceEmail = ffi.string('alice@example.com');
    sqlite3_bind_text(insertStmt, 1, aliceName.ptr(), -1, 0);
    sqlite3_bind_text(insertStmt, 2, aliceEmail.ptr(), -1, 0);
    rc = sqlite3_step(insertStmt);
    if (rc !== SQLITE_DONE)
        die("Insert Alice failed");

    // Insert Bob
    sqlite3_reset(insertStmt);
    let bobName = ffi.string('Bob');
    let bobEmail = ffi.string('bob@example.com');
    sqlite3_bind_text(insertStmt, 1, bobName.ptr(), -1, 0);
    sqlite3_bind_text(insertStmt, 2, bobEmail.ptr(), -1, 0);
    rc = sqlite3_step(insertStmt);
    if (rc !== SQLITE_DONE)
        die("Insert Bob failed");

    sqlite3_finalize(insertStmt);
    print("Inserted ", sqlite3_changes(db), " rows\n\n");

    // 5. Query data
    print("Querying users...\n");
    let selectSQL = "SELECT id, name, email FROM users ORDER BY id";
    rc = sqlite3_prepare_v2(db, selectSQL, -1, stmtPtr.ptr(), null);
    let selectStmt = stmtPtr;
    while (sqlite3_step(selectStmt) === SQLITE_ROW) {
        let id = sqlite3_column_int(selectStmt, 0);
        let name_ptr = sqlite3_column_text(selectStmt, 1);
        let email_ptr = sqlite3_column_text(selectStmt, 2);
        let name = ffi.string(name_ptr);
        let email = ffi.string(email_ptr);
        print("  User: ", id, " - ", name, " <", email, ">\n");
    }
    sqlite3_finalize(selectStmt);

    // 6. Error handling demo
    print("\n=== Error Handling Demo ===\n");
    rc = sqlite3_exec(db, "SELECT * FROM nonexistent_table", 0, 0, 0);
    if (rc !== SQLITE_OK) {
        let errmsg_ptr = sqlite3_errmsg(db);
        let errmsg = ffi.string(errmsg_ptr);
        print("Caught error: ", errmsg, "\n");
        print("Error code: ", sqlite3_errcode(db), "\n");
    }

    // Clean up
    sqlite3_close(db);

    print("\n=== Demo Complete ===\n");
}

// Run demo
run();
