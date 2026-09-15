Metamethods let values that carry a prototype (objects, arrays and resources)
customize how the ucode interpreter handles them. A metamethod is a regular
function stored under a reserved *dunder* name on a prototype (or directly on
an instance); the interpreter looks it up and invokes it automatically when a
certain operation is performed on the value.

With metamethods, a prototype can make its instances callable, synthesize
properties that are not stored anywhere, route property writes and deletions
to a backing store, or control how the value is rendered as a string.

```
let foo = proto({}, {
	__call__(...args) { return "called with " + args; },
	__get__(key)      { return key + " is virtual"; },
	__set__(key, val) { rawset(this, key, val); },
	__delete__(key)   { return rawdelete(this, key); },
	__tostring__()    { return "<my-obj>"; },
});

foo(1, 2);          // "called with [ 1, 2 ]"
foo.missing;        // "missing is virtual"
foo.other = 42;     // routed to __set__
delete foo.ghost;   // not an own key, routed to __delete__
print(foo);         // <my-obj>
```

ucode currently supports five metamethods:

| Metamethod     | Operation customized                       |
|----------------|--------------------------------------------|
| `__call__`     | calling the value as a function            |
| `__get__`      | reading a property that is not found       |
| `__set__`      | writing a property that is not an own key  |
| `__delete__`   | deleting a property that is not an own key |
| `__tostring__` | rendering the value as a string            |

Relational and arithmetic metamethods (`__lt__`, `__eq__`, `__add__`, ...)
are not part of the language.

## Key Characteristics of Ucode Metamethods

### Metamethods Are Strict Fallbacks

A property found by the normal lookup always wins over a metamethod. Each
metamethod is consulted only when the operation cannot be completed by the
normal mechanism:

| Operation           | Normal mechanism                      | Metamethod consulted when            |
|---------------------|---------------------------------------|--------------------------------------|
| `foo.bar` (read)    | own key, then prototype chain         | key not found anywhere in the chain  |
| `foo.bar = x` (write) | direct store into `foo`             | key is not already an own key of `foo` |
| `delete foo.bar`    | direct delete from `foo`              | key is not an own key of `foo`       |
| `foo(...)` (call)   | `foo` is a function                   | `foo` is not callable at all         |
| string rendering    | type-specific formatting              | a `__tostring__` is present          |

As a consequence, giving an object a `__get__` does not re-route reads of its
existing properties through script code; only genuinely missing keys reach the
metamethod. Real properties and metamethods can coexist on the same value, and
the real ones always win. In particular, reading `foo.__get__` as a plain
property returns the function itself, so metamethods are not hidden from
inspection.

Because `__set__` only fires for keys the instance does not own, reassigning
an existing key is a fast direct store; the metamethod is bypassed. This
asymmetry is intentional and keeps property writes on plain objects free of
any overhead.

### Resolution Walks the Full Prototype Chain

The metamethod itself is found by walking the value's entire prototype chain,
from the direct prototype to the most distant one. The first hit wins.

```
let grand = { __get__(key) { return "grand:" + key; } };
let parent = proto({}, grand);
let child  = proto({}, parent);

child.x;              // "grand:x"
```

Metamethods are looked up on the prototype chain only; the value's own keys
never count. An own property with a dunder name is plain data, not a
metamethod:

```
let o = proto({}, { __get__(key) { return "parent"; } });

o.__get__ = function(key) { return "own"; };

o.x;                  // "parent" - the own property does not shadow
o.__get__;            // the function itself, readable like any property
```

This keeps dunder names inert unless a prototype explicitly defines them:
ordinary property writes (mixin loops, data copied from external sources, a
function stored under a dunder name) cannot accidentally change how a value
behaves. To customize a single instance, give it its own prototype:
`o = proto(o, { __get__(key) { ... } })`.

### Invocation Convention

All metamethods are invoked as method calls on the instance: `this` is the
instance (not the prototype), and the operation-specific arguments follow.

| Metamethod     | Invocation             | Expected return value                       |
|----------------|------------------------|---------------------------------------------|
| `__call__`     | `m.__call__(...args)`  | the result of the call                      |
| `__get__`      | `m.__get__(key)`       | the property value, or `null` for "still missing" |
| `__set__`      | `m.__set__(key, value)`| ignored; the assignment yields `value`      |
| `__delete__`   | `m.__delete__(key)`    | truthy = deleted, falsy = not present       |
| `__tostring__` | `m.__tostring__()`     | a string (non-strings fall back to default rendering) |

The *key* argument of `__get__`, `__set__` and `__delete__` is the original
key value the script used: a string for `foo.bar`, a number for `foo[0]`.
Metamethods are looked up by exact key, without any coercion.

A metamethod is only honored when it is an actual function (closure or
native function). A non-callable value stored under a dunder name is skipped
and the search continues with the next prototype:

```
let o = proto({}, { __get__: "not callable" });

o.x;                  // null, no metamethod in effect
```

### The Assignment Expression Always Yields the Assigned Value

An assignment in ucode evaluates to the value being stored (`a.x = 5` yields
`5`). When a `__set__` dispatch handles `foo.bar = x`, the interpreter pushes
`x` as the expression's value and discards whatever `__set__` returned. A
`__set__` that forgets to return, returns `null`, or returns a coerced value
still yields `x` from the assignment expression:

```
let o = proto({}, {
	__set__(key, val) {
		rawset(this, key, val * 2);
		return "ignored";
	}
});

o.x = 21;            // the expression yields 21
o.x;                 // 42
```

A `__set__` that does not want to store a value must raise an exception; the
assignment then fails with that exception.

## The `__call__` Metamethod

`__call__` makes a value invocable. It is invoked as a method on the instance
and receives the call arguments:

```
let c = proto({ base: 10 }, {
	__call__(a, b) {
		return this.base + a + b;
	}
});

c(1, 2);            // 13
```

`this` inside `__call__` is always the value being called:

```
let inner = proto({ tag: "inner" }, {
	__call__(n) { return this.tag + ":" + n; }
});

let outer = { m: inner };

outer.m(7);         // "inner:7", `this` is the `inner` value
inner("x");         // "inner:x"
```

A value which holds itself as its own `__call__` does not become callable,
since only actual functions count as metamethods:

```
let c = {};
c.__call__ = c;

c();                // error: left-hand side is not a function
```

Because the interpreter's call path itself dispatches `__call__`, callable
objects work everywhere a function is accepted, including as callbacks for
builtins:

```
let add1 = proto({}, { __call__(x) { return x + 1; } });

map([1, 2, 3], add1);  // [ 2, 3, 4 ]
```

One caveat: a `__call__` that tail-calls the same instance

```
let foo = proto({}, { __call__() { return foo(); } });
foo();
```

loops forever without tripping the interpreter's recursion limit, because the
tail call reuses the current frame. This is the same class of behavior as a
plain tail-recursive function, but the re-dispatch is implicit, so it is easy
to write by accident.

## The `__get__` Metamethod

`__get__` is consulted when a property lookup finds nothing in the instance
itself nor in its prototype chain. It is invoked as a method on the instance
with the key as its single argument, and its return value becomes the result
of the read; returning `null` means "still missing":

```
let o = proto({}, {
	__get__(key) {
		return key == "bar" ? "virtual:bar" : null;
	}
});

o.bar;              // "virtual:bar"
o.foo;              // null
```

Existing properties shadow the metamethod, both own ones and ones inherited
from the prototype chain:

```
let hits = [];

let o = proto({ own: 1 }, {
	inherited: 2,
	__get__(key) {
		push(hits, key);
		return "virtual";
	}
});

o.own;              // 1
o.inherited;        // 2
o.missing;          // "virtual"
hits;               // [ "missing" ]
```

### Delegating to a Table

If a `__get__` returns an object or an array, the interpreter delegates the
lookup to that table, exactly like Lua's `__index` tables. The delegated
lookup is a fresh read, so it may in turn dispatch a `__get__`. This is a
convenient way to share a common set of virtual properties without copying
them:

```
let base = { greeting: "hi", shared: "base", n: 1 };
let o = proto({ shared: "own" }, { __get__(key) { return base; } });

o.greeting;         // "hi"
o.shared;           // "own", real properties still win
o.n + 1;            // 2
o.nope;             // null
```

### Optional Chaining

Optional reads go through the same lookup, so `?.` yields virtual properties
too:

```
let o = proto({}, { __get__(key) { return "virtual:" + key; } });

o?.y;               // "virtual:y"
```

### Compound Assignment

A compound assignment such as `foo.bar += 1` dispatches one read and one
write of the same key, so both `__get__` and `__set__` are consulted:

```
let log = [];

let o = proto({}, {
	__get__(key) {
		push(log, "get:" + key);
		return rawget(this, "_" + key);
	},
	__set__(key, val) {
		push(log, "set:" + key + "=" + val);
		rawset(this, "_" + key, val);
	}
});

o.n += 5;
o.n *= 2;

print(log);         // [ "get:n", "set:n=5", "get:n", "set:n=10" ]
o.n;                // 10
```

If the read half raises, the write half is skipped and the exception
propagates instead of storing a value derived from a read that never
happened.

## The `__set__` Metamethod

`__set__` is consulted when a property is assigned which is not already an
own property of the object. It is invoked as a method on the instance with
the key and the value as arguments:

```
let log = [];

let o = proto({ own: 1 }, {
	__set__(key, val) {
		push(log, key + "=" + val);
		rawset(this, "backing:" + key, val);
	}
});

o.nw = 2;           // routed to __set__
o.own = 3;          // own key, direct store, no dispatch

rawget(o, "backing:nw");   // 2
o.own;                    // 3
print(log);               // [ "nw=2" ]
```

Two details are worth keeping in mind:

* Writing a key that exists on a *prototype* but not on the instance does
  dispatch `__set__`. If the metamethod wants the usual shadowing behavior
  (create an own key), it stores it with `rawset(this, key, val)`; a plain
  `this[key] = val` would re-dispatch `__set__` and recurse (see
  [Raw Accessors](#raw-accessors)).
* Object literals store their members without dispatching `__set__`, so a
  literal may define the metamethod it is protected by:

```
let o = {
	__set__(key, val) {
		die("intercepted " + key);
	},
	a: 1,
	b: null
};

o.a;                // 1, the literal construction did not dispatch
```

A `null` value is stored and read back like any other value.

## The `__delete__` Metamethod

`__delete__` is consulted when `delete` is applied to a key the instance does
not own. It is invoked as a method on the instance with the key as its single
argument; a truthy return value means "deleted", a falsy one means "not
present":

```
let log = [];

let o = proto({ stored: 1 }, {
	__delete__(key) {
		push(log, key);
		return rawdelete(this, key);
	}
});

delete o.stored;     // own key, direct delete, no dispatch
delete o.ghost;      // not an own key, routed to __delete__

print(log);            // [ "ghost" ]
```

Deleting an own key never dispatches; it is a direct delete. `delete` on
arrays is not supported (it raises "left-hand side expression is not an
array or object"), so `__delete__` never fires for array elements.

## The `__tostring__` Metamethod

`__tostring__` controls how the value is rendered by `print()`, string
concatenation and the `%s`/`%J` format specifiers. It is invoked as a method
on the value with no arguments and must return a string:

```
let o = proto({}, {
	__tostring__() { return "<my-obj>"; }
});

print(o);           // <my-obj>
"[" + o + "]";      // [<my-obj>]
printf("%s\n", o);  // <my-obj>
printf("%.J\n", o); // "<my-obj>"
```

The legacy `tostring` name is still honored as an alias; `__tostring__` wins
when both are present. Both are now resolved by walking the full prototype
chain, so a `tostring` on a grandparent prototype works as well.

A broken `__tostring__` never makes `print()` fail: a non-callable method, a
call exception, or a non-string result all fall back to the default
rendering.

## Metamethods on Arrays

Arrays keep their dense storage: a key which is a valid numeric index never
dispatches a metamethod at all, whether the element exists or not. Only keys
which are no valid index (such as `1.5`, `"abc"` or any other non-numeric
name) are passed to `__get__` and `__set__`:

```
let log = [];
let store = {};

let a = proto([1, 2], {
	__get__(key) {
		push(log, "get:" + key);
		return rawget(store, key);
	},
	__set__(key, val) {
		push(log, "set:" + key);
		rawset(store, key, val);
	}
});

a[2] = 3;           // raw index store, no __set__
a[-1] = 4;          // raw index store, no __set__
a[9];               // null, raw index read, no __get__
a.name = "stored";  // __set__("name", "stored")
a.name;             // "stored", via __get__ from the backing store

print(log);         // [ "set:name", "get:name" ]
```

Note that the named fields cannot live on the array itself: `rawset()` on an
array only accepts index keys, so a `__set__` on an array must route its
values to some other storage, such as a plain object kept as a backing store
(closures capture it, as above).

This keeps integer-indexed access a fast O(1) slot read and reserves
`__get__`/`__set__` for the "array as a named-field container" case. Sparse
or numeric virtual properties are not supported on arrays; use an object for
that.

The array builtins `push()`, `unshift()`, `pop()`, `shift()` and `splice()`
are bulk structural operations and do not dispatch metamethods either.

## The `in` Operator

The `in` operator tests keys and never dispatches metamethods. For objects it
walks the full prototype chain:

```
let o = proto({ own: 1 }, {
	inherited: 2,
	__get__(key) { return "virtual"; }
});

"own" in o;         // true
"inherited" in o;   // true
"virtual" in o;     // false, purely-virtual properties are invisible to `in`
"__get__" in o;     // true, metamethods are stored properties
```

For arrays, `in` tests element values first and keys of the prototype chain
second:

```
let a = proto([1, 2], { named: 3 });

1 in a;             // true, element
"named" in a;       // true, prototype key
3 in a;             // false
```

A property that exists only as a virtual one (synthesized by `__get__` from
nothing) is not visible to `in`.

## Raw Accessors

A metamethod that re-enters the very operation it customizes re-dispatches
itself. There is no re-entrancy guard: such recursion continues until the
interpreter's call depth limit is exceeded, which raises "Too much recursion"
instead of hanging:

```
let o = proto({}, { __get__(key) { return this[key]; } });

o.x;                // error: Too much recursion
```

The escape hatch is the pair of *raw accessors*, which perform the underlying
read, write or delete without dispatching any metamethod. They are exposed to
scripts as the builtins `rawget()`, `rawset()` and `rawdelete()`:

#### {@link module:core#rawget|rawget(obj, key)} → {*}

Reads the property the way the interpreter would if `obj` had no `__get__` in
its prototype chain (array index, resource type-proto, or object own key plus
prototype chain), without dispatching `__get__`. Returns `null` if the
property is not present.

#### {@link module:core#rawset|rawset(obj, key, val)} → {*}

Stores the property the way the interpreter would if `obj` had no `__set__`
in its prototype chain (own-key store for objects, index store for arrays),
without dispatching `__set__`. Returns the stored value, or `null` on failure
(such as a non-container `obj` or a non-index key on an array).

#### {@link module:core#rawdelete|rawdelete(obj, key)} → {boolean}

Deletes the own property the way the interpreter would if `obj` had no
`__delete__` in its prototype chain, without dispatching `__delete__`.
Returns `true` if a property was deleted, `false` otherwise.

With the raw accessors, a metamethod can keep its backing store in the
instance itself, which is the idiomatic pattern for all three:

```
let o = proto({}, {
	__get__(key) {
		let v = rawget(this, "_" + key);
		return v === null ? "computed:" + key : v;
	},
	__set__(key, val) {
		rawset(this, "_" + key, val * 10);
	},
	__delete__(key) {
		return rawdelete(this, "_" + key);
	}
});

o.n = 4;
o.n;                // 40
o.other;            // "computed:other"
delete o.n;         // true
```

Nested dispatch on *different* keys is unrestricted and a normal, useful
pattern: a `__get__("a")` that reads `this.b` and triggers `__get__("b")`
simply recurses one frame deeper and returns.

## Exceptions and Recursion

Exceptions raised by a metamethod fail the operation and propagate to its
caller, for reads, writes and deletes alike, leaving the interpreter fully
usable afterwards:

```
let o = proto({}, {
	__get__(key)      { die("get:" + key); },
	__set__(key, val) { die("set:" + key); },
	__delete__(key)   { die("del:" + key); }
});

try { o.a; }             catch (e) { print(e); }   // get:a
try { o.a = 1; }         catch (e) { print(e); }   // set:a
try { delete o.a; }      catch (e) { print(e); }   // del:a
try { o.a += 1; }        catch (e) { print(e); }   // get:a
```

A metamethod that recurses too deeply fails with "Too much recursion", which
unwinds the dispatch and surfaces as the operation's error rather than
looping forever. Rendering a value while its own `__tostring__` is running
falls back to the default rendering instead of re-dispatching.

## Summary

| Case                                            | Outcome                                      |
|-------------------------------------------------|----------------------------------------------|
| `foo.bar` where `bar` is own or inherited       | normal value, `__get__` not consulted        |
| `foo.bar` missing, `__get__` set                | `__get__("bar")` result, `this` = `foo`      |
| `__get__` returns `null`                        | `null`, indistinguishable from not found     |
| `__get__` returns an object or array            | the lookup is delegated to that table        |
| `foo.bar = x`, `bar` an own key                 | direct store, `__set__` not consulted        |
| `foo.bar = x`, `bar` inherited or missing       | `__set__("bar", x)`, `this` = `foo`          |
| `foo.bar = x` again after the first write       | direct store, `__set__` bypassed             |
| `__set__` return value                          | ignored, the expression yields `x`           |
| `delete foo.bar`, `bar` an own key              | direct delete                                |
| `delete foo.bar`, `bar` not own                 | `__delete__("bar")`, truthy ⇒ `true`         |
| `foo(...)` where `foo` is a function            | normal call, `__call__` not consulted        |
| `foo(...)` where `foo` has `__call__`           | `__call__(...)`, `this` = `foo`              |
| `print(foo)` with `__tostring__`                | `__tostring__()` result                      |
| `print(foo)` with legacy `tostring`             | still works (alias)                          |
| `arr[i] = x`, `arr[i]`, `delete arr[i]`         | raw index store/read; delete is not supported |
| `arr["name"] = x`, `arr["name"]`                | `__set__("name", x)` / `__get__("name")`     |
| `x in foo`                                      | key/element test, never dispatches           |
| `rawget`/`rawset`/`rawdelete`                   | storage access without dispatch              |
