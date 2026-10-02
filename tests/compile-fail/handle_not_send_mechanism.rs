// Test 18 — the `!Send` MECHANISM, proved on local mirror types.
//
// This is the first half of the two-test split. It answers: "does
// `PhantomData<*const ()>` actually make a type `!Send`, and would a `usize`-only
// type silently be `Send`?"
//
// It uses LOCAL mirror types, not the real `LockHandle`, so it is immune to a
// refactor of `LockHandle`'s internals: the language property it demonstrates is
// independent of how `LockHandle` is built today. Test 19 is the half that
// couples to the real type.
//
// Assertion: this file must FAIL to compile — specifically on the `Marked` case
// below. The `Unmarked` case must COMPILE, which is what makes this file
// discriminating: it shows the two types differ, rather than that the bound is
// simply unsatisfiable for anything.

use std::marker::PhantomData;

/// Mirrors a naive handle: fields are all `usize`, so it is `Send` automatically.
struct Unmarked {
    base: usize,
    len: usize,
}

/// Mirrors the real handle: same fields, plus the `!Send` marker.
struct Marked {
    base: usize,
    len: usize,
    _not_send: PhantomData<*const ()>,
}

fn assert_send<T: Send>(_: &T) {}

fn main() {
    let unmarked = Unmarked { base: 0, len: 1 };
    // COMPILES — proving the naive form IS `Send`, which is why the marker is
    // required rather than optional. If this line failed, the test below would
    // prove nothing: it would be showing that no handle is ever `Send`.
    assert_send(&unmarked);

    let marked = Marked {
        base: 0,
        len: 1,
        _not_send: PhantomData,
    };
    // ERROR: `*const ()` is not `Send`, so `Marked` is not `Send`.
    assert_send(&marked);
}
