# Teaching Frame a C project's own memory functions

`src/session.c` allocates from the project's own pool (`pool_alloc` / `pool_release`, declared in `src/pool.h`), logs through `log_message`, and stops through `fatal`. Frame knows what `malloc`, `free`, `strlen` and `exit` do, but not these. [`.frame/packs/pool.toml`](.frame/packs/pool.toml) says it in four lines, for the files that include `pool.h`:

```toml
[[function]]
name = "pool_alloc"
allocates = "heap"          # heap | stack | mapped | new | new_array

[[function]]
name = "pool_release"
frees = "heap"

[[function]]
name = "log_message"
dereferences = [0]          # reads through its first argument (-1: every argument)

[[function]]
name = "fatal"
noreturn = true
```

```console
$ frame packs check .frame/packs/pool.toml
ok   .frame/packs/pool.toml: c/pool (0 entry points, 0 rules, 4 function facts)
```

With the pack (picked up from `.frame/packs/`), the session's name is used after it went back to the pool:

```console
$ frame scan src --root .
...
1. [CRITICAL] 🔴 use_after_free
   Location: src/session.c:12:4
   Description: Use after free: 'name' was freed. SL check: emp ⊬ name |-> _
   CWE: CWE-416
...
Scanned 2 files: 1 finding (1 critical)
```

Without it (the same `src/` with no `.frame/` beside it), the release is an unknown call, so the use after free is not seen, and `session_port` reads `port` on the path where `fatal` returns, which it never does:

```console
$ frame scan src --root .
...
1. [MEDIUM] 🟡 uninitialized_var
   Location: src/session.c:23:4
   Description: Use of uninitialized variable 'port': it is read on a path where it has no reaching definition
   CWE: CWE-457
...
Scanned 2 files: 1 finding (1 medium)
```

A pack's facts apply only to the files its `detect` matches (here, those including `pool.h`). The C library's own facts are in Frame's spec tables (`frame/sil/specs/data/c.toml`); a pack adds a project's functions next to them.
