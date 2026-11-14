# libmodsecurity3-rs

Safe Rust bindings to [libmodsecurity v3][upstream] — the engine behind
ModSecurity and the OWASP Core Rule Set.

The crate is two layers:

* `modsecurity::ffi` — hand-written declarations of the C API. The only module
  with `extern` blocks. You should not need it.
* everything else — a safe wrapper in which the compiler enforces the rules the
  C API only documents.

## Requirements

`libmodsecurity` 3.x and its headers:

```sh
# Debian / Ubuntu
sudo apt install libmodsecurity3 libmodsecurity-dev
# Fedora / RHEL
sudo dnf install mod_security libmodsecurity-devel
# macOS
brew install libmodsecurity
```

The build script links `-lmodsecurity` and honours three environment variables:

| Variable | Effect |
| --- | --- |
| `MODSECURITY_LIB_DIR` | extra library search path |
| `MODSECURITY_LIB_NAME` | link name, default `modsecurity` |
| `MODSECURITY_STATIC=1` | link statically, pulling in the C++ runtime |

## Usage

```rust
use modsecurity::{ModSecurity, Rules, Transaction};

// Once per process, shared across threads.
let mut ms = ModSecurity::new()?.with_connector_info("my-proxy/1.0")?;
ms.set_log_callback(|msg: &[u8]| {
    eprintln!("[modsec] {}", String::from_utf8_lossy(msg));
});

let mut rules = Rules::new()?;
rules.add_file("/etc/modsecurity.d/include.conf")?;

// Once per request.
let mut tx = Transaction::with_id(&ms, &rules, "req-0001")?;
tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443)?;
tx.process_uri("/search?q=%3Cscript%3E", "GET", "1.1")?;
tx.add_request_header(b"Host", b"example.com")?;

if let Some(action) = tx.process_request_headers()? {
    eprintln!("blocked: HTTP {} — {:?}", action.status, action.log_message());
}
tx.process_logging()?;
```

Each phase method returns `Ok(Some(intervention))` when a rule asked for a
disruptive action. Feed the request and response through in order
(`connection` → `uri` → request headers → request body → response headers →
response body → logging), and call `process_logging` at the end of every
transaction — that is what flushes the audit log.

There is a worked example:

```sh
cargo run --example inspect_request -- "/search?q=%3Cscript%3E"
cargo run --example inspect_request -- /index.html /etc/modsecurity.d/include.conf
```

## What the wrapper guarantees

* **Ordering.** A `Transaction` borrows the `ModSecurity` handle and the `Rules`
  set, so neither can be dropped while a transaction is alive. The
  use-after-free the C API invites is a compile error here.
* **No leaks.** Rule sets and transactions are released by `Drop`; the
  `strdup`ed strings libmodsecurity returns in interventions and parser errors
  are copied into Rust `String`s and freed immediately.
* **No aliasing.** Every call that mutates C++ state takes `&mut self`.
* **No unwinding into C++.** Log callbacks run inside `catch_unwind`.
* **Arbitrary bytes.** Header names and values are passed with explicit
  lengths, so they may hold any byte, NUL included. Arguments that must be C
  strings report interior NULs as `Error::InteriorNul` instead of panicking.

Every `unsafe` block carries a `SAFETY:` comment naming the invariant it relies
on, `unsafe_op_in_unsafe_fn` is denied crate-wide, and `unsafe` is confined to
the five modules that touch the C API: `ffi`, `intervention`, `modsecurity`,
`rules`, `transaction`. The public API exposes exactly one `unsafe` function,
`ModSecurity::shutdown`, which exists only so that a program can run the engine
destructor deliberately.

## Working around libmodsecurity

Two upstream behaviours cannot be wrapped literally without handing safe Rust a
way to corrupt memory. Both were found by the test suite in this repository,
against libmodsecurity 3.0.12.

**The engine destructor is process-global.** `~ModSecurity()` calls libxml2's
`xmlCleanupParser()`, which frees state shared by every libxml2 user in the
program. Destroying one engine while another engine, another thread, or an
unrelated XML-using crate is running is a use-after-free — reproducibly, a
`double free or corruption` abort. So this crate creates exactly one engine per
process, lazily, and never destroys it; `ModSecurity` is a cheap handle to it.
Dropping a handle is free and disturbs nothing.

Two things follow, and only matter if you hold several handles at once:
`set_connector_info` writes shared state (last call wins), while
`set_log_callback` is per handle — a transaction reports to the callback of the
handle that created it. `ModSecurity::shutdown` exists as an `unsafe` escape
hatch for programs that must satisfy a leak checker at exit.

**The SecLang parser has global state.** Parsing two rule sets concurrently
interleaves their diagnostics and corrupts the heap. `Rules` serialises
construction, parsing and destruction behind one process-wide lock. Evaluation
is untouched: concurrent request inspection against a shared rule set, the hot
path and the model upstream's own connectors use, stays lock-free.

## Logging versus interventions

libmodsecurity splits rule output in two, which is easy to misread:

| Match | Reported as |
| --- | --- |
| disruptive (`deny`, `drop`, `redirect`, …) | an `Intervention` returned by the phase method; message in `Intervention::log` |
| non-disruptive (`pass` with `log`) | the callback registered with `set_log_callback` |

A disruptive match never reaches the log callback. Handle both to see
everything.

## Known gaps

* `msc_get_response_body` is deliberately not wrapped: upstream implements it as
  `return m_responseBody.str().c_str();`, returning a pointer into a `std::string`
  temporary that is destroyed before the call returns. `Transaction::response_body_length`
  is provided; libmodsecurity v3 never rewrites a body, so the caller already
  holds the bytes it supplied. The raw declaration remains in `modsecurity::ffi`.
* `Transaction` is `Send` but not `Sync` — move it between threads freely, but
  one thread at a time, which `&mut self` on every method already enforces.

## Testing

```sh
cargo test                                          # 30 tests, no dependencies
cargo clippy --all-targets
cargo test --release -- --ignored --nocapture       # resident-memory leak check
scripts/valgrind-test.sh                            # the whole suite under Valgrind
```

`tests/integration.rs` covers the phase state machine, request and response
body inspection, interventions (deny and redirect), per-handle log callbacks,
binary header values, error reporting, panics in callbacks, and concurrent
parsing and evaluation across threads. `tests/crs.rs` then checks the whole
thing against a real rule set.

### Validating against the OWASP Core Rule Set

Hand-written rules prove the FFI plumbing; they do not prove that a production
rule set behaves correctly through it. `tests/crs.rs` loads the system CRS —
`/etc/modsecurity/crs/crs-setup.conf` plus
`/usr/share/modsecurity-crs/rules/*.conf`, as installed by Debian's and
Ubuntu's `modsecurity-crs` package — and asserts on both verdicts:

- **Blocked**, with status 403 from rule 949110, in phase 2: SQL injection in a
  query argument and in a form body, reflected XSS, local and remote file
  inclusion, OS command injection, PHP object injection, Shellshock in a
  `User-Agent`, and the sqlmap/Nikto/nmap scanner agents.
- **Blocked**, with status 403 from rule 959100, in phase 4: MySQL error text
  and PHP source leaking into a response body.
- **Allowed**: ordinary page, asset and paginated API requests, a form post and
  a JSON post — the false-positive side, which a block-only test cannot show.
- **Configuration still reaches the engine**: `SecRuleEngine DetectionOnly`
  reports through the log callback and returns no intervention, and raising
  `tx.inbound_anomaly_score_threshold` before the CRS loads lets the same
  attack through. Both are negative controls: they fail if this crate were
  blocking for some reason of its own.
- **Concurrency**: eight threads sharing one `Rules`, and four threads each
  parsing the full CRS at once.

Both paths can be pointed elsewhere with `MODSEC_CRS_SETUP` and
`MODSEC_CRS_RULES`. Where the CRS is not installed the tests report a skip and
pass; setting `MODSEC_REQUIRE_CRS=1` turns that skip into a failure, so CI
cannot pass them vacuously.

Two things worth knowing if you are wiring the CRS into a connector:

- **`owasp-crs.load` cannot be handed to the parser.** Debian's loader file
  uses Apache's `IncludeOptional`, which libmodsecurity v3's SecLang parser
  rejects outright. Include `crs-setup.conf` and the rules glob yourself.
- **`Rules::add_file` does not glob.** It opens exactly the path given;
  wildcards belong to the `Include` *directive*, so the glob goes in through
  `add_plain("Include …/rules/*.conf\n")`.
- **The CRS blocks in phase 2.** Rule 949110 evaluates the accumulated anomaly
  score after the request body, so a connector that stops at
  `process_request_headers` never sees the intervention — even for a request
  already scored past the threshold. `tests/crs.rs` asserts this explicitly so
  the behaviour is not mistaken for a bug.

Finally, the host-server directives are yours to supply. Debian ships them in
`modsecurity.conf-recommended`, which belongs to the Apache module, not to the
CRS: without `SecRuleEngine On` the rule set detects and never blocks, and
without `SecRequestBodyAccess On` phase 2 sees no body at all. `prelude()` in
`tests/crs.rs` is a working starting point.

### Memory checking with Valgrind

A safe wrapper around a C++ library is only as good as its heap discipline, so
memory correctness is checked two ways, both driven by `scripts/valgrind-test.sh`.

**From outside**, that script points cargo's test runner at
`scripts/valgrind-runner.sh`, so every test binary — not just the memory
tests — runs under Memcheck. A definite or indirect leak, an invalid access, a
double free or a read of uninitialised memory exits 99 and fails the run.
"Still reachable" is not an error: the engine is a deliberate process-wide
singleton (see above). Pass anything you like through to cargo:

```sh
scripts/valgrind-test.sh                      # everything
scripts/valgrind-test.sh --test memcheck      # just the memory tests
scripts/valgrind-test.sh -- --nocapture foo   # harness arguments after --
```

**From inside**, `tests/memcheck.rs` uses [crabgrind] to call Valgrind's
client-request interface from within the test process. That buys something an
outside-in run cannot do: it takes leak and error counts *around a specific
workload*, so one-time start-up allocations — the engine singleton included —
cancel out and whatever remains is attributable to the code under test. The
tests bracket 500 disrupted transactions, 100 transactions carrying 16 KiB
bodies, 25 rule-set build/merge/error cycles and 200 trips through the log
trampoline, and assert the delta is zero bytes.

Both layers were verified to fail, not just to pass: dropping the `free` in
`Intervention::take_cstring` makes the in-process check report
`500 disrupted transactions leaked 248955 bytes` and Valgrind exit 99, and
freeing twice there is caught as `Invalid free()` by the error-count test.

crabgrind is an **optional** dependency behind the `valgrind` feature, which
exists only to build that test target — it needs the Valgrind headers and
libclang, so plain `cargo test` neither builds nor requires it, and the library
keeps its empty dependency list. The script enables the feature itself.

Without Valgrind, every client request is a silent no-op, so the memory tests
report that they were skipped and pass. `scripts/valgrind-test.sh` sets
`MODSEC_REQUIRE_VALGRIND=1`, which turns that skip into a failure so the entry
point cannot pass vacuously.

`valgrind.supp` holds the suppressions applied to every binary. There is
exactly one: a `std::thread` handle the Rust test harness allocates for the
main thread and parks in a thread-local Memcheck cannot follow. Nothing is
suppressed for libmodsecurity — 3.0.12 reports no definite or indirect leaks
under this suite. The file carries a commented template if another platform
needs one.

`valgrind-pcre2-jit.supp` is applied to the CRS binary alone, by a one-line
branch in `scripts/valgrind-runner.sh`. libmodsecurity links libpcre2-8, whose
JIT scans subject strings with *unaligned* 16-byte vector loads: a load may
start inside the string and run past its end — never across a page boundary, so
it cannot fault — and the JIT then branches on the bytes beyond it before
masking them off. Memcheck reports both steps, from two anonymous JIT frames
with no symbols to anchor a suppression to. The entries can therefore only
match on `Memcheck:Addr16` and `Memcheck:Cond` with unsymbolised frames, which
is blunt enough that it would also hide a genuine 16-byte invalid read in this
crate — hence the per-binary scoping, which leaves every other test binary
checked at full strength. Upstream's fix is to build PCRE2 with
`--enable-valgrind`; if your distribution does, delete the file and the branch.

Under Memcheck the CRS tests shrink their thread and iteration counts — they
detect Valgrind from its `LD_PRELOAD` — which keeps the full run near a minute
instead of eight.

[crabgrind]: https://github.com/2dav/crabgrind

## Continuous integration and releasing

`.github/workflows/ci.yml` runs three test jobs on every push to `main` and
every pull request:

| Job | What it does |
| --- | --- |
| **Test (stable)** | `cargo fmt --check`, clippy with and without `--all-features` (both `-D warnings`), `cargo test --all-targets`, the doc tests, and a `cargo doc` build with the flags docs.rs will use |
| **Build (MSRV 1.85)** | `cargo check --all-targets` on the toolchain `rust-version` promises |
| **Memcheck** | `scripts/valgrind-test.sh` — every test binary under Valgrind |

System dependencies come from apt (`libmodsecurity-dev`, `modsecurity-crs`,
and Valgrind plus `libclang-dev` for the Memcheck job) and the toolchain from
the rustup already on the runner, so the pipeline uses no third-party actions.
`MODSEC_REQUIRE_CRS=1` is set for the whole workflow and the setup step checks
for the CRS files directly: a runner without the rule set fails the build
rather than quietly skipping `tests/crs.rs`.

### Cutting a release

Releases are never automatic. Start the **CI** workflow by hand from the
Actions tab and choose a level — `patch`, `minor`, `major`, `rc`, `beta` or
`alpha`. The `release` job `needs` all three test jobs, so cargo-release runs
only on a commit that has just gone green; leaving the level at `none` runs the
tests and stops. Tick **dry_run** to have cargo-release print what it would do
and change nothing.

What a real run does is set out in `release.toml`: bump the version, commit,
tag `v{version}`, push both, and publish to crates.io. Before the first one:

- Add a **`CARGO_REGISTRY_TOKEN`** repository secret, or set `publish = false`
  in `release.toml` to tag without publishing. Without it cargo-release fails
  at the publish step, *after* the commit and tag have been made.
- Give Actions write access to the repository (Settings → Actions → General →
  Workflow permissions), since the job pushes a commit and a tag.
- If `main` is protected, allow the `github-actions[bot]` push or the release
  will be rejected at the last step.
- `allow-branch = ["main"]` means a dispatch from any other branch is refused
  up front, before anything is written.

To require a human approval before publishing, add an `environment:` to the
`release` job and configure required reviewers on it.

## License

Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
<https://www.apache.org/licenses/LICENSE-2.0>), matching upstream ModSecurity.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.

[upstream]: https://github.com/owasp-modsecurity/ModSecurity
