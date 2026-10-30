//! `kaspa-redteam serve`: the web page. People drop a `.sil` file in a browser
//! and get the same report the command line gives, without installing anything.
//!
//! Every scan runs as a separate child process of this same binary (the
//! ordinary `kaspa-redteam <file> --json` command) in a fresh temporary folder,
//! with a wall-clock limit and a memory limit, and the folder is deleted when
//! it ends. Uploaded contracts are never kept, logged or sent anywhere.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PAGE: &str = include_str!("web/index.html");
/// Link-preview card (Open Graph / X), 1200x630.
const OG_IMAGE: &[u8] = include_bytes!("web/og.png");
struct Example {
    slug: &'static str,
    title: &'static str,
    blurb: &'static str,
    /// What is wrong with the broken version, in plain words.
    bug: &'static str,
    /// What the fixed version changes.
    fix: &'static str,
    broken: &'static str,
    fixed: Option<&'static str>,
}

/// The examples the page offers: one per kind of bug. The rest of `examples/`
/// stays in the repo.
const EXAMPLES: &[Example] = &[
    Example {
        slug: "htlc_swap",
        title: "Atomic swap",
        blurb: "A coin unlocked by a secret, or refunded after a timeout.",
        bug: "the secret alone unlocks the coin. When the rightful claimer reveals it, anyone watching the network can copy it and take the coin first.",
        fix: "the claimer must also sign, so a copied secret is useless to anyone else.",
        broken: include_str!("../../../examples/htlc_swap_FAIL.sil"),
        fixed: Some(include_str!("../../../examples/htlc_swap_PASS.sil")),
    },
    Example {
        slug: "last_will",
        title: "Inheritance",
        blurb: "Goes to the heir after a long silence from the owner.",
        bug: "after the waiting period anyone can trigger the payout, and nothing says it has to go to the heir. The first person to try can send it to themselves.",
        fix: "the payout can only go to the heir.",
        broken: include_str!("../../../examples/last_will_FAIL.sil"),
        fixed: Some(include_str!("../../../examples/last_will_PASS.sil")),
    },
    Example {
        slug: "escrow",
        title: "Escrow",
        blurb: "A buyer, a seller and an arbiter who settles disputes.",
        bug: "the arbiter's signature is checked against a key the caller supplies, so anyone can sign as the arbiter and settle the dispute in their own favor.",
        fix: "the arbiter is the key fixed when the escrow was created, and can only pay the buyer or the seller.",
        broken: include_str!("../../../examples/escrow_FAIL.sil"),
        fixed: Some(include_str!("../../../examples/escrow_PASS.sil")),
    },
    Example {
        slug: "name_registry",
        title: "Name registry",
        blurb: "One coin per name; the owner is recorded inside the coin.",
        bug: "anyone can move the coin and record themselves as the new owner. There is no check that the current owner agreed.",
        fix: "only the current owner's signature can hand the name on.",
        broken: include_str!("../../../examples/name_registry_FAIL.sil"),
        fixed: Some(include_str!("../../../examples/name_registry_PASS.sil")),
    },
    Example {
        slug: "leaky_vault",
        title: "Leaky vault",
        blurb: "Every classic covenant bug in one file.",
        bug: "eight paths, each with a different classic bug: optional signatures, keys chosen by the caller, unpinned payouts, shared inputs and more.",
        fix: "",
        broken: include_str!("../../../examples/leaky_vault_FAIL.sil"),
        fixed: None,
    },
];
const MAX_BODY: usize = 1 << 20; // 1 MiB: a contract plus a baseline file
const MAX_SOURCE: usize = 256 * 1024;
const MAX_FILES: usize = 8;
const MAX_ARGS: usize = 32;

pub struct ServeOptions {
    pub bind: String,
    pub port: u16,
    /// Scans that may run at once; more get "busy, try again".
    pub jobs: usize,
    /// Seconds before a scan is stopped.
    pub timeout: u64,
    /// Worker threads per scan.
    pub threads: usize,
}

struct Shared {
    opts: ServeOptions,
    running: Mutex<Vec<IpAddr>>,
    counter: AtomicU64,
    exe: PathBuf,
}

pub fn serve(opts: ServeOptions) -> Result<()> {
    let addr = format!("{}:{}", opts.bind, opts.port);
    let server = tiny_http::Server::http(&addr).map_err(|e| anyhow::anyhow!("listen on {addr}: {e}"))?;
    let exe = std::env::current_exe().context("find this program's own path")?;
    eprintln!(
        "kaspa-redteam web page on http://{addr}  ({} scan(s) at once, {} s limit each)",
        opts.jobs, opts.timeout
    );
    let shared = Arc::new(Shared { opts, running: Mutex::new(Vec::new()), counter: AtomicU64::new(0), exe });
    for req in server.incoming_requests() {
        let shared = shared.clone();
        std::thread::spawn(move || handle(req, &shared));
    }
    Ok(())
}

fn respond(req: tiny_http::Request, status: u16, ctype: &str, body: impl Into<Vec<u8>>) {
    let header = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("ascii header");
    let resp = tiny_http::Response::from_data(body.into())
        .with_status_code(status)
        .with_header(header("Content-Type", ctype))
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("Referrer-Policy", "no-referrer"));
    let _ = req.respond(resp);
}

fn respond_json(req: tiny_http::Request, status: u16, v: &Value) {
    respond(req, status, "application/json; charset=utf-8", v.to_string());
}

/// `https://host` the request was made to (plain `http` only for a local address).
fn origin(req: &tiny_http::Request) -> String {
    let mut host = String::from("localhost");
    let mut proto = None;
    for h in req.headers() {
        match h.field.as_str().as_str().to_ascii_lowercase().as_str() {
            "host" => host = h.value.as_str().to_string(),
            "x-forwarded-proto" => proto = Some(h.value.as_str().to_string()),
            _ => {}
        }
    }
    let host: String =
        host.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')).collect();
    let local = host.starts_with("localhost") || host.starts_with("127.") || host.starts_with('[');
    let scheme = proto
        .filter(|p| p == "http" || p == "https")
        .unwrap_or_else(|| if local { "http".into() } else { "https".into() });
    format!("{scheme}://{host}")
}

/// Who is asking: the socket address, or the proxy's header when the request
/// came through a reverse proxy on this machine.
fn client_ip(req: &tiny_http::Request) -> IpAddr {
    let peer = req.remote_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
    if !peer.is_loopback() {
        return peer;
    }
    for h in req.headers() {
        let name = h.field.as_str().as_str().to_ascii_lowercase();
        if name == "x-real-ip" || name == "x-forwarded-for" {
            if let Some(ip) = h.value.as_str().split(',').next().and_then(|s| s.trim().parse().ok()) {
                return ip;
            }
        }
    }
    peer
}

fn handle(mut req: tiny_http::Request, s: &Shared) {
    let url = req.url().split('?').next().unwrap_or("/").to_string();
    // HEAD is answered like GET (link-preview crawlers often ask HEAD first); the body is dropped.
    let method = match req.method() {
        tiny_http::Method::Head => tiny_http::Method::Get,
        m => m.clone(),
    };
    match (&method, url.as_str()) {
        (&tiny_http::Method::Get, "/") | (&tiny_http::Method::Get, "/index.html") => {
            // Link previews need absolute URLs: build them from the host the page was asked for.
            let page = PAGE.replace("%ORIGIN%", &origin(&req));
            respond(req, 200, "text/html; charset=utf-8", page)
        }
        (&tiny_http::Method::Get, "/og.png") => {
            let header =
                |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("ascii header");
            let resp = tiny_http::Response::from_data(OG_IMAGE.to_vec())
                .with_header(header("Content-Type", "image/png"))
                .with_header(header("Cache-Control", "public, max-age=86400"));
            let _ = req.respond(resp);
        }
        (&tiny_http::Method::Get, "/api/examples") => {
            let list: Vec<Value> = EXAMPLES
                .iter()
                .map(|e| {
                    json!({
                        "slug": e.slug,
                        "title": e.title,
                        "blurb": e.blurb,
                        "bug": e.bug,
                        "fix": e.fix,
                        "broken": { "filename": format!("{}_FAIL.sil", e.slug), "source": e.broken },
                        "fixed": e.fixed.map(|s| json!({ "filename": format!("{}_PASS.sil", e.slug), "source": s })),
                    })
                })
                .collect();
            respond_json(req, 200, &json!({ "examples": list }))
        }
        (&tiny_http::Method::Get, "/api/example") => {
            let e = EXAMPLES.iter().find(|e| e.slug == "leaky_vault").expect("built in");
            respond_json(req, 200, &json!({ "filename": "leaky_vault_FAIL.sil", "source": e.broken }))
        }
        (&tiny_http::Method::Get, "/api/library") => {
            let mut rows: Vec<&'static redteam_core::AttackMeta> =
                redteam_covenant::registry().iter().map(|a| a.meta()).collect();
            rows.extend(redteam_node::registry().iter().map(|a| a.meta()));
            respond_json(
                req,
                200,
                &json!({
                    "tool_version": env!("CARGO_PKG_VERSION"),
                    "library_version": redteam_core::LIBRARY_VERSION,
                    "attacks": rows,
                }),
            )
        }
        (&tiny_http::Method::Get, "/health") => respond(req, 200, "text/plain", "ok"),
        (&tiny_http::Method::Post, "/api/params") => {
            let mut body = Vec::new();
            let read = req.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body);
            if read.is_err() || body.len() > MAX_BODY {
                return respond_json(req, 413, &json!({ "error": "That upload is over 1 MiB." }));
            }
            match params_of(&body, s) {
                Ok(v) => respond_json(req, 200, &v),
                Err(e) => respond_json(req, 400, &json!({ "error": format!("{e:#}") })),
            }
        }
        (&tiny_http::Method::Post, "/api/scan") => {
            let ip = client_ip(&req);
            let mut body = Vec::new();
            let read = req.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body);
            if read.is_err() || body.len() > MAX_BODY {
                return respond_json(req, 413, &json!({ "error": "That upload is over 1 MiB." }));
            }
            // One scan per visitor, and a cap overall.
            {
                let mut running = s.running.lock().unwrap();
                if running.contains(&ip) {
                    drop(running);
                    return respond_json(
                        req,
                        429,
                        &json!({ "error": "You already have a scan running. Wait for it to finish." }),
                    );
                }
                if running.len() >= s.opts.jobs {
                    drop(running);
                    return respond_json(
                        req,
                        503,
                        &json!({ "error": "Every scanner is busy right now. Try again in a minute." }),
                    );
                }
                running.push(ip);
            }
            let result = scan(&body, s);
            s.running.lock().unwrap().retain(|x| *x != ip);
            match result {
                Ok(v) => respond_json(req, 200, &v),
                Err(e) => respond_json(req, 400, &json!({ "error": format!("{e:#}") })),
            }
        }
        _ => respond(req, 404, "text/plain", "not found"),
    }
}

/// `name.sil`, letters, digits, `-_.` only.
fn safe_name(name: &str, ext: &str, fallback: &str) -> String {
    let base: String = Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(80)
        .collect();
    let base = base.trim_start_matches('.').to_string();
    if base.is_empty() {
        fallback.to_string()
    } else if base.ends_with(ext) {
        base
    } else {
        format!("{base}{ext}")
    }
}

fn scan(body: &[u8], s: &Shared) -> Result<Value> {
    let req: Value = serde_json::from_slice(body).context("the request is not JSON")?;
    let source = req.get("source").and_then(|v| v.as_str()).unwrap_or("");
    let baseline = req.get("baseline").and_then(|v| v.as_str()).unwrap_or("");
    // A project: several files that work together, tested as one program.
    let mut project: Vec<(String, String)> = Vec::new();
    if let Some(list) = req.get("files").and_then(|v| v.as_array()) {
        if list.len() > MAX_FILES {
            anyhow::bail!("At most {MAX_FILES} files at once.");
        }
        for f in list {
            let src = f.get("source").and_then(|v| v.as_str()).unwrap_or("");
            if src.trim().is_empty() {
                continue;
            }
            if src.len() > MAX_SOURCE {
                anyhow::bail!("A contract is over 256 KiB.");
            }
            let mut name = safe_name(f.get("filename").and_then(|v| v.as_str()).unwrap_or(""), ".sil", "contract.sil");
            let mut k = 2;
            while project.iter().any(|(n, _)| *n == name) {
                name = format!("{}_{k}.sil", name.trim_end_matches(".sil"));
                k += 1;
            }
            project.push((name, src.to_string()));
        }
    }
    if source.trim().is_empty() && baseline.trim().is_empty() && project.is_empty() {
        anyhow::bail!("Give a .sil contract (or a baseline file).");
    }
    if source.len() > MAX_SOURCE {
        anyhow::bail!("That contract is over 256 KiB.");
    }
    let mut args = Vec::new();
    if let Some(list) = req.get("args").and_then(|v| v.as_array()) {
        for a in list.iter().filter_map(|a| a.as_str()).map(str::trim).filter(|a| !a.is_empty()) {
            if args.len() >= MAX_ARGS {
                anyhow::bail!("At most {MAX_ARGS} constructor values.");
            }
            let ok = a.len() <= 300
                && a.split_once('=').is_some_and(|(k, _)| {
                    !k.trim().is_empty() && k.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
                && !a.chars().any(char::is_control);
            if !ok {
                anyhow::bail!("Constructor value `{}` is not NAME=VALUE.", a.chars().take(60).collect::<String>());
            }
            args.push(a.to_string());
        }
    }

    let n = s.counter.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("kaspa-redteam-web-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let _cleanup = Cleanup(dir.clone());

    let mut cmd = Command::new(&s.exe);
    let mut shown_name = String::from("baseline");
    if !project.is_empty() {
        for (name, src) in &project {
            std::fs::write(dir.join(name), src)?;
            cmd.arg(name);
        }
        shown_name = project.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ");
    } else if !source.trim().is_empty() {
        let name = safe_name(req.get("filename").and_then(|v| v.as_str()).unwrap_or(""), ".sil", "contract.sil");
        std::fs::write(dir.join(&name), source)?;
        cmd.arg(&name);
        shown_name = name;
    }
    for a in &args {
        cmd.arg("--arg").arg(a);
    }
    // A compiled script from the user's own compiler, tested instead of today's compile.
    let compiled = req.get("compiled").and_then(|v| v.as_str()).unwrap_or("").trim();
    if !compiled.is_empty() {
        if !project.is_empty() || source.trim().is_empty() {
            anyhow::bail!("A compiled script goes with exactly one .sil file (its source).");
        }
        if compiled.len() > 512 * 1024 {
            anyhow::bail!("The compiled file is over 512 KiB.");
        }
        std::fs::write(dir.join("compiled.json"), compiled)?;
        cmd.arg("--compiled").arg("compiled.json");
    }
    // Constructor values pasted as JSON (the file a project deploys with).
    let args_json = req.get("args_json").and_then(|v| v.as_str()).unwrap_or("").trim();
    if !args_json.is_empty() {
        if args_json.len() > 64 * 1024 {
            anyhow::bail!("The constructor values are over 64 KiB.");
        }
        std::fs::write(dir.join("constructor-values.json"), args_json)?;
        cmd.arg("--args").arg("constructor-values.json");
    }
    if !baseline.trim().is_empty() && project.is_empty() {
        let name = safe_name(req.get("baseline_name").and_then(|v| v.as_str()).unwrap_or(""), ".json", "baseline.json");
        std::fs::write(dir.join(&name), baseline)?;
        cmd.arg("--baseline").arg(&name);
    }
    // Searching stops well before the hard limit so attacks still run and a report comes back.
    // A project also spends what it minted after the search (up to 20 s of its
    // own), so its search stops earlier.
    let deadline = if project.len() > 1 { s.opts.timeout / 2 } else { s.opts.timeout * 2 / 3 }.max(5).to_string();
    cmd.args(["--json", "--no-color", "--out", "findings", "--deadline", &deadline])
        .current_dir(&dir)
        .env("RAYON_NUM_THREADS", s.opts.threads.to_string())
        .env_remove("REDTEAM_DEBUG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    limit_memory(&mut cmd);

    let started = Instant::now();
    let mut child = cmd.spawn().context("start the scanner")?;
    let mut out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let out_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let err_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.take(64 * 1024).read_to_end(&mut v);
        v
    });
    let limit = Duration::from_secs(s.opts.timeout);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout = out_t.join().unwrap_or_default();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).trim().to_string();
    let Some(status) = status else {
        anyhow::bail!(
            "The scan took longer than {} s and was stopped. Run kaspa-redteam on your own machine for big contracts.",
            s.opts.timeout
        );
    };
    match status.code() {
        Some(0) | Some(1) => {}
        Some(2) => anyhow::bail!("{}", stderr.trim_start_matches("error: ")),
        _ => anyhow::bail!("The scanner stopped unexpectedly (out of memory?). {stderr}"),
    }
    let mut report: Value = serde_json::from_slice(&stdout).context("read the scanner's report")?;
    // Finding files, for download; paths inside them point at the temp folder, so show bare names.
    // A project writes each contract's findings to findings/<stem>/, so names
    // read `department_fund/OUT-01.json`.
    let mut names = Vec::new();
    collect(&dir.join("findings"), "", &mut names);
    names.sort();
    let files: Vec<Value> = names
        .iter()
        .map(|name| {
            let content = std::fs::read_to_string(dir.join("findings").join(name)).unwrap_or_default();
            json!({ "name": name, "content": scrub(&content, &dir) })
        })
        .collect();
    if let Value::Object(o) = &mut report {
        if project.is_empty() {
            o.insert("web_subject".into(), Value::String(shown_name));
        }
    }
    let report: Value = serde_json::from_str(&scrub(&report.to_string(), &dir))?;
    Ok(json!({ "report": report, "files": files }))
}

/// The constructor parameters of the uploaded file(s), for the form: compiled
/// in a child process like a scan, with a short limit.
fn params_of(body: &[u8], s: &Shared) -> Result<Value> {
    let req: Value = serde_json::from_slice(body).context("the request is not JSON")?;
    let mut files: Vec<(String, String)> = Vec::new();
    let list = req.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for f in list.iter().take(MAX_FILES) {
        let src = f.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if src.trim().is_empty() || src.len() > MAX_SOURCE {
            continue;
        }
        let mut name = safe_name(f.get("filename").and_then(|v| v.as_str()).unwrap_or(""), ".sil", "contract.sil");
        let mut k = 2;
        while files.iter().any(|(n, _)| *n == name) {
            name = format!("{}_{k}.sil", name.trim_end_matches(".sil"));
            k += 1;
        }
        files.push((name, src.to_string()));
    }
    if files.is_empty() {
        anyhow::bail!("No contract to read.");
    }
    let n = s.counter.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("kaspa-redteam-params-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let _cleanup = Cleanup(dir.clone());
    let mut cmd = Command::new(&s.exe);
    cmd.arg("params");
    for (name, src) in &files {
        std::fs::write(dir.join(name), src)?;
        cmd.arg(name);
    }
    cmd.current_dir(&dir).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    limit_memory(&mut cmd);
    let mut child = cmd.spawn().context("start the reader")?;
    let started = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if started.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Reading the constructor took too long.");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    child.stdout.take().expect("piped").read_to_end(&mut out)?;
    child.stderr.take().expect("piped").take(64 * 1024).read_to_end(&mut err)?;
    if !status.success() {
        let e = String::from_utf8_lossy(&err).trim().to_string();
        anyhow::bail!("{}", e.trim_start_matches("error: "));
    }
    Ok(json!({ "contracts": serde_json::from_slice::<Value>(&out).context("read the parameters")? }))
}

/// Files under `dir`, as paths relative to it (one level of folders is enough).
fn collect(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.filter_map(|e| e.ok()) {
        let name = e.file_name().to_string_lossy().to_string();
        let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        match e.file_type() {
            Ok(t) if t.is_dir() && prefix.is_empty() => collect(&e.path(), &path, out),
            Ok(t) if t.is_file() => out.push(path),
            _ => {}
        }
    }
}

/// Replaces the temporary folder in paths with nothing, so reports read
/// `findings/OUT-01.json` instead of a server path.
fn scrub(text: &str, dir: &Path) -> String {
    let d = dir.display().to_string();
    text.replace(&format!("{d}/"), "").replace(&d, ".")
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 2 GiB of address space per scan, so one hostile contract cannot take the
/// whole machine down.
fn limit_memory(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                let lim = libc::rlimit { rlim_cur: 2 << 30, rlim_max: 2 << 30 };
                libc::setrlimit(libc::RLIMIT_AS, &lim);
                Ok(())
            });
        }
    }
}
