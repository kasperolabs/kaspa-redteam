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
const EXAMPLE: &str = include_str!("../../../fixtures/OUT-03/vulnerable.sil");
const MAX_BODY: usize = 1 << 20; // 1 MiB: a contract plus a baseline file
const MAX_SOURCE: usize = 256 * 1024;
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
    match (req.method(), url.as_str()) {
        (tiny_http::Method::Get, "/") | (tiny_http::Method::Get, "/index.html") => {
            respond(req, 200, "text/html; charset=utf-8", PAGE)
        }
        (tiny_http::Method::Get, "/api/example") => {
            respond_json(req, 200, &json!({ "filename": "out03-example.sil", "source": EXAMPLE }))
        }
        (tiny_http::Method::Get, "/api/library") => {
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
        (tiny_http::Method::Get, "/health") => respond(req, 200, "text/plain", "ok"),
        (tiny_http::Method::Post, "/api/scan") => {
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
    if source.trim().is_empty() && baseline.trim().is_empty() {
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
    if !source.trim().is_empty() {
        let name = safe_name(req.get("filename").and_then(|v| v.as_str()).unwrap_or(""), ".sil", "contract.sil");
        std::fs::write(dir.join(&name), source)?;
        cmd.arg(&name);
        shown_name = name;
    }
    for a in &args {
        cmd.arg("--arg").arg(a);
    }
    if !baseline.trim().is_empty() {
        let name = safe_name(req.get("baseline_name").and_then(|v| v.as_str()).unwrap_or(""), ".json", "baseline.json");
        std::fs::write(dir.join(&name), baseline)?;
        cmd.arg("--baseline").arg(&name);
    }
    cmd.args(["--json", "--no-color", "--out", "findings"])
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
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir.join("findings")) {
        let mut names: Vec<_> =
            rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).collect();
        names.sort();
        for name in names {
            let content = std::fs::read_to_string(dir.join("findings").join(&name)).unwrap_or_default();
            files.push(json!({ "name": name, "content": scrub(&content, &dir) }));
        }
    }
    if let Value::Object(o) = &mut report {
        o.insert("web_subject".into(), Value::String(shown_name));
    }
    let report: Value = serde_json::from_str(&scrub(&report.to_string(), &dir))?;
    Ok(json!({ "report": report, "files": files }))
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
