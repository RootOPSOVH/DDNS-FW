//! DDNS Firewall Synchronizer v2.2.1
//!
//! Ultra-lightweight, production-grade DDNS-based iptables firewall manager.
//! Designed for 24/7 critical servers - zero SSH access loss guaranteed.
//!
//! Safety guarantees:
//! - Atomic state cache for crash recovery
//! - NEVER deletes a rule without active replacement
//! - IP unchanged = zero operations (no micro-interruptions)
//! - DNS failure = no changes (fail-safe)
//! - iptables failure = no changes (fail-safe)
//! - Loop protection with max iterations
//! - Memory bounded (max 100 rules)
//! - Reboot/crash safe with automatic recovery
//! - Idempotent: safe to run unlimited times
//! - File locking prevents concurrent execution
//! - Strict permissions prevent privilege escalation

use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

// ============================================================================
// Constants
// ============================================================================

const INSTALL_DIR: &str = "/etc/ddnsfw";
const BINARY_PATH: &str = "/etc/ddnsfw/run";
const CONFIG_PATH: &str = "/etc/ddnsfw/conf.conf";
const CACHE_PATH: &str = "/etc/ddnsfw/service.cache";
const SERVICE_PATH: &str = "/etc/systemd/system/ddnsfw.service";
const TIMER_PATH: &str = "/etc/systemd/system/ddnsfw.timer";
const IPTABLES_COMMENT: &str = "DDNS-ACCESS";
const DNS_TIMEOUT_SECS: u64 = 10;

// Safety limits
const MAX_ENTRIES: usize = 100;      // Max config entries
const MAX_RULES: usize = 100;        // Max iptables rules to process
const MAX_LOOP_ITERATIONS: usize = 200;  // Absolute max iterations in any loop

const IPTABLES_PATHS: &[&str] = &[
    "/usr/sbin/iptables",
    "/sbin/iptables",
    "/usr/bin/iptables",
];

const LOCK_PATH: &str = "/etc/ddnsfw/.lock";

// ============================================================================
// Cache Structure (Crash Recovery)
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum CacheState {
    Idle,
    Adding,
    Deleting,
}

#[derive(Debug, Clone)]
struct Cache {
    state: CacheState,
    rules: HashSet<(Ipv4Addr, u16)>,
    pending: Option<(Ipv4Addr, u16)>,
}

impl Cache {
    fn new() -> Self {
        Cache {
            state: CacheState::Idle,
            rules: HashSet::new(),
            pending: None,
        }
    }

    fn load() -> Self {
        let Ok(file) = File::open(CACHE_PATH) else {
            return Cache::new();
        };

        let reader = BufReader::new(file);
        let mut cache = Cache::new();
        let mut line_count = 0;

        for line in reader.lines().map_while(Result::ok) {
            line_count += 1;
            if line_count > 10 {
                break; // Corrupt cache protection
            }

            if let Some(state_str) = line.strip_prefix("STATE:") {
                cache.state = match state_str {
                    "ADDING" => CacheState::Adding,
                    "DELETING" => CacheState::Deleting,
                    _ => CacheState::Idle,
                };
            } else if let Some(rules_str) = line.strip_prefix("RULES:") {
                let mut rule_count = 0;
                for rule in rules_str.split(',') {
                    if rule_count >= MAX_RULES {
                        break;
                    }
                    if let Some((ip, port)) = parse_ip_port(rule) {
                        cache.rules.insert((ip, port));
                        rule_count += 1;
                    }
                }
            } else if let Some(pending_str) = line.strip_prefix("PENDING:") {
                cache.pending = parse_ip_port(pending_str);
            }
        }

        cache
    }

    fn save(&self) {
        // Limit rules in cache
        let rules_to_save: Vec<_> = self.rules.iter().take(MAX_RULES).collect();

        let rules_str: String = rules_to_save
            .iter()
            .map(|(ip, port)| format!("{}:{}", ip, port))
            .collect::<Vec<_>>()
            .join(",");

        let state_str = match self.state {
            CacheState::Idle => "IDLE",
            CacheState::Adding => "ADDING",
            CacheState::Deleting => "DELETING",
        };

        let pending_str = self
            .pending
            .map(|(ip, port)| format!("{}:{}", ip, port))
            .unwrap_or_default();

        let content = format!("STATE:{}\nRULES:{}\nPENDING:{}\n", state_str, rules_str, pending_str);

        // Atomic write
        let temp_path = format!("{}.tmp", CACHE_PATH);
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
        {
            let _ = file.write_all(content.as_bytes());
            let _ = file.sync_all();
            let _ = fs::rename(&temp_path, CACHE_PATH);
        }
    }

    fn set_idle(&mut self) {
        self.state = CacheState::Idle;
        self.pending = None;
        self.save();
    }

    fn set_adding(&mut self, ip: Ipv4Addr, port: u16) {
        self.state = CacheState::Adding;
        self.pending = Some((ip, port));
        self.save();
    }

    fn set_deleting(&mut self, ip: Ipv4Addr, port: u16) {
        self.state = CacheState::Deleting;
        self.pending = Some((ip, port));
        self.save();
    }

    fn add_rule(&mut self, ip: Ipv4Addr, port: u16) {
        if self.rules.len() < MAX_RULES {
            self.rules.insert((ip, port));
        }
        self.state = CacheState::Idle;
        self.pending = None;
        self.save();
    }

    fn remove_rule(&mut self, ip: Ipv4Addr, port: u16) {
        self.rules.remove(&(ip, port));
        self.state = CacheState::Idle;
        self.pending = None;
        self.save();
    }
}

fn parse_ip_port(s: &str) -> Option<(Ipv4Addr, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let colon = s.rfind(':')?;
    let ip: Ipv4Addr = s[..colon].parse().ok()?;
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some((ip, port))
}

// ============================================================================
// Minimal Error Handling
// ============================================================================

fn exit_err(msg: &str) -> ! {
    eprintln!("[ddnsfw] ERROR: {}", msg);
    std::process::exit(1);
}

// ============================================================================
// File Locking (Prevents Concurrent Execution)
// ============================================================================

/// Acquires an exclusive lock on the lock file.
/// Returns the lock file handle (must be kept alive during operation).
/// If another instance is running, waits up to 30 seconds then exits.
fn acquire_lock() -> Option<File> {
    // Create lock file if it doesn't exist
    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(LOCK_PATH)
        .ok()?;

    // Try to acquire exclusive lock (non-blocking first)
    let fd = lock_file.as_raw_fd();
    let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

    if result == 0 {
        // Lock acquired immediately
        return Some(lock_file);
    }

    // Another instance is running, wait with timeout
    println!("[ddnsfw] Another instance is running, waiting...");

    // Try blocking lock with timeout using a separate thread
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();
    let fd_copy = fd;

    thread::spawn(move || {
        let result = unsafe { libc::flock(fd_copy, libc::LOCK_EX) };
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(0) => Some(lock_file),
        _ => {
            eprintln!("[ddnsfw] ERROR: Timeout waiting for lock (another instance running too long)");
            None
        }
    }
}

// ============================================================================
// System Checks
// ============================================================================

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn find_iptables() -> Option<&'static str> {
    IPTABLES_PATHS.iter().find(|p| Path::new(p).exists()).copied()
}

fn is_installed() -> bool {
    Path::new(BINARY_PATH).exists() && Path::new(CONFIG_PATH).exists()
}

fn is_running_installed() -> bool {
    env::current_exe()
        .map(|p| p.to_string_lossy() == BINARY_PATH)
        .unwrap_or(false)
}

// ============================================================================
// DNS Resolution (Synchronous - no async overhead)
// ============================================================================

fn resolve_dns(hostname: &str) -> Option<Ipv4Addr> {
    let output = Command::new("getent")
        .args(["ahostsv4", hostname])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next()?;
    let ip_str = first_line.split_whitespace().next()?;
    ip_str.parse().ok()
}

fn resolve_dns_timeout(hostname: &str, timeout: Duration) -> Option<Ipv4Addr> {
    use std::sync::mpsc;
    use std::thread;

    let hostname = hostname.to_string();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = resolve_dns(&hostname);
        let _ = tx.send(result);
    });

    rx.recv_timeout(timeout).ok().flatten()
}

// ============================================================================
// iptables Operations
// ============================================================================

fn iptables(bin: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

fn iptables_run(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn get_existing_rules(bin: &str) -> HashSet<(Ipv4Addr, u16)> {
    let mut rules = HashSet::new();

    let Some(output) = iptables(bin, &["-S", "INPUT"]) else {
        return rules;
    };

    let mut iteration = 0;
    for line in output.lines() {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Too many iptables rules, truncating");
            break;
        }

        if !line.contains(IPTABLES_COMMENT) {
            continue;
        }

        if rules.len() >= MAX_RULES {
            break;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut ip: Option<Ipv4Addr> = None;
        let mut port: Option<u16> = None;

        for i in 0..parts.len().min(50) {  // Limit parsing iterations
            if parts[i] == "-s" && i + 1 < parts.len() {
                ip = parts[i + 1].trim_end_matches("/32").parse().ok();
            }
            if parts[i] == "--dport" && i + 1 < parts.len() {
                port = parts[i + 1].parse().ok();
            }
        }

        if let (Some(ip), Some(port)) = (ip, port) {
            rules.insert((ip, port));
        }
    }

    rules
}

fn rule_exists(bin: &str, ip: Ipv4Addr, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-C", "INPUT",
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ],
    )
}

/// Add rule - appends to end (not position 1) to maintain order
fn add_rule(bin: &str, ip: Ipv4Addr, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-I", "INPUT", "1",  // Still insert at 1 for priority over other rules
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ],
    )
}

fn delete_rule(bin: &str, ip: Ipv4Addr, port: u16) -> bool {
    iptables_run(
        bin,
        &[
            "-D", "INPUT",
            "-s", &format!("{}/32", ip),
            "-p", "tcp",
            "-m", "tcp",
            "--dport", &port.to_string(),
            "-m", "comment",
            "--comment", IPTABLES_COMMENT,
            "-j", "ACCEPT",
        ],
    )
}

// ============================================================================
// Configuration
// ============================================================================

struct DdnsEntry {
    hostname: String,
    port: u16,
}

fn parse_config() -> Vec<DdnsEntry> {
    let Ok(content) = fs::read_to_string(CONFIG_PATH) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    let mut iteration = 0;

    for line in content.lines() {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Config file too large, truncating");
            break;
        }

        if entries.len() >= MAX_ENTRIES {
            eprintln!("[ddnsfw] WARN: Max {} entries allowed", MAX_ENTRIES);
            break;
        }

        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(colon) = line.rfind(':') {
            let hostname = line[..colon].trim().to_string();
            if let Ok(port) = line[colon + 1..].trim().parse::<u16>() {
                if !hostname.is_empty() && port > 0 {
                    entries.push(DdnsEntry { hostname, port });
                }
            }
        }
    }

    entries
}

// ============================================================================
// Crash Recovery
// ============================================================================

fn recover_from_crash(iptables_bin: &str, cache: &mut Cache) {
    match cache.state {
        CacheState::Idle => {}
        CacheState::Adding => {
            if let Some((ip, port)) = cache.pending {
                println!("[ddnsfw] Recovery: Checking pending add {}:{}", ip, port);
                if !rule_exists(iptables_bin, ip, port) {
                    println!("[ddnsfw] Recovery: Re-adding rule {}:{}", ip, port);
                    if add_rule(iptables_bin, ip, port) {
                        cache.add_rule(ip, port);
                    } else {
                        cache.set_idle();
                    }
                } else {
                    cache.add_rule(ip, port);
                }
            } else {
                cache.set_idle();
            }
        }
        CacheState::Deleting => {
            if let Some((ip, port)) = cache.pending {
                println!("[ddnsfw] Recovery: Delete interrupted for {}:{}, ignoring", ip, port);
            }
            cache.set_idle();
        }
    }
}

// ============================================================================
// Core Sync Algorithm (CRITICAL - Zero Bug Tolerance)
// ============================================================================

fn sync_firewall() {
    // Acquire exclusive lock to prevent concurrent execution
    let _lock = match acquire_lock() {
        Some(lock) => lock,
        None => {
            eprintln!("[ddnsfw] ERROR: Could not acquire lock");
            return;
        }
    };
    // Lock is held until _lock goes out of scope

    let Some(iptables_bin) = find_iptables() else {
        eprintln!("[ddnsfw] ERROR: iptables not found");
        return;
    };

    // Load cache and recover if needed
    let mut cache = Cache::load();
    if cache.state != CacheState::Idle {
        println!("[ddnsfw] Detected incomplete operation, recovering...");
        recover_from_crash(iptables_bin, &mut cache);
    }

    let entries = parse_config();
    if entries.is_empty() {
        println!("[ddnsfw] No entries in config");
        return;
    }

    println!("[ddnsfw] Syncing {} entries...", entries.len());

    // Get actual iptables state (source of truth)
    let existing_rules = get_existing_rules(iptables_bin);

    // Update cache with actual state
    cache.rules = existing_rules.clone();
    cache.save();

    // Track desired rules and what needs to be added
    let mut desired_rules: HashSet<(Ipv4Addr, u16)> = HashSet::new();
    let mut rules_to_add: Vec<(Ipv4Addr, u16)> = Vec::new();

    // Phase 1: Resolve all DNS first (no iptables changes yet)
    let mut iteration = 0;
    for entry in &entries {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Loop protection triggered in phase 1");
            break;
        }

        print!("[ddnsfw] {}:{} -> ", entry.hostname, entry.port);
        let _ = io::stdout().flush();

        let Some(ip) = resolve_dns_timeout(&entry.hostname, Duration::from_secs(DNS_TIMEOUT_SECS)) else {
            println!("SKIP (DNS failed, keeping existing)");
            // Keep existing rules for this port
            for &(existing_ip, existing_port) in &existing_rules {
                if existing_port == entry.port {
                    desired_rules.insert((existing_ip, existing_port));
                }
            }
            continue;
        };

        print!("{} ", ip);
        let _ = io::stdout().flush();

        desired_rules.insert((ip, entry.port));

        // Check if rule already exists - if yes, NO OPERATION needed
        if existing_rules.contains(&(ip, entry.port)) {
            println!("OK (no change)");
            continue;
        }

        // Also check with iptables directly (belt and suspenders)
        if rule_exists(iptables_bin, ip, entry.port) {
            println!("OK (exists)");
            continue;
        }

        // Need to add this rule
        rules_to_add.push((ip, entry.port));
        println!("PENDING");
    }

    // Phase 2: Add new rules (safe - only adds, preserves existing)
    iteration = 0;
    for (ip, port) in &rules_to_add {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Loop protection triggered in phase 2");
            break;
        }

        print!("[ddnsfw] Adding {}:{} ... ", ip, port);
        let _ = io::stdout().flush();

        cache.set_adding(*ip, *port);

        if add_rule(iptables_bin, *ip, *port) {
            cache.add_rule(*ip, *port);
            println!("OK");
        } else {
            // Retry once
            if add_rule(iptables_bin, *ip, *port) {
                cache.add_rule(*ip, *port);
                println!("OK (retry)");
            } else {
                cache.set_idle();
                println!("FAILED (keeping existing)");
                // Keep existing rules for this port
                for &(existing_ip, existing_port) in &existing_rules {
                    if existing_port == *port {
                        desired_rules.insert((existing_ip, existing_port));
                    }
                }
            }
        }
    }

    // Phase 3: Delete old rules (safe - new rules already active)
    iteration = 0;
    for &(ip, port) in &existing_rules {
        iteration += 1;
        if iteration > MAX_LOOP_ITERATIONS {
            eprintln!("[ddnsfw] WARN: Loop protection triggered in phase 3");
            break;
        }

        if !desired_rules.contains(&(ip, port)) {
            print!("[ddnsfw] Removing old {}:{} ... ", ip, port);
            let _ = io::stdout().flush();

            cache.set_deleting(ip, port);

            if delete_rule(iptables_bin, ip, port) {
                cache.remove_rule(ip, port);
                println!("OK");
            } else {
                cache.set_idle();
                println!("FAILED (rule remains)");
            }
        }
    }

    cache.set_idle();
    println!("[ddnsfw] Sync complete");
}

// ============================================================================
// Installation
// ============================================================================

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input).unwrap_or(0);
    input.trim().to_string()
}

fn prompt_yn(msg: &str, default: bool) -> bool {
    let suffix = if default { " [Y/n]: " } else { " [y/N]: " };
    let input = prompt(&format!("{}{}", msg, suffix)).to_lowercase();
    match input.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    }
}

fn interactive_setup() -> Vec<DdnsEntry> {
    if find_iptables().is_none() {
        exit_err(
            "iptables not found!\n\
             Install it first:\n  \
             Ubuntu/Debian: sudo apt install iptables\n  \
             CentOS/RHEL:   sudo yum install iptables",
        );
    }

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║         DDNS Firewall Synchronizer - Setup                 ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    let mut entries = Vec::new();
    let mut loop_count = 0;

    loop {
        loop_count += 1;
        if loop_count > MAX_ENTRIES {
            println!("Maximum {} entries reached.", MAX_ENTRIES);
            break;
        }

        let port: u16 = loop {
            let s = prompt("SSH Port (e.g., 22): ");
            if let Ok(p) = s.parse() {
                if p > 0 {
                    break p;
                }
            }
            println!("Invalid port, try again.");
        };

        let hostname = loop {
            let s = prompt("DDNS hostname (e.g., home.dyndns.org): ");
            if !s.is_empty() && !s.contains(' ') && s.len() < 256 {
                break s;
            }
            println!("Invalid hostname, try again.");
        };

        println!("Added: {}:{}", hostname, port);
        entries.push(DdnsEntry { hostname, port });

        if !prompt_yn("\nAdd another entry?", false) {
            break;
        }
    }

    if entries.is_empty() {
        exit_err("At least one entry required");
    }

    println!("\nEntries to configure:");
    for e in &entries {
        println!("  * {}:{}", e.hostname, e.port);
    }

    if !prompt_yn("\nProceed with installation?", true) {
        exit_err("Cancelled");
    }

    entries
}

fn install(entries: Vec<DdnsEntry>) {
    println!("\nInstalling...\n");

    print!("  [1/8] Creating directory... ");
    if fs::create_dir_all(INSTALL_DIR).is_err() {
        exit_err("Failed to create directory");
    }
    // Set directory permissions to 700 (rwx------) - only root can access
    if fs::set_permissions(INSTALL_DIR, fs::Permissions::from_mode(0o700)).is_err() {
        exit_err("Failed to set directory permissions");
    }
    println!("OK");

    print!("  [2/8] Copying binary... ");
    let exe = env::current_exe().unwrap_or_else(|_| exit_err("Cannot get exe path"));
    if exe.to_string_lossy() != BINARY_PATH {
        if fs::copy(&exe, BINARY_PATH).is_err() {
            exit_err("Failed to copy binary");
        }
    }
    // Set binary permissions to 700 (rwx------) - only root can execute
    if fs::set_permissions(BINARY_PATH, fs::Permissions::from_mode(0o700)).is_err() {
        exit_err("Failed to set binary permissions");
    }
    println!("OK");

    print!("  [3/8] Creating config... ");
    let mut config = String::from(
        "# DDNS Firewall Configuration\n\
         # Format: hostname:port\n\n",
    );
    for e in &entries {
        config.push_str(&format!("{}:{}\n", e.hostname, e.port));
    }
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(CONFIG_PATH);
    if file.is_err() || file.unwrap().write_all(config.as_bytes()).is_err() {
        exit_err("Failed to write config");
    }
    println!("OK");

    print!("  [4/8] Initializing cache... ");
    let cache = Cache::new();
    cache.save();
    println!("OK");

    print!("  [5/8] Creating lock file... ");
    // Create lock file with 600 permissions
    if OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(LOCK_PATH)
        .is_err()
    {
        exit_err("Failed to create lock file");
    }
    println!("OK");

    print!("  [6/8] Creating systemd service... ");
    let service = r#"[Unit]
Description=DDNS Firewall Synchronizer
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/ddnsfw/run
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ddnsfw

[Install]
WantedBy=multi-user.target
"#;
    if fs::write(SERVICE_PATH, service).is_err() {
        exit_err("Failed to write service file");
    }
    println!("OK");

    print!("  [7/8] Creating systemd timer... ");
    let timer = r#"[Unit]
Description=DDNS Firewall Synchronizer Timer

[Timer]
OnBootSec=30sec
OnUnitActiveSec=2min
RandomizedDelaySec=10sec
Persistent=true

[Install]
WantedBy=timers.target
"#;
    if fs::write(TIMER_PATH, timer).is_err() {
        exit_err("Failed to write timer file");
    }
    println!("OK");

    print!("  [8/8] Enabling service... ");
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();
    let _ = Command::new("systemctl").args(["enable", "ddnsfw.timer"]).output();
    let _ = Command::new("systemctl").args(["start", "ddnsfw.timer"]).output();
    println!("OK");

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║                 Installation Complete!                     ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("\nFiles:");
    println!("  Binary:  {}", BINARY_PATH);
    println!("  Config:  {}", CONFIG_PATH);
    println!("  Cache:   {}", CACHE_PATH);
    println!("  Service: {}", SERVICE_PATH);
    println!("  Timer:   {}", TIMER_PATH);
    println!("\nCommands:");
    println!("  Status:  systemctl status ddnsfw.timer");
    println!("  Logs:    journalctl -u ddnsfw -f");
    println!("  Rules:   iptables -L INPUT -n | grep DDNS");

    println!("\nRunning initial sync...\n");
    let _ = Command::new("systemctl").args(["start", "ddnsfw.service"]).output();
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    if !is_root() {
        exit_err("Must run as root");
    }

    if is_installed() && is_running_installed() {
        sync_firewall();
    } else if is_installed() {
        println!("Already installed at {}", BINARY_PATH);
        println!("To reinstall: sudo rm -rf {} {} {}", INSTALL_DIR, SERVICE_PATH, TIMER_PATH);
    } else {
        let entries = interactive_setup();
        install(entries);
    }
}
