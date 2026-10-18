//! TokenGen CLI — the first user-facing surface.
//!
//! # What this binary is, and is not
//!
//! It adds **no cryptographic behaviour**. Every capability it exposes is already built and frozen in the
//! `tokengen` library; this crate wires them to a terminal. If a guarantee needs changing, it changes in the
//! library under an amendment — never here.
//!
//! # The two constraints that shape it (D-P13)
//!
//! **1. Writing to the terminal is permitted *here and only here*.** The library crates deny
//! `print_stdout`/`print_stderr`. This crate declares its own policy in its own manifest, so the library's
//! deny stays absolute and these exceptions stay visible where a security reviewer will see them.
//!
//! **2. No interactive input.** F3.5's contract requires the session guard be polled *"even while blocked on
//! input"*. `stdin` reads block, so that contract cannot be met single-threaded once input is involved. This
//! CLI therefore takes flags only and completes in milliseconds — there is **no window in which the guard is
//! unpolled**. Passphrase input is deferred to F5/F6, which must solve the blocking problem properly.
//!
//! The cost is real and recorded: **there is no passphrase prompt in this revision.**
//!
//! # The rule that matters most
//!
//! **Only [`GuardStatus::Present`] permits a secret to be printed.** Every other status — including
//! `Unverifiable` and `Disabled` — exits non-zero without writing a secret to stdout. This restates the
//! library's fail-closed property at the user-facing surface, which is where it becomes a *user outcome*
//! rather than a test assertion.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use tokengen::generator::{self, Charset};
use tokengen::session::{GuardStatus, SessionGuard, SystemDeviceReader};
use tokengen::zeroize::Secret;

/// Exit codes. Documented in `--help` and distinct on purpose: a caller must be able to tell a *usage*
/// error from a *security* refusal, because the responses differ.
mod exit {
    /// Success: a secret was produced and printed.
    pub const OK: u8 = 0;
    /// The caller asked for something invalid (bad length, unknown charset, unknown flag).
    pub const USAGE: u8 = 2;
    /// The session guard refused: the device is missing, swapped, unverifiable, or the guard is disabled.
    /// **This is a security outcome, not a usage error.**
    pub const GUARD_REFUSED: u8 = 3;
    /// The platform cannot provide a required capability (F3/F3.5 `NotSupported`).
    pub const UNSUPPORTED: u8 = 4;
    /// The entropy source or generator failed.
    pub const GENERATION_FAILED: u8 = 5;
}

/// The parsed command line. Hand-parsed: a CLI with six flags does not need a dependency, and every
/// dependency is attack surface the project must review (F3.6 keeps the shipped graph at four crates).
struct Options {
    length: usize,
    charset: CharsetSpec,
    quiet: bool,
    workdir: Option<PathBuf>,
    dev_mode_acknowledged: bool,
}

enum CharsetSpec {
    Alnum,
    Lower,
    Upper,
    Digits,
    Hex,
}

enum Parsed {
    Generate(Options),
    Status,
    Help,
    Version,
}

fn usage() -> &'static str {
    "\
tokengen — portable, offline passkey generator

USAGE:
    tokengen <COMMAND> [OPTIONS]

COMMANDS:
    generate     Generate a secret (requires the session guard)
    status       Report the platform and session-guard status, without generating
    help         Show this help
    version      Show the version

OPTIONS for `generate`:
    -l, --length <N>      Length of the generated secret (default: 32)
    -c, --charset <SET>   Character set: alnum (default), lower, upper, digits, hex
    -C, --workdir <PATH>  Directory bound to the session guard (default: current directory)
    -q, --quiet           Suppress the scrollback and memory-lock notices. For scripts and pipes.
        --i-know-dev-mode-unguarded
                          Continue even though this build has the session guard compiled OFF.
                          Without this flag, a dev-mode build refuses to generate.

EXIT CODES:
    0  success
    2  usage error (bad command, bad flag, bad length, unknown charset)
    3  SECURITY: the session guard refused (device missing, swapped, or unverifiable)
    4  this location or platform cannot be used: no device backend (macOS/Windows), or the
       working directory is not on a block device at all (tmpfs, overlay, network mount)
    5  the entropy source or generator failed

ABOUT THE GUARD:
    On Linux the tool refuses to run unless the working directory is on a removable device, and it
    re-checks that device before printing anything. If the device is unplugged or replaced, the tool
    exits non-zero and prints no secret.

    On macOS and Windows there is no device backend yet, so the tool refuses with exit code 4. This is
    deliberate: it will not pretend to be guarded.

COMMANDS ARE SUBCOMMANDS ON PURPOSE:
    `generate`, `status` and the commands F5-F8 will add are different ACTIONS with different
    arguments. A bare-flags CLI could not grow them without breaking its interface.
"
}

/// The command line: a SUBCOMMAND, then its options.
///
/// Subcommands rather than bare flags because `generate`, `status`, and the `verify`/`config`/`doctor`
/// commands F5-F8 will add are different **actions** with different arguments. A bare-flags CLI could not
/// grow them without breaking its own interface — and this is the interface users will script against.
fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let Some(command) = args.first() else {
        return Err("no command given; try `tokengen help`".to_string());
    };
    let rest = &args[1..];

    match command.as_str() {
        "help" | "-h" | "--help" => return Ok(Parsed::Help),
        "version" | "-V" | "--version" => return Ok(Parsed::Version),
        "status" => return Ok(Parsed::Status),
        "generate" => {}
        other => {
            return Err(format!(
                "unknown command `{other}`; expected one of: generate, status, help, version"
            ))
        }
    }

    parse_generate_options(rest)
}

fn parse_generate_options(args: &[String]) -> Result<Parsed, String> {
    let mut opts = Options {
        length: 32,
        charset: CharsetSpec::Alnum,
        quiet: false,
        workdir: None,
        dev_mode_acknowledged: false,
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        // Values are taken from the next argument; a missing one is a usage error, never a default.
        let mut take_value = |flag: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };

        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-q" | "--quiet" => opts.quiet = true,
            "--i-know-dev-mode-unguarded" => opts.dev_mode_acknowledged = true,
            "-l" | "--length" => {
                let v = take_value(arg)?;
                opts.length = v
                    .parse::<usize>()
                    .map_err(|_| format!("--length expects a positive integer, got `{v}`"))?;
                if opts.length == 0 {
                    return Err("--length must be at least 1".to_string());
                }
            }
            "-c" | "--charset" => {
                let v = take_value(arg)?;
                opts.charset = match v.as_str() {
                    "alnum" => CharsetSpec::Alnum,
                    "lower" => CharsetSpec::Lower,
                    "upper" => CharsetSpec::Upper,
                    "digits" => CharsetSpec::Digits,
                    "hex" => CharsetSpec::Hex,
                    other => {
                        return Err(format!(
                            "unknown charset `{other}`; expected one of: alnum, lower, upper, digits, hex"
                        ))
                    }
                };
            }
            "-C" | "--workdir" => {
                let v = take_value(arg)?;
                opts.workdir = Some(PathBuf::from(v));
            }
            other => return Err(format!("unknown argument `{other}`; try --help")),
        }
        i += 1;
    }

    Ok(Parsed::Generate(opts))
}

/// Build the charset for a preset, from the **frozen** F2 constructors.
///
/// `hex` is assembled from the frozen `digits` and `lowercase` sets rather than parsed from a literal, so
/// the charset's contents are owned by the library and cannot drift here.
fn build_charset(spec: &CharsetSpec) -> Result<Charset, String> {
    let set = match spec {
        CharsetSpec::Alnum => {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
            bytes.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            bytes.extend_from_slice(b"0123456789");
            Charset::new(&bytes)
        }
        CharsetSpec::Lower => Ok(Charset::lowercase()),
        CharsetSpec::Upper => Ok(Charset::uppercase()),
        CharsetSpec::Digits => Ok(Charset::digits()),
        CharsetSpec::Hex => {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"0123456789abcdef");
            Charset::new(&bytes)
        }
    };
    set.map_err(|e| format!("could not construct the charset: {e:?}"))
}

/// Describe a non-`Present` status for stderr, without ever including a secret.
///
/// The identities in `IdentityMismatch` are **device properties, not secrets** (F3.5 documents this), so
/// naming them here is intended: it tells the user *what changed*.
fn describe_refusal(status: &GuardStatus) -> String {
    match status {
        GuardStatus::Present => "present".to_string(),
        GuardStatus::Missing => {
            "the device this session was bound to is no longer present".to_string()
        }
        GuardStatus::IdentityMismatch { expected, observed } => format!(
            "a DIFFERENT device is now at the bound path\n  \
             expected uuid={} serial={}\n  observed uuid={} serial={}",
            expected.uuid, expected.serial, observed.uuid, observed.serial
        ),
        GuardStatus::Unverifiable { component } => format!(
            "the device's identity could not be verified ({component:?}); \
             refusing rather than binding to an unconfirmed identity"
        ),
        GuardStatus::Disabled => {
            "this build has the session guard compiled OFF (dev-mode)".to_string()
        }
        // `GuardStatus` is `#[non_exhaustive]`: a future variant must not be reported as success.
        other => format!("unrecognised guard status {other:?}; refusing"),
    }
}

fn run(args: &[String]) -> ExitCode {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(exit::USAGE);
        }
    };

    let opts = match parsed {
        Parsed::Help => {
            print!("{}", usage());
            return ExitCode::from(exit::OK);
        }
        Parsed::Version => {
            println!("tokengen {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::from(exit::OK);
        }
        Parsed::Status => {
            // Deliberately does NOT require the guard to succeed: the point of `status` is to explain WHY
            // the guard refuses. It prints no secret, so it cannot leak one.
            let workdir = PathBuf::from(".");
            println!("tokengen {}", env!("CARGO_PKG_VERSION"));
            match SessionGuard::capture(SystemDeviceReader::new(), &workdir) {
                Ok((_guard, status)) => {
                    println!("session guard: {}", describe_refusal(&status));
                    let code = if matches!(status, GuardStatus::Present | GuardStatus::Disabled) {
                        exit::OK
                    } else {
                        exit::GUARD_REFUSED
                    };
                    return ExitCode::from(code);
                }
                Err(e) => {
                    println!("session guard: unavailable ({e:?})");
                    let code = if matches!(e, tokengen::session::SessionError::NotSupported) {
                        exit::UNSUPPORTED
                    } else {
                        exit::GUARD_REFUSED
                    };
                    return ExitCode::from(code);
                }
            }
        }
        Parsed::Generate(o) => o,
    };

    // ---------------------------------------------------------------------------------------------
    // THE GUARD. Everything below this point is only reachable through `Present`.
    // ---------------------------------------------------------------------------------------------
    let workdir = opts.workdir.clone().unwrap_or_else(|| PathBuf::from("."));

    let captured = SessionGuard::capture(SystemDeviceReader::new(), &workdir);
    let guard = match captured {
        Ok((guard, status)) => {
            // FIRST decision of the program: is this session permitted at all?
            match status {
                // `Disabled` is a dev-mode build. It is NEVER treated as success: without an explicit
                // acknowledgement the tool refuses, because a build with the guard compiled off must not
                // silently produce secrets. See D-P13 and F3.5 §8.
                GuardStatus::Disabled if !opts.dev_mode_acknowledged => {
                    eprintln!(
                        "error: SECURITY — this build has the session guard compiled OFF (dev-mode).\n\
                         Refusing to generate. If this is a deliberate development build, pass\n\
                         --i-know-dev-mode-unguarded; the output is then unguarded and the tool will say so."
                    );
                    return ExitCode::from(exit::GUARD_REFUSED);
                }
                GuardStatus::Present | GuardStatus::Disabled => guard,
                other => {
                    eprintln!(
                        "error: SECURITY — session guard refused: {}",
                        describe_refusal(&other)
                    );
                    return ExitCode::from(exit::GUARD_REFUSED);
                }
            }
        }
        Err(e) => {
            // `NotSupported` is a platform-capability outcome, distinct from a security refusal.
            let (code, msg) = match &e {
                tokengen::session::SessionError::NotSupported => (
                    exit::UNSUPPORTED,
                    "this platform has no device backend (macOS and Windows are not implemented; \
                     see the README). The tool will not pretend to be guarded."
                        .to_string(),
                ),
                tokengen::session::SessionError::NotOnRemovableDevice => (
                    exit::GUARD_REFUSED,
                    "the working directory is not on a removable device. The session guard binds to the \
                     drive, so the tool refuses to run from the internal disk."
                        .to_string(),
                ),
                // AM-007: NOT a security refusal. There is no device here to have been swapped, so this is
                // a capability outcome (exit 4), and the message must not suggest a missing drive — the user
                // would look for a loose cable that does not exist.
                tokengen::session::SessionError::NoBlockDevice => (
                    exit::UNSUPPORTED,
                    "the working directory is not on a block device at all (tmpfs, an overlay filesystem, \
                     or a network mount). No device identity can be read here, so the guard cannot bind. \
                     Run the tool from a directory on a real removable device."
                        .to_string(),
                ),
                other => (
                    exit::GUARD_REFUSED,
                    format!("session guard refused at capture: {other:?}"),
                ),
            };
            eprintln!("error: {msg}");
            return ExitCode::from(code);
        }
    };

    if opts.dev_mode_acknowledged {
        eprintln!(
            "WARNING: dev-mode — this build has the session guard compiled OFF. \
             The output is UNGUARDED. Never use this build for real secrets."
        );
    }

    let charset = match build_charset(&opts.charset) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(exit::USAGE);
        }
    };

    // Generate, and hold the result in a `Secret` so it is zeroized on drop.
    let generated = generator::generate_key_os(&charset, opts.length);
    let key = match generated {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: generation failed: {e:?}");
            return ExitCode::from(exit::GENERATION_FAILED);
        }
    };

    // THE SECOND CHECK. The device may have changed while we were generating. This is the last point
    // before a secret leaves the process, and it is not optional.
    let status = guard.check();
    if !matches!(status, GuardStatus::Present | GuardStatus::Disabled) {
        eprintln!(
            "error: SECURITY — session guard refused before output: {}",
            describe_refusal(&status)
        );
        // `key` is dropped here; its allocation is zeroized by `Secret`'s contract below.
        return ExitCode::from(exit::GUARD_REFUSED);
    }

    let (secret, lock_status) = Secret::new(key);
    if !matches!(lock_status, tokengen::zeroize::MemoryLockStatus::Locked) && !opts.quiet {
        // Honest on stderr, not fatal: F3 reports the status rather than failing the run. But the user is
        // told, because "no lock" means the secret may reach swap.
        eprintln!("warning: memory was NOT locked ({lock_status:?}); the secret may reach swap or a core dump");
    }

    // The scrollback warning (D-P13 decision 3): on a TTY the secret persists in scrollback. Say so.
    if !opts.quiet && std::io::stdout().is_terminal() {
        eprintln!(
            "note: writing to the terminal. This secret will remain in your terminal scrollback.\n\
             Use --quiet to suppress this notice in scripts, or pipe the output to a file or clipboard."
        );
    }

    // Print the secret and flush, so a pipe consumer receives it even if the process exits immediately.
    let mut out = std::io::stdout().lock();
    let write_result = out
        .write_all(secret.as_slice())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    drop(secret); // zeroize

    if write_result.is_err() {
        eprintln!("error: could not write the secret to stdout");
        return ExitCode::from(exit::GENERATION_FAILED);
    }

    ExitCode::from(exit::OK)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args)
}
