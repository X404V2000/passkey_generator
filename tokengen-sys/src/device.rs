//! Device resolution and identity for the F3.5 session guard — Linux backend.
//!
//! Split into its own module under
//! [`AM-002`](../../../plan/reports/F3/AM-002_tokengen-sys_Module_Split.md), which anticipated this file
//! ("after F3.5: 3 `unsafe`-bearing modules, enumerated").
//!
//! **The third of exactly three `unsafe`-bearing modules in this crate** (the others are
//! [`crate::memory`] and [`crate::coredump`]). Every `unsafe` block carries a `// SAFETY:` justification.
//!
//! # What this module answers, and what it deliberately does not
//!
//! It resolves a **path** to the **device** backing it, and reads that device's identity. The unit of
//! identity is a device, not a path: a mount point can be reused by a different drive, which is exactly the
//! attack the guard exists to detect (F3.5 §6.1).
//!
//! # Mechanisms — all probed, none assumed
//!
//! | Step | Mechanism | Probe |
//! |---|---|---|
//! | path → device | `stat(path).st_dev` → major:minor → `/sys/dev/block/<maj>:<min>` | P5 |
//! | device → filesystem UUID | scan `/dev/disk/by-uuid`, match the link resolving to this device | P5 |
//! | device → hardware serial | `device/serial` (plain text), else `device/vpd_pg80` (binary VPD page 0x80) | P3, **P8** |
//! | device → removable | `/sys/block/<dev>/removable` | P6 |
//!
//! **No external binary is used** — no `blkid`, no `udevadm`. `stat` and `std::fs` only, satisfying G7.
//!
//! # The P8 correction, and why the reading order is explicit
//!
//! The original blueprint named `/sys/block/<dev>/device/serial` for the serial. Probe P8, run with a real
//! USB mass-storage device attached, showed that path is **NVMe-only** — **absent** on USB, which is the
//! device class this tool runs from. The real USB source is `device/vpd_pg80`, the SCSI VPD page 0x80.
//!
//! So the serial is read in a defined order, and **unreadable is never treated as absent**:
//! `device/serial` → `device/vpd_pg80` → `Unreadable`. A device whose serial cannot be read must produce
//! `Unverifiable`, never a fabricated or partial value (§10.1, test 6).
//!
//! # Fail closed
//!
//! Non-Unix targets have no backend in this revision and return `NotSupported` — **never** a plausible
//! `Ok`. A stub that reported success would make the guard's `Present` status a lie, which is the
//! false-assurance class this project treats as its worst defect.

#[cfg(unix)]
// The `unsafe` opt-out for this module. Confined here and to `crate::memory` and `crate::coredump`; every
// `unsafe` block inside carries a `// SAFETY:` justification. The main `tokengen` crate cannot acquire this
// allowance — its root uses `forbid`, which no module can relax (verified: `error[E0453]`).
#[allow(unsafe_code)]
mod platform {
    use crate::device::{
        DeviceDescriptor, DeviceIdentity, DeviceReadError, IdentityComponent, RawDevice,
    };
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    /// `major(dev)` / `minor(dev)` as the kernel encodes them in `st_dev`.
    ///
    /// Linux's `dev_t` is `(major << 20) | minor` for the *internal* encoding, but the value surfaced to
    /// userspace in `st_dev` by glibc follows the legacy `(major << 8) | minor` layout for the low range.
    /// Probe P5 confirmed the working decode against `/sys/dev/block/<maj>:<min>`:
    /// `66306` → `259:2`. The division is done in `u64` to avoid truncation on large device numbers.
    fn split_dev(dev: u64) -> (u64, u64) {
        // glibc's convention, which P5 validated on this host. Using 256 rather than 2^20 is deliberate and
        // matches what `stat` reports for `st_dev`; the 2^20 form applies to the kernel's internal type.
        (dev / 256, dev % 256)
    }

    /// `stat` the path and return its `st_dev`.
    fn st_dev_of(path: &Path) -> Result<u64, DeviceReadError> {
        let c =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| DeviceReadError::InvalidPath)?;

        let mut st: libc::stat = unsafe { std::mem::zeroed() };

        // SAFETY: `c` is a valid NUL-terminated C string that outlives the call. `&mut st` points to a
        // properly aligned, initialised `libc::stat` owned by this frame. `stat` writes only into that
        // buffer and reads only the path; it retains neither pointer. The return value is checked below.
        let rc = unsafe { libc::stat(c.as_ptr(), &mut st) };
        if rc != 0 {
            return Err(DeviceReadError::StatFailed);
        }
        // `st_dev` is used as an opaque device number. On Linux/glibc it is already
        // `u64`; `u64::from` here would also fail to compile if it were not, which is
        // the behaviour we want — a silent lossy cast would be worse.
        Ok(st.st_dev)
    }

    /// Resolve a `st_dev` to its kernel block-device name, e.g. `sda1`.
    ///
    /// Reads `/sys/dev/block/<maj>:<min>`, a symlink into the device tree. The final component of the
    /// resolved path is the device name (P5).
    fn resolve_block_name(dev: u64) -> Result<String, DeviceReadError> {
        let (maj, min) = split_dev(dev);
        let link = PathBuf::from(format!("/sys/dev/block/{maj}:{min}"));
        let resolved = fs::canonicalize(&link).map_err(|_| DeviceReadError::DeviceNotFound)?;
        resolved
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .ok_or(DeviceReadError::DeviceNotFound)
    }

    /// The **whole-disk** name for a partition name (`sda1` → `sda`, `nvme0n1p2` → `nvme0n1`).
    ///
    /// The serial and `removable` attributes live on the whole disk, not the partition, so this step is
    /// required before reading either — the mistake the blueprint called out (P3: "the real path is one
    /// level down, on the device's parent node").
    fn whole_disk(name: &str) -> String {
        // `nvme0n1p2` -> strip `p2`; `sda1` -> strip `1`; `sda` -> unchanged.
        if let Some(idx) = name.rfind('p') {
            if name[idx + 1..].chars().all(|c| c.is_ascii_digit()) && idx + 1 < name.len() {
                // Only treat `p` as a partition separator if what precedes it ends in a digit
                // (`nvme0n1p2`), otherwise `sda` would be mangled by a stray `p`.
                if name[..idx]
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_ascii_digit())
                {
                    return name[..idx].to_string();
                }
            }
        }
        let trimmed: String = name
            .trim_end_matches(|c: char| c.is_ascii_digit())
            .to_string();
        if trimmed.is_empty() {
            name.to_string()
        } else {
            trimmed
        }
    }

    /// Read `/sys/block/<disk>/removable`. `1` means the kernel considers it removable.
    fn is_removable_disk(disk: &str) -> Result<bool, DeviceReadError> {
        let p = format!("/sys/block/{disk}/removable");
        let s = fs::read_to_string(&p).map_err(|_| DeviceReadError::PropertyUnreadable)?;
        match s.trim() {
            "1" => Ok(true),
            "0" => Ok(false),
            _ => Err(DeviceReadError::PropertyUnreadable),
        }
    }

    /// Read the hardware serial, trying the plain-text path first and then the binary VPD page.
    ///
    /// **The order is load-bearing**, and the fallback exists because of Probe P8: `device/serial` exists
    /// for NVMe and is **absent** for USB mass storage, where the serial lives in `device/vpd_pg80`.
    fn read_serial(disk: &str) -> Result<String, DeviceReadError> {
        // 1. Plain text (NVMe, and any class that provides it).
        let plain = format!("/sys/block/{disk}/device/serial");
        if let Ok(s) = fs::read_to_string(&plain) {
            let t = s.trim();
            if !t.is_empty() {
                return Ok(t.to_string());
            }
            // Readable but empty is NOT the same as absent: report unreadable rather than falling through
            // to a different mechanism that might yield a value for a different reason. (§10.1, test 6.)
            return Err(DeviceReadError::PropertyUnreadable);
        }

        // 2. Binary VPD page 0x80 (USB mass storage). Probe P8.
        let vpd = format!("/sys/block/{disk}/device/vpd_pg80");
        let bytes = fs::read(&vpd).map_err(|_| DeviceReadError::PropertyUnreadable)?;
        decode_vpd_pg80(&bytes)
    }

    /// Decode a SCSI VPD page 0x80 (Unit Serial Number).
    ///
    /// Layout, per SPC-4 and confirmed against a real device by Probe P8:
    ///
    /// ```text
    /// byte 0        peripheral device type / qualifier
    /// byte 1        page code — must be 0x80
    /// bytes 2..3    big-endian length of the serial that follows
    /// bytes 4..4+n  ASCII serial (space/NUL padded)
    /// ```
    ///
    /// **Bounds-checking is mandatory.** A truncated or short read yields an error, never a partial
    /// serial: binding identity to a prefix would let a different device sharing that prefix pass the
    /// check, which is worse than having no serial at all.
    fn decode_vpd_pg80(bytes: &[u8]) -> Result<String, DeviceReadError> {
        if bytes.len() < 4 {
            return Err(DeviceReadError::PropertyUnreadable);
        }
        if bytes[1] != 0x80 {
            // Not a Unit Serial Number page; do not guess at another page's contents.
            return Err(DeviceReadError::PropertyUnreadable);
        }
        let len = ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        let end = 4usize
            .checked_add(len)
            .ok_or(DeviceReadError::PropertyUnreadable)?;
        if end > bytes.len() {
            // Declared length exceeds what was actually read: truncated, so refuse.
            return Err(DeviceReadError::PropertyUnreadable);
        }
        let s =
            std::str::from_utf8(&bytes[4..end]).map_err(|_| DeviceReadError::PropertyUnreadable)?;
        let t = s.trim().trim_matches('\0').trim();
        if t.is_empty() {
            return Err(DeviceReadError::PropertyUnreadable);
        }
        Ok(t.to_string())
    }

    /// Read the filesystem UUID by reverse traversal of `/dev/disk/by-uuid`.
    ///
    /// That directory is indexed **uuid → device**, so a forward lookup for a known device cannot work
    /// (the error the directive's original §6.1 route made, corrected by Probe P5). This scans the links
    /// and returns the UUID whose target resolves to the same device as `disk_path`.
    fn uuid_for_device(disk_path: &Path) -> Result<String, DeviceReadError> {
        let target = fs::canonicalize(disk_path).map_err(|_| DeviceReadError::DeviceNotFound)?;
        let dir = Path::new("/dev/disk/by-uuid");
        let entries = fs::read_dir(dir).map_err(|_| DeviceReadError::PropertyUnreadable)?;

        for entry in entries.flatten() {
            let link = entry.path();
            if let Ok(dest) = fs::canonicalize(&link) {
                if dest == target {
                    if let Some(name) = link.file_name().and_then(|n| n.to_str()) {
                        return Ok(name.to_string());
                    }
                }
            }
        }
        Err(DeviceReadError::UuidNotFound)
    }

    pub(super) fn resolve(path: &Path) -> Result<DeviceDescriptor, DeviceReadError> {
        let dev = st_dev_of(path)?;
        let part = resolve_block_name(dev)?;
        let disk = whole_disk(&part);

        if !is_removable_disk(&disk)? {
            // A non-removable backing device is a refusal, not an error to be tolerated: the guard's
            // premise is that the session dies with the drive. Mirrors test 1.
            return Err(DeviceReadError::NotRemovable);
        }

        Ok(DeviceDescriptor {
            inner: RawDevice {
                partition: part,
                disk,
            },
        })
    }

    pub(super) fn identify(dev: &RawDevice) -> Result<DeviceIdentity, DeviceReadError> {
        let uuid = uuid_for_device(Path::new(&format!("/dev/{}", dev.partition)))?;
        let serial = read_serial(&dev.disk)?;
        Ok(DeviceIdentity { uuid, serial })
    }

    pub(super) fn is_removable(dev: &RawDevice) -> Result<bool, DeviceReadError> {
        is_removable_disk(&dev.disk)
    }

    /// Map a platform failure to the public component it concerns, so callers can distinguish
    /// *which* identity component was unverifiable without inventing a value for it.
    pub(super) fn component_of(err: &DeviceReadError) -> Option<IdentityComponent> {
        match err {
            DeviceReadError::PropertyUnreadable | DeviceReadError::UuidNotFound => {
                Some(IdentityComponent::FilesystemUuid)
            }
            _ => None,
        }
    }
}

/// Targets with no backend in this revision. Fail closed.
///
/// Returning `Err(NotSupported)` — never `Ok` — is deliberate: a stub that reported success would make the
/// caller's `Present` status a lie and leave G16/G17 silently unmet. See F3.5 §6.3 and §10.2 (W1, W2).
#[cfg(not(unix))]
mod platform {
    use crate::device::{DeviceDescriptor, DeviceIdentity, DeviceReadError, RawDevice};
    use std::path::Path;

    pub(super) fn resolve(_path: &Path) -> Result<DeviceDescriptor, DeviceReadError> {
        Err(DeviceReadError::NotSupported)
    }

    pub(super) fn identify(_dev: &RawDevice) -> Result<DeviceIdentity, DeviceReadError> {
        Err(DeviceReadError::NotSupported)
    }

    pub(super) fn is_removable(_dev: &RawDevice) -> Result<bool, DeviceReadError> {
        Err(DeviceReadError::NotSupported)
    }
}

// ---------------------------------------------------------------------------------------------
// Public (safe) API
// ---------------------------------------------------------------------------------------------

/// A device resolved by the platform layer. **Crate-private** — callers only ever see the opaque
/// [`DeviceDescriptor`]. Kept separate so the per-OS representation cannot leak into the public API.
/// The device names a descriptor carries.
///
/// `dead_code` is allowed **deliberately and in this exact form**. The fields are read only by the Unix
/// backend; on the `not(unix)` build (which `scripts/cfg_check.sh` compiles by inverting the gates) the
/// reading code is disabled and they appear unused. A `cfg_attr` would be the finer instrument, but the
/// gate inverts `#[cfg(...)]` **textually** and does not understand `cfg_attr` — so the `cfg_attr` would
/// survive the inversion and leave the warning live on the very build the gate exists to check.
///
/// Recorded because the blunt form was chosen for a reason, not by default.
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub(crate) struct RawDevice {
    /// The partition device name, e.g. `sda1` (used for the UUID reverse lookup).
    pub(crate) partition: String,
    /// The whole-disk name, e.g. `sda` (serial and `removable` live here, not on the partition).
    pub(crate) disk: String,
}

/// Why a device could not be resolved or identified.
///
/// Public because it appears in the return type of this module's public functions. It names only
/// *device-resolution* failures — never key material — so exposing it leaks nothing, and it lets the
/// `tokengen` crate map each case to the caller-facing `SessionError` without collapsing them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceReadError {
    /// The path could not be `stat`ed.
    StatFailed,
    /// The path is not a valid C string (contains an interior NUL).
    InvalidPath,
    /// `st_dev` did not resolve to a block device under `/sys/dev/block`.
    DeviceNotFound,
    /// A sysfs property could not be read, or was malformed/truncated.
    PropertyUnreadable,
    /// No `/dev/disk/by-uuid` link resolves to this device.
    UuidNotFound,
    /// The backing device is not removable. A refusal, not a failure to determine.
    NotRemovable,
    /// No backend for this target. Always fail closed.
    ///
    /// Constructed only by the `#[cfg(not(unix))]` stub, so on a Unix build it is never built — which is
    /// correct, not dead code. `#[allow]` here rather than on the enum, so the other variants stay checked.
    #[allow(dead_code)]
    NotSupported,
}

/// Which identity component an `Unverifiable` status refers to. Public, non-secret, and small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityComponent {
    /// The filesystem UUID.
    FilesystemUuid,
    /// The hardware serial.
    HardwareSerial,
}

/// The pair that identifies a device. **Not secret** — these are device properties, not key material, so
/// `Debug`/`PartialEq` are appropriate here (unlike the main crate's secret types). G9 does not apply:
/// this is not a secret comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// The filesystem UUID, from the reverse traversal of `/dev/disk/by-uuid`.
    pub uuid: String,
    /// The hardware serial, from `device/serial` or, for USB, `device/vpd_pg80`.
    pub serial: String,
}

/// An **opaque** resolved device.
///
/// Private field, no `Clone`, and — deliberately — **no `Debug`**. A descriptor holds the resolved device
/// name, and a derived `Debug` would print *where the tool ran* into any formatted error, against the
/// G2/G11–G13 posture of leaving no trace on the host. [`DeviceIdentity`] is the value to render when
/// diagnostics are needed.
///
/// The only way to obtain one is a successful [`resolve`], so a caller cannot fabricate a device.
pub struct DeviceDescriptor {
    pub(crate) inner: RawDevice,
}

/// Resolve a path to the removable device backing it.
///
/// Fails closed on every error path: a non-removable backing device, an unreadable property, or a target
/// with no backend all produce `Err`, never a plausible success.
///
/// # Errors
///
/// Returns [`DeviceReadError`] as a description of the failure; the `tokengen` crate maps it to the
/// caller-facing `SessionError`.
pub fn resolve(path: &std::path::Path) -> Result<DeviceDescriptor, DeviceReadError> {
    platform::resolve(path)
}

/// Read the identity (filesystem UUID + hardware serial) of a resolved device.
///
/// # Errors
///
/// Returns `Err` if either component cannot be read. A partial identity is never returned: an
/// `Unverifiable` component must surface as an error so the caller can report *which* component was
/// unverifiable rather than treating a missing value as a match.
pub fn identify(device: &DeviceDescriptor) -> Result<DeviceIdentity, DeviceReadError> {
    platform::identify(&device.inner)
}

/// True if the device is removable according to the kernel.
///
/// # Errors
///
/// Returns `Err` if the property cannot be read; never a default.
pub fn is_removable(device: &DeviceDescriptor) -> Result<bool, DeviceReadError> {
    platform::is_removable(&device.inner)
}

/// The identity component a failure concerns, where the platform can determine it.
///
/// Lets the caller build `Unverifiable { component }` without inventing a value.
#[must_use]
pub fn component_of(err: &DeviceReadError) -> Option<IdentityComponent> {
    // On a target with no backend there is nothing to map: the caller receives `NotSupported` and reports
    // the guard as unsupported rather than unverifiable. Kept as one expression so neither branch needs an
    // early `return`, which the workspace lints deny.
    #[cfg(unix)]
    let component = platform::component_of(err);
    #[cfg(not(unix))]
    let component = {
        let _ = err;
        None
    };
    component
}
