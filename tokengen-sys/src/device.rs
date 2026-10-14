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

    /// How a device is attached, as far as removability is concerned.
    ///
    /// Declared **inside the Unix platform module**, not at crate level, because it is only ever
    /// produced and consumed here. On a target with no backend it does not exist at all — which is why
    /// it is not dead code waiting for an `#[allow]`.
    ///
    /// This placement is deliberate and was forced by a real defect (DEFECT-002 D-2a): a crate-level
    /// enum that only the Unix backend referenced became **dead code on the inverted build**, which
    /// `-D warnings` turns into a compile error — while the gate passed, because it did not deny
    /// warnings. Scoping the type to where it is used fixes the cause rather than silencing the lint.
    ///
    /// Note the form matters: `#[cfg_attr(not(unix), allow(dead_code))]` does **not** work, because
    /// `scripts/cfg_check.sh` inverts `#[cfg(...)]` **textually** and leaves `cfg_attr` alone.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Transport {
        /// A transport whose devices are expected to be physically detachable: usb, mmc, thunderbolt, firewire.
        Removable,
        /// A transport whose devices are normally fixed: nvme, ata, sata, virtio.
        Fixed,
        /// Could not be determined from the device path. Callers must not assume either way.
        Unknown,
    }
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    /// Widen a `dev_t` to `u64`.
    ///
    /// `dev_t` is **`u64` on Linux and `i32` on macOS** (measured: `libc` declares `pub type dev_t = i32`
    /// for apple targets). Returning it directly from a `u64` function is what failed the macOS build
    /// (`error[E0308]`, DEFECT-003).
    ///
    /// This exists as a named function rather than an inline `as u64` for a specific reason: on Linux the
    /// cast is a no-op, clippy flags it as `unnecessary_cast`, and a future contributor would delete it —
    /// silently breaking macOS, where it is load-bearing. One named place, one comment, one reason.
    ///
    /// The widening is lossless for every device number either platform produces; `dev_t` is unsigned in
    /// practice on both.
    ///
    /// # Why this one lint is allowed, and only here
    ///
    /// On Linux the cast is a no-op, and clippy correctly calls it `unnecessary_cast`. On macOS it is
    /// **required**. No single form satisfies both without an allowance — that is the nature of a
    /// platform-dependent type alias.
    ///
    /// The allowance is scoped to this function, is named, and carries this reasoning, so it cannot be
    /// mistaken for a blanket suppression. A crate-wide `-A` would also hide a genuinely unnecessary cast
    /// elsewhere. **This is the narrowest form that keeps macOS compiling and Linux lint-clean.**
    #[allow(clippy::unnecessary_cast)]
    fn dev_t_to_u64(dev: libc::dev_t) -> u64 {
        dev as u64
    }

    /// glibc's `major()`: the high bits above the 8-bit minor field.
    ///
    /// Written out rather than borrowed from a crate — it is three operations, and the project's
    /// dependency budget is deliberate (minimal attack surface; see G7).
    fn major(dev: u64) -> u64 {
        ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64)
    }

    /// glibc's `minor()`.
    fn minor(dev: u64) -> u64 {
        (dev & 0xff) | ((dev >> 12) & !0xffu64)
    }

    /// True if `/sys/dev/block/<maj>:<min>` names an existing block device.
    fn sysfs_block_exists((maj, min): (u64, u64)) -> bool {
        PathBuf::from(format!("/sys/dev/block/{maj}:{min}")).exists()
    }

    /// `stat` the path and return the **device it lives on**, as `(major, minor)`.
    ///
    /// # Two fields, and reading the wrong one silently fails
    ///
    /// A path names a device in one of two ways, and the device is **not** in the same field:
    ///
    /// | the path is a… | the device is in |
    /// |---|---|
    /// | mounted filesystem path (`/`, `/media/x/DRIVE`) | `st_dev` |
    /// | **device node** (`/dev/sda1`) | **`st_rdev`** |
    ///
    /// Measured on this host (`probes/stdev_vs_rdev.py`):
    ///
    /// ```text
    /// /          st_dev -> 259:2  resolves        st_rdev -> 0:0    does not
    /// /dev/sda1  st_dev -> 0:6    DOES NOT        st_rdev -> 8:1    resolves
    /// ```
    ///
    /// Reading `st_dev` alone yields, for a device node, the major:minor of the filesystem the node lives
    /// on (`0:6`) — which resolves to nothing. **So neither field is right for both cases: prefer whichever
    /// one actually resolves.** Choosing by field alone is what made an earlier revision of this function
    /// fail for device nodes, and the failure was silent until it was measured.
    fn device_of(path: &Path) -> Result<(u64, u64), DeviceReadError> {
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

        // `st_dev` first: for a mounted filesystem path this is the backing device, and that is the
        // common case — `cwd` is a directory on a mount.
        // `st_dev` is `dev_t`, which is **u64 on Linux and i32 on macOS** — a real difference this
        // function must not assume away. It goes through `dev_t_to_u64` so the widening happens in one
        // named place: an inline `as u64` here would be flagged by clippy on Linux (where it is a cast
        // to the same type) and removed by a future contributor, silently breaking macOS again.
        // Same shape as D2: a Unix-family cfg assumption that is not uniform across Unix.
        let from_st_dev = (
            major(dev_t_to_u64(st.st_dev)),
            minor(dev_t_to_u64(st.st_dev)),
        );
        if sysfs_block_exists(from_st_dev) {
            return Ok(from_st_dev);
        }

        // Otherwise the path is a device node: its own device is `st_rdev`.
        // Same widening, same reason (see above): `st_rdev` is also `dev_t`.
        let from_st_rdev = (
            major(dev_t_to_u64(st.st_rdev)),
            minor(dev_t_to_u64(st.st_rdev)),
        );
        if sysfs_block_exists(from_st_rdev) {
            return Ok(from_st_rdev);
        }

        // Neither resolved. Failing closed is correct: we cannot say which device this path is on, and
        // guessing would bind identity to the wrong thing.
        Err(DeviceReadError::DeviceNotFound)
    }

    /// Resolve a `(major, minor)` pair to its kernel block-device name, e.g. `sda1`.
    ///
    /// Reads `/sys/dev/block/<maj>:<min>`, a symlink into the device tree. The final component of the
    /// resolved path is the device name (P5).
    fn resolve_block_name(dev: (u64, u64)) -> Result<String, DeviceReadError> {
        let (maj, min) = dev;
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
    /// The kernel's `removable` flag for a whole disk, or `None` if it cannot be read.
    ///
    /// **Secondary signal only** — see [`is_removable_disk`].
    fn removable_flag(disk: &str) -> Option<bool> {
        let p = format!("/sys/block/{disk}/removable");
        match fs::read_to_string(&p).ok()?.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }

    /// The transport a whole disk is attached over, derived from its device path.
    ///
    /// Resolves `/sys/block/<disk>/device` and looks for a controller component. **Depth-independent:**
    /// the device path's length varies by transport (NVMe is shallower than SCSI-over-USB), so walking a
    /// fixed number of `..` levels is fragile. Counting components is not.
    ///
    /// Probed by `probes/transport_removability.py`, and cross-checked against both `/sys/dev/block` and
    /// `lsblk -o TRAN`, which agree.
    fn transport_of(disk: &str) -> Transport {
        let path = format!("/sys/block/{disk}/device");
        let Ok(resolved) = fs::canonicalize(&path) else {
            return Transport::Unknown;
        };
        for component in resolved.components() {
            let name = component.as_os_str().to_string_lossy();
            if let Some(rest) = name.strip_prefix("usb") {
                if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    return Transport::Removable;
                }
            }
            // Other removable transports, listed so the intent is explicit rather than implied.
            for marker in ["mmc", "thunderbolt", "firewire"] {
                if name.starts_with(marker) {
                    return Transport::Removable;
                }
            }
            for marker in ["nvme", "ata", "sata", "virtio"] {
                if name.starts_with(marker) {
                    return Transport::Fixed;
                }
            }
        }
        Transport::Unknown
    }

    /// Decide whether the backing device is removable **for the guard's purposes**.
    ///
    /// # Why the transport, and not `/sys/block/<dev>/removable`
    ///
    /// The kernel flag is **not** a usable proxy for "external". Measured on the maintainer's host:
    ///
    /// | device | transport | flag | actually external |
    /// |---|---|---|---|
    /// | `sda` | usb | `1` | yes (flash drive) |
    /// | `sdb` | usb | **`0`** | **yes (500 GB enclosure)** |
    /// | `nvme0n1` | nvme | `0` | no (internal root) |
    ///
    /// `sdb` and `nvme0n1` are indistinguishable by the flag, but only `sdb` is external. A USB enclosure
    /// whose bridge presents a fixed disk reports `0`. So a **removable transport is authoritative**
    /// (Founder decision, 2026-10-13), and the flag is kept as a **secondary** signal — a device on a
    /// fixed transport that nevertheless reports `1` (e.g. a media slot) is accepted.
    ///
    /// This is **not** a weakening: the flag alone produced a **false refusal** for a legitimate external
    /// drive. The check that matters — that an internal root disk is refused — still holds, because
    /// `nvme` is a fixed transport.
    ///
    /// **Stated limitation, recorded with the feature:** a device soldered internally but attached over
    /// USB cannot be distinguished from an external one, and is accepted. It is not detectable from sysfs.
    /// Refusing every USB device to defend against it would reject every external drive.
    fn is_removable_disk(disk: &str) -> Result<bool, DeviceReadError> {
        match transport_of(disk) {
            Transport::Removable => Ok(true),
            Transport::Fixed => {
                // A fixed transport may still report removable media (e.g. a card-reader slot).
                Ok(removable_flag(disk).unwrap_or(false))
            }
            // Unknown transport: fall back to the flag, and if that is unreadable, fail closed rather
            // than guess. An unfounded `Ok(false)` would refuse silently; an unfounded `Ok(true)` would
            // accept a device we cannot characterise. Reporting the error is the honest third option.
            Transport::Unknown => removable_flag(disk).ok_or(DeviceReadError::PropertyUnreadable),
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
        let dev = device_of(path)?;
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
