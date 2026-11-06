//! Find the host `/etc` entries that are still exactly what the package
//! manager installed.
//!
//! A package-mode host has no pristine copy of its `/etc`, so a 3-way merge
//! against the new image's `/usr/etc` would treat every difference between the
//! host's package versions and the image's as an admin change, and carry the
//! host's copy forward (old PAM or sshd defaults, the compiled SELinux policy,
//! ...). The RPM database records what each package installed, which
//! separates the two: an entry that still matches it is a package default,
//! and the image's version should win. Anything else is the admin's or the
//! machine's: edited files, files no package owns, `%ghost` files such as
//! `machine-id` or `hostname`, and `%config` files whose content RPM doesn't
//! verify, such as `fstab` and `passwd`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use cap_std_ext::cap_std::{
    ambient_authority,
    fs::{Dir, MetadataExt},
};
use cap_std_ext::dirext::CapStdExtDirExt;
use openssl::hash::{MessageDigest, hash};

/// RPM database locations, relative to the host root, newest first.
const RPMDB_PATHS: &[&str] = &["usr/lib/sysimage/rpm", "var/lib/rpm"];
/// Files that mark a directory as an RPM database (sqlite, ndb, bdb).
const RPMDB_FILES: &[&str] = &["rpmdb.sqlite", "Packages.db", "Packages"];

/// One file record per line; `%{=TAG}` repeats a per-package value.
const RPM_QUERYFORMAT: &str = "[%{FILENAMES}\t%{=FILEDIGESTALGO}\t%{FILEDIGESTS}\t%{FILEMODES}\t\
    %{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILELINKTOS}\t%{FILEFLAGS}\t%{FILEVERIFYFLAGS}\t%{FILESIZES}\n]";

/// `RPMFILE_CONFIG`: a configuration file (`%config`).
const RPMFILE_CONFIG: u32 = 1 << 0;
/// `RPMFILE_GHOST`: the package owns the path but doesn't ship its content.
const RPMFILE_GHOST: u32 = 1 << 6;
/// `rpmVerifyAttrs` bits: which attributes `rpm -V` checks for a file.
const RPMVERIFY_FILEDIGEST: u32 = 1 << 0;
const RPMVERIFY_FILESIZE: u32 = 1 << 1;
const RPMVERIFY_LINKTO: u32 = 1 << 2;
const RPMVERIFY_USER: u32 = 1 << 3;
const RPMVERIFY_GROUP: u32 = 1 << 4;
const RPMVERIFY_MODE: u32 = 1 << 6;
const RPMVERIFY_CAPS: u32 = 1 << 8;
/// `rpm -V` reports access ACLs as a mode change, and checks file capabilities.
const XATTR_POSIX_ACL_ACCESS: &str = "system.posix_acl_access";
const XATTR_CAPABILITY: &str = "security.capability";

/// What the RPM database says one package installed at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RpmFile {
    digest_algo: u32,
    digest: String,
    mode: u32,
    user: String,
    group: String,
    link_to: String,
    flags: u32,
    verify_flags: u32,
    size: u64,
}

/// The `/etc` entries (relative to `/etc`) which match a package's record.
#[derive(Debug, Default)]
pub(crate) struct PackageDefaults {
    defaults: BTreeSet<PathBuf>,
    /// Package files the host changed in a way RPM verifies (content or
    /// mode).
    edited: BTreeSet<PathBuf>,
    /// Every path some package owns.
    owned: BTreeSet<PathBuf>,
}

impl PackageDefaults {
    /// Query the host's RPM database and compare its `/etc` records with the
    /// host's files. Fails if the host has no RPM database, since without
    /// one every difference from the image would count as an admin change.
    pub(crate) fn from_rpmdb(root: &Path) -> Result<Self> {
        let dbpath = RPMDB_PATHS
            .iter()
            .find(|dbpath| {
                RPMDB_FILES
                    .iter()
                    .any(|file| root.join(dbpath).join(file).exists())
            })
            .with_context(|| {
                format!(
                    "--merge-etc needs the host's RPM database to tell admin changes in /etc from \
                     package defaults, but none was found under {} ({})",
                    root.display(),
                    RPMDB_PATHS.join(", ")
                )
            })?;
        let output = Command::new("rpm")
            .arg("--root")
            .arg(root)
            .args([
                "--dbpath",
                &format!("/{dbpath}"),
                "-qa",
                "--qf",
                RPM_QUERYFORMAT,
            ])
            .run_get_string()
            .context("Querying the host's RPM database")?;
        let records = parse_rpm_records(&output);
        let root_dir = Dir::open_ambient_dir(root, ambient_authority())
            .with_context(|| format!("Opening {}", root.display()))?;
        let accounts = HostAccounts::load(&root_dir)?;
        let etc = Dir::open_ambient_dir(root.join("etc"), ambient_authority())
            .context("Opening host /etc")?;
        let mut defaults = BTreeSet::new();
        let mut edited = BTreeSet::new();
        let owned = records.keys().cloned().collect();
        for (path, files) in records {
            if files
                .iter()
                .any(|file| host_matches(&etc, &path, file, &accounts))
            {
                defaults.insert(path);
            } else if files.iter().any(|file| host_edited(&etc, &path, file)) {
                edited.insert(path);
            }
        }
        Ok(Self {
            defaults,
            edited,
            owned,
        })
    }

    pub(crate) fn contains(&self, path: &Path) -> bool {
        self.defaults.contains(path)
    }

    /// Whether the host changed a package file at `path` in a way RPM
    /// verifies (its content or mode), i.e. an edit by the admin.
    pub(crate) fn is_edited(&self, path: &Path) -> bool {
        self.edited.contains(path)
    }

    /// Whether some package owns `path`.
    pub(crate) fn is_owned(&self, path: &Path) -> bool {
        self.owned.contains(path)
    }

    #[cfg(test)]
    pub(crate) fn from_paths(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let defaults = paths.into_iter().collect::<BTreeSet<_>>();
        Self {
            owned: defaults.clone(),
            defaults,
            edited: BTreeSet::new(),
        }
    }
}

/// Parse the query output into the records for paths below `/etc`, keyed by
/// their path relative to `/etc`. A path can have records from several
/// packages (shared directories, multilib files).
fn parse_rpm_records(output: &str) -> BTreeMap<PathBuf, Vec<RpmFile>> {
    let mut records = BTreeMap::<PathBuf, Vec<RpmFile>>::new();
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        // Paths containing tabs or newlines can't be parsed from this format;
        // leaving them out treats them as admin changes, the safe side.
        let [
            path,
            algo,
            digest,
            mode,
            user,
            group,
            link_to,
            flags,
            verify_flags,
            size,
        ] = fields[..]
        else {
            continue;
        };
        let Some(relative) = path.strip_prefix("/etc/") else {
            continue;
        };
        let parse_int = |value: &str| value.parse::<i64>().ok().map(|value| value as u32);
        let (Some(mode), Some(flags), Some(verify_flags)) =
            (parse_int(mode), parse_int(flags), parse_int(verify_flags))
        else {
            continue;
        };
        records
            .entry(PathBuf::from(relative))
            .or_default()
            .push(RpmFile {
                // Packages without the tag predate it and use MD5.
                digest_algo: parse_int(algo).unwrap_or(1),
                digest: digest.to_string(),
                mode,
                user: user.to_string(),
                group: group.to_string(),
                link_to: link_to.to_string(),
                flags,
                verify_flags,
                size: size.parse().unwrap_or(u64::MAX),
            });
    }
    records
}

/// Map the host's uids and gids to names, as `rpm -V` compares names.
#[derive(Debug, Default)]
struct HostAccounts {
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
}

impl HostAccounts {
    fn load(root: &Dir) -> Result<Self> {
        use bootc_sysusers::nameservice::{group, passwd};
        let users = passwd::load_etc_passwd(root)?
            .unwrap_or_default()
            .into_iter()
            .map(|entry| (entry.uid, entry.name))
            .collect();
        let groups = group::load_etc_group(root)?
            .into_iter()
            .map(|entry| (entry.gid, entry.name))
            .collect();
        Ok(Self { users, groups })
    }
}

fn message_digest(algo: u32) -> Option<MessageDigest> {
    // PGPHASHALGO values
    match algo {
        1 => Some(MessageDigest::md5()),
        2 => Some(MessageDigest::sha1()),
        8 => Some(MessageDigest::sha256()),
        9 => Some(MessageDigest::sha384()),
        10 => Some(MessageDigest::sha512()),
        11 => Some(MessageDigest::sha224()),
        _ => None,
    }
}

/// Whether the host entry at `path` (relative to `etc`) still matches what
/// the package recorded, checking the attributes `rpm -V` would. Any error
/// reading the host entry counts as a mismatch, so the entry is merged.
fn host_matches(etc: &Dir, path: &Path, file: &RpmFile, accounts: &HostAccounts) -> bool {
    if file.flags & RPMFILE_GHOST != 0 {
        return false;
    }
    let Ok(metadata) = etc.symlink_metadata(path) else {
        return false;
    };
    let verify = |flag: u32| file.verify_flags & flag != 0;
    const S_IFMT: u32 = 0o170000;
    if metadata.mode() & S_IFMT != file.mode & S_IFMT {
        return false;
    }
    if verify(RPMVERIFY_MODE) && metadata.mode() & 0o7777 != file.mode & 0o7777 {
        return false;
    }
    if !metadata.is_symlink() {
        let has_xattr = |name: &str| etc.getxattr(path, name).ok().flatten().is_some();
        if (verify(RPMVERIFY_MODE) && has_xattr(XATTR_POSIX_ACL_ACCESS))
            || (verify(RPMVERIFY_CAPS) && has_xattr(XATTR_CAPABILITY))
        {
            return false;
        }
    }
    if verify(RPMVERIFY_USER) && accounts.users.get(&metadata.uid()) != Some(&file.user) {
        return false;
    }
    if verify(RPMVERIFY_GROUP) && accounts.groups.get(&metadata.gid()) != Some(&file.group) {
        return false;
    }
    if metadata.is_symlink() {
        return !verify(RPMVERIFY_LINKTO)
            || etc
                .read_link_contents(path)
                .is_ok_and(|target| target.as_os_str() == file.link_to.as_str());
    }
    if metadata.is_file() {
        if !verify(RPMVERIFY_FILEDIGEST) {
            // RPM doesn't verify content that is rewritten after install. In
            // a %config file (fstab, passwd, ...) that is the admin's or the
            // machine's state. Otherwise it is generated from package content
            // (e.g. the compiled SELinux policy), and the image's own version
            // should win.
            return file.flags & RPMFILE_CONFIG == 0
                && (!verify(RPMVERIFY_FILESIZE) || metadata.len() == file.size);
        }
        let Some(digest) = message_digest(file.digest_algo) else {
            return false;
        };
        return etc
            .read(path)
            .ok()
            .and_then(|content| hash(digest, &content).ok())
            .is_some_and(|actual| hex::encode(actual) == file.digest);
    }
    true
}

/// Whether the host changed a package's regular file at `path` in a way
/// RPM verifies: its content, or its mode.
fn host_edited(etc: &Dir, path: &Path, file: &RpmFile) -> bool {
    if file.flags & RPMFILE_GHOST != 0 {
        return false;
    }
    let Ok(metadata) = etc.symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    let verify = |flag: u32| file.verify_flags & flag != 0;
    if verify(RPMVERIFY_MODE) && metadata.mode() & 0o7777 != file.mode & 0o7777 {
        return true;
    }
    if !verify(RPMVERIFY_FILEDIGEST) {
        return false;
    }
    let Some(digest) = message_digest(file.digest_algo) else {
        return false;
    };
    etc.read(path)
        .ok()
        .and_then(|content| hash(digest, &content).ok())
        .is_some_and(|actual| hex::encode(actual) != file.digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::fs::PermissionsExt;

    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const VERIFY_ALL: u32 = u32::MAX;

    fn record(mode: u32, digest: &str, link_to: &str, flags: u32, verify_flags: u32) -> RpmFile {
        RpmFile {
            digest_algo: 8,
            digest: digest.into(),
            mode,
            user: "root".into(),
            group: "root".into(),
            link_to: link_to.into(),
            flags,
            verify_flags,
            size: "package default".len() as u64,
        }
    }

    #[test]
    fn rpm_query_output_is_parsed_for_etc_only() {
        let output = concat!(
            "/etc/ssh/sshd_config\t8\tabc\t33152\troot\troot\t\t1\t-1\t10\n",
            "/etc/ssl/certs\t8\t\t41471\troot\troot\t/etc/pki/tls/certs\t0\t-1\t10\n",
            "/etc/machine-id\t\t\t33060\troot\troot\t\t64\t-1\t0\n",
            "/usr/bin/ls\t8\tdef\t33261\troot\troot\t\t0\t-1\t10\n",
            "/etc/bad\tnot enough fields\n",
            "/etc/ssh/sshd_config\t8\tabc\t33152\troot\troot\t\t1\t-1\t10\n",
        );
        let records = parse_rpm_records(output);
        assert_eq!(
            records.keys().collect::<Vec<_>>(),
            ["machine-id", "ssh/sshd_config", "ssl/certs"]
                .map(Path::new)
                .to_vec()
        );
        assert_eq!(records[Path::new("ssh/sshd_config")].len(), 2);
        let sshd = &records[Path::new("ssh/sshd_config")][0];
        assert_eq!((sshd.mode, sshd.verify_flags), (0o100600, u32::MAX));
        let machine_id = &records[Path::new("machine-id")][0];
        assert_eq!(
            (machine_id.digest_algo, machine_id.flags),
            (1, RPMFILE_GHOST)
        );
    }

    #[test]
    fn host_entries_are_compared_like_rpm_verify() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;
        td.write("default.conf", b"package default")?;
        td.write("edited.conf", b"admin edit")?;
        td.write("chmod.conf", b"package default")?;
        td.set_permissions("chmod.conf", PermissionsExt::from_mode(0o600))?;
        td.write("policy.bin", b"regenerated")?;
        td.write("machine-id", b"0123")?;
        td.create_dir("conf.d")?;
        td.symlink_contents("/etc/pki/tls/certs", "certs")?;
        td.symlink_contents("/elsewhere", "relinked")?;

        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let accounts = HostAccounts {
            users: BTreeMap::from([(uid, "root".into())]),
            groups: BTreeMap::from([(gid, "root".into())]),
        };
        let digest = hex::encode(hash(MessageDigest::sha256(), b"package default")?);
        let file_mode = S_IFREG | (td.metadata("default.conf")?.mode() & 0o7777);
        let dir_mode = S_IFDIR | (td.metadata("conf.d")?.mode() & 0o7777);
        let cases = [
            (
                "default.conf",
                record(file_mode, &digest, "", 0, VERIFY_ALL),
                true,
            ),
            (
                "edited.conf",
                record(file_mode, &digest, "", 0, VERIFY_ALL),
                false,
            ),
            (
                "chmod.conf",
                record(file_mode, &digest, "", 0, VERIFY_ALL),
                false,
            ),
            (
                "chmod.conf",
                record(file_mode, &digest, "", 0, VERIFY_ALL & !RPMVERIFY_MODE),
                true,
            ),
            (
                "policy.bin",
                record(
                    file_mode,
                    &digest,
                    "",
                    0,
                    VERIFY_ALL & !RPMVERIFY_FILEDIGEST & !RPMVERIFY_FILESIZE,
                ),
                true,
            ),
            (
                "policy.bin",
                record(
                    file_mode,
                    &digest,
                    "",
                    RPMFILE_CONFIG,
                    VERIFY_ALL & !RPMVERIFY_FILEDIGEST & !RPMVERIFY_FILESIZE,
                ),
                false,
            ),
            (
                "machine-id",
                record(file_mode, &digest, "", RPMFILE_GHOST, VERIFY_ALL),
                false,
            ),
            ("conf.d", record(dir_mode, "", "", 0, VERIFY_ALL), true),
            (
                "conf.d",
                record(file_mode, &digest, "", 0, VERIFY_ALL),
                false,
            ),
            (
                "certs",
                record(S_IFLNK | 0o777, "", "/etc/pki/tls/certs", 0, VERIFY_ALL),
                true,
            ),
            (
                "relinked",
                record(S_IFLNK | 0o777, "", "/etc/pki/tls/certs", 0, VERIFY_ALL),
                false,
            ),
            (
                "missing.conf",
                record(file_mode, &digest, "", 0, VERIFY_ALL),
                false,
            ),
        ];
        for (path, file, expected) in cases {
            assert_eq!(
                host_matches(&td, Path::new(path), &file, &accounts),
                expected,
                "{path}: {file:?}"
            );
        }

        // Unverified content whose verified size changed is not a default.
        let mut sized = record(
            file_mode,
            &digest,
            "",
            0,
            VERIFY_ALL & !RPMVERIFY_FILEDIGEST,
        );
        sized.size = 1;
        assert!(!host_matches(
            &td,
            Path::new("policy.bin"),
            &sized,
            &accounts
        ));

        let verified = record(file_mode, &digest, "", 0, VERIFY_ALL);
        assert!(host_edited(&td, Path::new("edited.conf"), &verified));
        assert!(!host_edited(&td, Path::new("default.conf"), &verified));
        let unverified = record(
            file_mode,
            &digest,
            "",
            0,
            VERIFY_ALL & !RPMVERIFY_FILEDIGEST,
        );
        assert!(!host_edited(&td, Path::new("edited.conf"), &unverified));
        // chmod.conf is 0600 where the package has file_mode.
        assert!(host_edited(&td, Path::new("chmod.conf"), &verified));

        let other_owner = HostAccounts {
            users: BTreeMap::from([(uid, "someone".into())]),
            groups: accounts.groups.clone(),
        };
        let default = record(file_mode, &digest, "", 0, VERIFY_ALL);
        assert!(!host_matches(
            &td,
            Path::new("default.conf"),
            &default,
            &other_owner
        ));
        Ok(())
    }
}
