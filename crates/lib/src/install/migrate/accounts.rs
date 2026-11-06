//! Keep the image's users and groups when the host's account databases are
//! carried into the new `/etc`.
//!
//! `useradd` and package scriptlets edit `/etc/passwd` and friends on every
//! host, so `--merge-etc` always carries the host's copies forward, which
//! would drop accounts the image defines (in its Containerfile, or in packages
//! the host doesn't have). systemd-sysusers recreates only those declared in
//! `sysusers.d`, and with a different id than the files in the image use.
//! So entries the image has and the host doesn't are appended, unless their
//! id is already taken on the host.
//!
//! Images built with nss-altfiles keep their system accounts in
//! `/usr/lib/passwd` and `/usr/lib/group`, which only resolve while
//! `nsswitch.conf` lists `altfiles`. The host's `nsswitch.conf` is carried
//! too and usually doesn't, so those accounts are added to `/etc` as well.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};

const SELINUX_XATTR: &str = "security.selinux";
/// In both group(5) and gshadow(5), the member list is the fourth field.
const MEMBERS_FIELD: usize = 3;
/// In gshadow(5), the group administrators are the third field.
const GSHADOW_ADMINS_FIELD: usize = 2;

/// Account databases, with the shadow database holding their secrets.
/// Groups come first, so that a user's primary group can be checked.
const ACCOUNT_DATABASES: &[(&str, &str)] = &[("group", "gshadow"), ("passwd", "shadow")];
/// The primary group id is the fourth passwd(5) field.
const PRIMARY_GID_FIELD: usize = 3;
/// In both passwd(5) and group(5), the numeric id is the third field.
const ID_FIELD: usize = 2;

/// Name and id of a passwd(5) or group(5) line, or `None` for comments,
/// blank lines and NSS compat entries.
fn entry_name_id(line: &str) -> Option<(&str, &str)> {
    if line.is_empty() || line.starts_with(['#', '+', '-']) {
        return None;
    }
    let mut fields = line.split(':');
    let name = fields.next()?;
    let id = fields.nth(ID_FIELD - 1)?;
    Some((name, id))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MissingEntries<'a> {
    /// Image lines to append.
    lines: Vec<&'a str>,
    /// Why other image entries are not added.
    conflicts: Vec<String>,
}

/// Find the image entries whose name the host database lacks and whose id
/// is free there. `check` can veto an entry with a reason (used for a user's
/// primary group).
fn missing_entries<'a>(
    image: &'a str,
    host: &str,
    check: impl Fn(&str) -> Option<String>,
) -> MissingEntries<'a> {
    let mut known = host
        .lines()
        .filter_map(entry_name_id)
        .map(|(name, id)| (name.to_string(), id.to_string()))
        .collect::<Vec<_>>();
    let mut missing = MissingEntries::default();
    for line in image.lines() {
        let Some((name, id)) = entry_name_id(line) else {
            continue;
        };
        if let Some((_, host_id)) = known.iter().find(|(known_name, _)| known_name == name) {
            if host_id != id {
                missing.conflicts.push(format!(
                    "{name}: id {host_id} on the host, {id} in the image"
                ));
            }
            continue;
        }
        if let Some((host_name, _)) = known.iter().find(|(_, known_id)| known_id == id) {
            missing.conflicts.push(format!(
                "{name}: id {id} is used by {host_name} on the host"
            ));
            continue;
        }
        if let Some(reason) = check(line) {
            missing.conflicts.push(format!("{name}: {reason}"));
            continue;
        }
        known.push((name.to_string(), id.to_string()));
        missing.lines.push(line);
    }
    missing
}

/// Map group ids to names in a group(5) database.
fn group_names(group: &str) -> Vec<(&str, &str)> {
    group
        .lines()
        .filter_map(entry_name_id)
        .map(|(name, id)| (id, name))
        .collect()
}

/// The shadow lines for `names` from the image that the host lacks.
fn missing_shadow_entries<'a>(image: &'a str, host: &str, names: &BTreeSet<&str>) -> Vec<&'a str> {
    let host_names = host
        .lines()
        .filter_map(|line| line.split(':').next())
        .collect::<BTreeSet<_>>();
    image
        .lines()
        .filter(|line| {
            line.split(':')
                .next()
                .is_some_and(|name| names.contains(name) && !host_names.contains(name))
        })
        .collect()
}

/// Append `lines` to `name` in `etc`, keeping the file's inode and so its
/// mode, owner and SELinux label.
fn append_lines(etc: &Dir, name: &str, current: &str, lines: &[impl AsRef<str>]) -> Result<()> {
    let mut content = current.to_string();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    for line in lines {
        content.push_str(line.as_ref());
        content.push('\n');
    }
    replace_file(etc, name, &content)
}

/// Replace `name` in `etc` with `content` atomically, keeping its mode,
/// owner and SELinux label: by now this `/etc` belongs to the only
/// deployment the host can boot.
fn replace_file(etc: &Dir, name: &str, content: &str) -> Result<()> {
    use cap_std_ext::cap_std::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::io::Write;

    let write = || -> Result<()> {
        let metadata = etc.metadata(name)?;
        let label = etc.getxattr(name, SELINUX_XATTR)?;
        let temp = format!(".{name}.bootc-merge");
        etc.remove_file_optional(&temp)?;
        // Readable only by root until it has the original's mode: this may
        // be shadow.
        let mut file = etc.open_with(
            &temp,
            cap_std_ext::cap_std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600),
        )?;
        rustix::fs::fchown(
            &file,
            Some(rustix::fs::Uid::from_raw(metadata.uid())),
            Some(rustix::fs::Gid::from_raw(metadata.gid())),
        )?;
        if let Some(label) = label {
            rustix::fs::fsetxattr(
                &file,
                SELINUX_XATTR,
                &label,
                rustix::fs::XattrFlags::empty(),
            )?;
        }
        file.set_permissions(PermissionsExt::from_mode(metadata.mode() & 0o7777))?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        etc.rename(&temp, etc, name)?;
        Ok(())
    };
    write().with_context(|| format!("Writing /etc/{name}"))
}

/// Copies of `lines` with the given colon-separated `fields` emptied.
fn without_fields(lines: &[&str], fields: &[usize]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            line.split(':')
                .enumerate()
                .map(|(index, field)| if fields.contains(&index) { "" } else { field })
                .collect::<Vec<_>>()
                .join(":")
        })
        .collect()
}

/// Add the members the image lists for groups both sides have, so that e.g.
/// a user the image put in `wheel` stays there. `members_field` is the
/// comma-separated member list's index, and `eligible` says which users may
/// be added (the same account on both sides). Returns the new content and the
/// `group(member)` additions, or `None` if nothing changes.
fn add_group_members(
    image: &str,
    merged: &str,
    members_field: usize,
    eligible: impl Fn(&str) -> bool,
) -> Option<(String, Vec<String>)> {
    let members = |line: &str| -> Vec<String> {
        line.split(':')
            .nth(members_field)
            .map(|field| {
                field
                    .split(',')
                    .filter(|member| !member.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut added = Vec::new();
    let mut content = String::new();
    for line in merged.lines() {
        let image_line = entry_name(line).and_then(|name| {
            image
                .lines()
                .find(|image_line| entry_name(image_line) == Some(name))
        });
        let mut fields = line.split(':').map(str::to_string).collect::<Vec<_>>();
        if let Some(image_line) = image_line
            && fields.len() > members_field
        {
            let mut current = members(line);
            for member in members(image_line) {
                if !current.contains(&member) && eligible(&member) {
                    added.push(format!("{}({member})", fields[0]));
                    current.push(member);
                }
            }
            fields[members_field] = current.join(",");
        }
        content.push_str(&fields.join(":"));
        content.push('\n');
    }
    (!added.is_empty()).then_some((content, added))
}

/// The name of a group(5)/gshadow(5) line, or `None` for comments etc.
fn entry_name(line: &str) -> Option<&str> {
    if line.is_empty() || line.starts_with(['#', '+', '-']) {
        return None;
    }
    line.split(':').next()
}

/// Whether `nsswitch.conf` in `etc` resolves `database` through nss-altfiles.
/// It is usually a symlink to `/etc/authselect/nsswitch.conf`.
fn uses_altfiles(etc: &Dir, database: &str) -> Result<bool> {
    const NSSWITCH: &str = "nsswitch.conf";
    let path = match etc.symlink_metadata_optional(NSSWITCH)? {
        Some(metadata) if metadata.is_symlink() => {
            let target = etc.read_link_contents(NSSWITCH)?;
            match target.strip_prefix("/etc") {
                Ok(relative) => relative.to_owned(),
                Err(_) => target,
            }
        }
        Some(_) => NSSWITCH.into(),
        None => return Ok(false),
    };
    let Some(content) = etc.read_to_string_optional(&path)? else {
        return Ok(false);
    };
    Ok(content.lines().any(|line| {
        let line = line.split_once('#').map_or(line, |(line, _)| line);
        line.split_once(':').is_some_and(|(key, sources)| {
            key.trim() == database && sources.split_whitespace().any(|s| s == "altfiles")
        })
    }))
}

/// The image's `database`, plus its nss-altfiles one when the merged
/// `nsswitch.conf` won't resolve that.
fn read_with_altfiles(
    image_etc: &Dir,
    image_lib: Option<&Dir>,
    merged_etc: &Dir,
    database: &str,
) -> Result<String> {
    let mut image = image_etc
        .read_to_string_optional(database)?
        .unwrap_or_default();
    if let Some(image_lib) = image_lib
        && !uses_altfiles(merged_etc, database)?
        && let Some(altfiles) = image_lib.read_to_string_optional(database)?
    {
        if !image.is_empty() && !image.ends_with('\n') {
            image.push('\n');
        }
        image.push_str(&altfiles);
    }
    Ok(image)
}

/// Append the image's accounts that the merged `/etc` lacks. `image_etc` is
/// the image's pristine `/etc` (`/usr/etc` in the deployment), `image_lib`
/// its `/usr/lib` (for nss-altfiles), and `merged_etc` the deployment's `/etc`
/// after the merge.
pub(crate) fn add_image_accounts(
    image_etc: &Dir,
    image_lib: Option<&Dir>,
    merged_etc: &Dir,
    verbose: bool,
) -> Result<()> {
    for (database, shadow) in ACCOUNT_DATABASES {
        let Some(merged) = merged_etc.read_to_string_optional(database)? else {
            continue;
        };
        let image = read_with_altfiles(image_etc, image_lib, merged_etc, database)?;
        // A user is only added if its primary group id names the same group
        // on the host (after the group pass) as in the image.
        let (image_groups, merged_groups) = if *database == "passwd" {
            (
                read_with_altfiles(image_etc, image_lib, merged_etc, "group")?,
                merged_etc
                    .read_to_string_optional("group")?
                    .unwrap_or_default(),
            )
        } else {
            Default::default()
        };
        let (image_groups, merged_groups) =
            (group_names(&image_groups), group_names(&merged_groups));
        let missing = missing_entries(&image, &merged, |line| {
            if *database != "passwd" {
                return None;
            }
            let gid = line.split(':').nth(PRIMARY_GID_FIELD)?;
            let image_group = image_groups.iter().find(|(id, _)| *id == gid).map(|g| g.1);
            let merged_group = merged_groups.iter().find(|(id, _)| *id == gid).map(|g| g.1);
            (image_group != merged_group).then(|| {
                format!(
                    "its primary group {gid} is {} on the host",
                    merged_group.unwrap_or("missing")
                )
            })
        });
        for conflict in &missing.conflicts {
            println!("  Image {database} entry not added: {conflict}");
        }
        if missing.lines.is_empty() {
            continue;
        }
        let names = missing
            .lines
            .iter()
            .filter_map(|line| entry_name_id(line).map(|(name, _)| name))
            .collect::<BTreeSet<_>>();
        if verbose {
            println!(
                "  Adding the image's {database} entries: {}",
                names.iter().copied().collect::<Vec<_>>().join(", ")
            );
        }
        // Appended groups start without members (or gshadow admins): the
        // member pass below adds those that are the same account here.
        let member_fields: &[usize] = match *database {
            "group" => &[MEMBERS_FIELD],
            _ => &[],
        };
        let lines = without_fields(&missing.lines, member_fields);
        append_lines(merged_etc, database, &merged, &lines)?;

        if let (Some(image_shadow), Some(merged_shadow)) = (
            image_etc.read_to_string_optional(shadow)?,
            merged_etc.read_to_string_optional(shadow)?,
        ) {
            let lines = missing_shadow_entries(&image_shadow, &merged_shadow, &names);
            let member_fields: &[usize] = match *shadow {
                "gshadow" => &[GSHADOW_ADMINS_FIELD, MEMBERS_FIELD],
                _ => &[],
            };
            let lines = without_fields(&lines, member_fields);
            if !lines.is_empty() {
                append_lines(merged_etc, shadow, &merged_shadow, &lines)?;
            }
        }
    }

    // Only users that are the same account on both sides (same name and
    // uid, including those just appended) get the image's memberships.
    let user_ids = |passwd: &str| -> Vec<(String, String)> {
        passwd
            .lines()
            .filter_map(entry_name_id)
            .map(|(name, id)| (name.to_string(), id.to_string()))
            .collect()
    };
    let image_users = user_ids(&read_with_altfiles(
        image_etc, image_lib, merged_etc, "passwd",
    )?);
    let merged_users = user_ids(
        &merged_etc
            .read_to_string_optional("passwd")?
            .unwrap_or_default(),
    );
    let eligible = |name: &str| {
        let uid = |users: &[(String, String)]| {
            users
                .iter()
                .find(|(user, _)| user == name)
                .map(|(_, id)| id.clone())
        };
        uid(&image_users).is_some_and(|id| uid(&merged_users) == Some(id))
    };
    // Members, and in gshadow also the group administrators.
    for (database, fields) in [
        ("group", &[MEMBERS_FIELD][..]),
        ("gshadow", &[GSHADOW_ADMINS_FIELD, MEMBERS_FIELD][..]),
    ] {
        let image = if database == "group" {
            read_with_altfiles(image_etc, image_lib, merged_etc, database)?
        } else {
            image_etc
                .read_to_string_optional(database)?
                .unwrap_or_default()
        };
        for &field in fields {
            let Some(merged) = merged_etc.read_to_string_optional(database)? else {
                continue;
            };
            if let Some((content, added)) = add_group_members(&image, &merged, field, eligible) {
                if verbose && database == "group" {
                    println!("  Adding the image's group members: {}", added.join(", "));
                }
                replace_file(merged_etc, database, &content)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::ambient_authority;

    #[test]
    fn missing_entries_skip_known_names_and_taken_ids() {
        let image = "root:x:0:0:root:/root:/bin/bash\n\
                     imguser:x:950:950::/var/lib/imguser:/sbin/nologin\n\
                     imguser:x:950:950::/var/lib/imguser:/sbin/nologin\n\
                     clash:x:1000:1000::/home/clash:/bin/bash\n\
                     bob:x:1001:1001::/home/bob:/bin/bash\n\
                     vetoed:x:960:960::/:/sbin/nologin\n\
                     # comment\n\
                     +nis\n";
        let host = "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n";
        let missing = missing_entries(image, host, |line| {
            line.starts_with("vetoed:").then(|| "vetoed".to_string())
        });
        assert_eq!(
            missing,
            MissingEntries {
                lines: vec!["imguser:x:950:950::/var/lib/imguser:/sbin/nologin"],
                conflicts: vec![
                    "clash: id 1000 is used by bob on the host".to_string(),
                    "bob: id 1000 on the host, 1001 in the image".to_string(),
                    "vetoed: vetoed".to_string(),
                ],
            }
        );
        assert_eq!(
            missing_entries(host, host, |_| None),
            MissingEntries::default()
        );
    }

    #[test]
    fn image_group_members_are_added_to_shared_groups() {
        let image = "wheel:x:10:imgadmin,stranger\nusers:x:100:\nimgonly:x:900:a\n";
        let merged = "wheel:x:10:alice\nusers:x:100:bob\n# comment\n";
        assert_eq!(
            add_group_members(image, merged, MEMBERS_FIELD, |user| user == "imgadmin"),
            Some((
                "wheel:x:10:alice,imgadmin\nusers:x:100:bob\n# comment\n".to_string(),
                vec!["wheel(imgadmin)".to_string()]
            ))
        );
        assert_eq!(
            add_group_members(merged, merged, MEMBERS_FIELD, |_| true),
            None
        );
    }

    #[test]
    fn appended_groups_only_keep_members_that_are_the_same_account() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;
        for dir in ["image", "merged"] {
            td.create_dir(dir)?;
        }
        let image = td.open_dir("image")?;
        let merged = td.open_dir("merged")?;
        image.write(
            "passwd",
            "core:x:1000:1000::/home/core:/bin/bash\nsvc:x:950:950::/:/sbin/nologin\n",
        )?;
        image.write(
            "group",
            "core:x:1000:\nsvc:x:950:\nappadmins:x:951:core,svc\n",
        )?;
        image.write(
            "gshadow",
            "core:!::\nsvc:!::\nappadmins:!:core,svc:core,svc\n",
        )?;
        // The host's core is a different account.
        merged.write("passwd", "core:x:1002:1002::/home/core:/bin/bash\n")?;
        merged.write("group", "core:x:1002:\n")?;
        merged.write("gshadow", "core:!::\n")?;

        add_image_accounts(&image, None, &merged, false)?;

        assert_eq!(
            merged.read_to_string("group")?,
            "core:x:1002:\nsvc:x:950:\nappadmins:x:951:svc\n"
        );
        assert_eq!(
            merged.read_to_string("gshadow")?,
            "core:!::\nsvc:!::\nappadmins:!:svc:svc\n"
        );
        Ok(())
    }

    #[test]
    fn users_whose_primary_group_differs_are_not_added() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;
        for dir in ["image", "merged"] {
            td.create_dir(dir)?;
        }
        let image = td.open_dir("image")?;
        let merged = td.open_dir("merged")?;
        image.write(
            "passwd",
            "svc:x:950:951::/:/sbin/nologin\nok:x:952:952::/:/sbin/nologin\n",
        )?;
        image.write("group", "svcgrp:x:951:\nokgrp:x:952:\n")?;
        merged.write("passwd", "root:x:0:0::/root:/bin/bash\n")?;
        // gid 951 belongs to an unrelated host group.
        merged.write("group", "root:x:0:\nhostgrp:x:951:\n")?;

        add_image_accounts(&image, None, &merged, false)?;

        assert_eq!(
            merged.read_to_string("group")?,
            "root:x:0:\nhostgrp:x:951:\nokgrp:x:952:\n"
        );
        assert_eq!(
            merged.read_to_string("passwd")?,
            "root:x:0:0::/root:/bin/bash\nok:x:952:952::/:/sbin/nologin\n"
        );
        Ok(())
    }

    #[test]
    fn image_accounts_are_appended_with_their_shadow_entries() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;
        for dir in ["image", "merged"] {
            td.create_dir(dir)?;
        }
        let image = td.open_dir("image")?;
        let merged = td.open_dir("merged")?;
        image.write(
            "passwd",
            "root:x:0:0::/root:/bin/bash\nimguser:x:950:951::/:/sbin/nologin\n",
        )?;
        image.write("shadow", "root:!::0:::::\nimguser:!*::0:::::\n")?;
        image.write("group", "root:x:0:\nimggroup:x:951:\n")?;
        image.write("gshadow", "root:::\nimggroup:!::\n")?;
        // No trailing newline on the host's passwd.
        merged.write(
            "passwd",
            "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash",
        )?;
        merged.write("shadow", "root:!::0:::::\nbob:$6$x::0:::::\n")?;
        merged.write("group", "root:x:0:\nbob:x:1000:\n")?;
        merged.write("gshadow", "root:::\nbob:!::\n")?;

        add_image_accounts(&image, None, &merged, false)?;
        add_image_accounts(&image, None, &merged, false)?;

        assert_eq!(
            merged.read_to_string("passwd")?,
            "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n\
             imguser:x:950:951::/:/sbin/nologin\n"
        );
        assert_eq!(
            merged.read_to_string("shadow")?,
            "root:!::0:::::\nbob:$6$x::0:::::\nimguser:!*::0:::::\n"
        );
        assert_eq!(
            merged.read_to_string("group")?,
            "root:x:0:\nbob:x:1000:\nimggroup:x:951:\n"
        );
        assert_eq!(
            merged.read_to_string("gshadow")?,
            "root:::\nbob:!::\nimggroup:!::\n"
        );
        Ok(())
    }

    #[test]
    fn altfiles_accounts_are_added_unless_nsswitch_uses_altfiles() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;
        for dir in ["image", "lib", "merged", "merged/authselect"] {
            td.create_dir(dir)?;
        }
        let image = td.open_dir("image")?;
        let lib = td.open_dir("lib")?;
        let merged = td.open_dir("merged")?;
        image.write("passwd", "root:x:0:0::/root:/bin/bash\n")?;
        image.write("group", "root:x:0:\n")?;
        lib.write(
            "passwd",
            "avahi:x:70:70::/var/run/avahi-daemon:/sbin/nologin\n",
        )?;
        lib.write("group", "avahi:x:70:\n")?;
        merged.write("passwd", "root:x:0:0::/root:/bin/bash\n")?;
        merged.write("group", "root:x:0:\n")?;
        merged.symlink_contents("/etc/authselect/nsswitch.conf", "nsswitch.conf")?;

        // With altfiles in nsswitch.conf, /usr/lib/passwd already resolves.
        merged.write(
            "authselect/nsswitch.conf",
            "passwd:     files altfiles systemd\ngroup:      files [SUCCESS=merge] altfiles\n",
        )?;
        assert!(uses_altfiles(&merged, "passwd")? && uses_altfiles(&merged, "group")?);
        add_image_accounts(&image, Some(&lib), &merged, false)?;
        assert_eq!(
            merged.read_to_string("passwd")?,
            "root:x:0:0::/root:/bin/bash\n"
        );

        // The host's nsswitch.conf, without it.
        merged.write(
            "authselect/nsswitch.conf",
            "passwd:     files systemd\ngroup:      files [SUCCESS=merge] systemd\n",
        )?;
        assert!(!uses_altfiles(&merged, "passwd")?);
        add_image_accounts(&image, Some(&lib), &merged, false)?;
        assert_eq!(
            merged.read_to_string("passwd")?,
            "root:x:0:0::/root:/bin/bash\navahi:x:70:70::/var/run/avahi-daemon:/sbin/nologin\n"
        );
        assert_eq!(merged.read_to_string("group")?, "root:x:0:\navahi:x:70:\n");
        Ok(())
    }
}
