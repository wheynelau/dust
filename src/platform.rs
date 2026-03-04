#[allow(unused_imports)]
use std::fs;

use std::path::{Path, PathBuf};

#[cfg(target_family = "unix")]
fn get_block_size() -> u64 {
    // All os specific implementations of MetadataExt seem to define a block as 512 bytes
    // https://doc.rust-lang.org/std/os/linux/fs/trait.MetadataExt.html#tymethod.st_blocks
    512
}

type InodeAndDevice = (u64, u64);
type FileTime = (i64, i64, i64);

#[cfg(target_family = "unix")]
pub fn get_metadata<P: AsRef<Path>>(
    path: P,
    use_apparent_size: bool,
    follow_links: bool,
) -> Option<(u64, Option<InodeAndDevice>, FileTime)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = if follow_links {
        path.as_ref().metadata()
    } else {
        path.as_ref().symlink_metadata()
    };
    match metadata {
        Ok(md) => {
            let file_size = md.len();
            if use_apparent_size {
                Some((
                    file_size,
                    Some((md.ino(), md.dev())),
                    (md.mtime(), md.atime(), md.ctime()),
                ))
            } else {
                // On NTFS mounts, the reported block count can be unexpectedly large.
                // To avoid overestimating disk usage, cap the allocated size to what the
                // file should occupy based on the file system I/O block size (blksize).
                // Related: https://github.com/bootandy/dust/issues/295
                let blksize = md.blksize();
                let target_size = file_size.div_ceil(blksize) * blksize;
                let reported_size = md.blocks() * get_block_size();

                // File systems can pre-allocate more space for a file than what would be necessary
                let pre_allocation_buffer = blksize * 65536;
                let max_size = target_size + pre_allocation_buffer;
                let allocated_size = if reported_size > max_size {
                    target_size
                } else {
                    reported_size
                };
                Some((
                    allocated_size,
                    Some((md.ino(), md.dev())),
                    (md.mtime(), md.atime(), md.ctime()),
                ))
            }
        }
        Err(_e) => None,
    }
}

#[cfg(target_family = "windows")]
pub fn get_metadata<P: AsRef<Path>>(
    path: P,
    use_apparent_size: bool,
    follow_links: bool,
) -> Option<(u64, Option<InodeAndDevice>, FileTime)> {
    // On windows opening the file to get size, file ID and volume can be very
    // expensive because 1) it causes a few system calls, and more importantly 2) it can cause
    // windows defender to scan the file.
    // Therefore we try to avoid doing that for common cases, mainly those of
    // plain files:

    // The idea is to make do with the file size that we get from the OS for
    // free as part of iterating a folder. Therefore we want to make sure that
    // it makes sense to use that free size information:

    // Volume boundaries:
    // The user can ask us not to cross volume boundaries. If the DirEntry is a
    // plain file and not a reparse point or other non-trivial stuff, we assume
    // that the file is located on the same volume as the directory that
    // contains it.

    // File ID:
    // This optimization does deprive us of access to a file ID. As a
    // workaround, we just make one up that hopefully does not collide with real
    // file IDs.
    // Hard links: Unresolved. We don't get inode/file index, so hard links
    // count once for each link. Hopefully they are not too commonly in use on
    // windows.

    // Size:
    // We assume (naively?) that for the common cases the free size info is the
    // same as one would get by doing the expensive thing. Sparse, encrypted and
    // compressed files are not included in the common cases, as one can image
    // there being more than view on their size.

    // Savings in orders of magnitude in terms of time, io and cpu have been
    // observed on hdd, windows 10, some 100Ks files taking up some hundreds of
    // GBs:
    // Consistently opening the file: 30 minutes.
    // With this optimization:         8 sec.

    use std::io;
    use winapi_util::Handle;
    fn handle_from_path_limited(path: &Path) -> io::Result<Handle> {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;

        // So, it seems that it does does have to be that expensive to open
        // files to get their info: Avoiding opening the file with the full
        // GENERIC_READ is key:

        // https://docs.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights:
        // "For example, a Windows file object maps the GENERIC_READ bit to the
        // READ_CONTROL and SYNCHRONIZE standard access rights and to the
        // FILE_READ_DATA, FILE_READ_EA, and FILE_READ_ATTRIBUTES
        // object-specific access rights"

        // The flag FILE_READ_DATA seems to be the expensive one, so we'll avoid
        // that, and a most of the other ones. Simply because it seems that we
        // don't need them.

        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .open(path)?;
        Ok(Handle::from_file(file))
    }

    fn get_metadata_expensive(
        path: &Path,
        use_apparent_size: bool,
    ) -> Option<(u64, Option<InodeAndDevice>, FileTime)> {
        use winapi_util::file::information;

        let h = handle_from_path_limited(path).ok()?;
        let info = information(&h).ok()?;

        if use_apparent_size {
            use filesize::PathExt;
            Some((
                path.size_on_disk().ok()?,
                Some((info.file_index(), info.volume_serial_number())),
                (
                    info.last_write_time().unwrap() as i64,
                    info.last_access_time().unwrap() as i64,
                    info.creation_time().unwrap() as i64,
                ),
            ))
        } else {
            Some((
                info.file_size(),
                Some((info.file_index(), info.volume_serial_number())),
                (
                    info.last_write_time().unwrap() as i64,
                    info.last_access_time().unwrap() as i64,
                    info.creation_time().unwrap() as i64,
                ),
            ))
        }
    }

    use std::os::windows::fs::MetadataExt;
    let path = path.as_ref();
    let metadata = if follow_links {
        path.metadata()
    } else {
        path.symlink_metadata()
    };
    match metadata {
        Ok(ref md) => {
            const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
            const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;
            const FILE_ATTRIBUTE_SYSTEM: u32 = 0x04;
            const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
            const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x00000200;
            const FILE_ATTRIBUTE_PINNED: u32 = 0x00080000;
            const FILE_ATTRIBUTE_UNPINNED: u32 = 0x00100000;
            const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x00040000;
            const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x00400000;
            const FILE_ATTRIBUTE_OFFLINE: u32 = 0x00001000;
            // normally FILE_ATTRIBUTE_SPARSE_FILE would be enough, however Windows sometimes likes to mask it out. see: https://stackoverflow.com/q/54560454
            const IS_PROBABLY_ONEDRIVE: u32 = FILE_ATTRIBUTE_SPARSE_FILE
                | FILE_ATTRIBUTE_PINNED
                | FILE_ATTRIBUTE_UNPINNED
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                | FILE_ATTRIBUTE_OFFLINE;
            let attr_filtered = md.file_attributes()
                & !(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM);
            if ((attr_filtered & FILE_ATTRIBUTE_ARCHIVE) != 0
                || (attr_filtered & FILE_ATTRIBUTE_DIRECTORY) != 0
                || md.file_attributes() == FILE_ATTRIBUTE_NORMAL)
                && !((attr_filtered & IS_PROBABLY_ONEDRIVE != 0) && use_apparent_size)
            {
                Some((
                    md.len(),
                    None,
                    (
                        md.last_write_time() as i64,
                        md.last_access_time() as i64,
                        md.creation_time() as i64,
                    ),
                ))
            } else {
                get_metadata_expensive(path, use_apparent_size)
            }
        }
        _ => get_metadata_expensive(path, use_apparent_size),
    }
}

#[cfg(target_os = "macos")]
pub fn expand_with_firmlinks(paths: &mut Vec<PathBuf>) {
    let Ok(content) = std::fs::read_to_string("/usr/share/firmlinks") else {
        return;
    };

    let firmlinks: Vec<(PathBuf, PathBuf)> = get_firmlinked_paths(content);

    let cwd = std::env::current_dir().ok();
    let extras = expand_firmlinks_inner(paths, &firmlinks, cwd.as_ref());

    paths.extend(extras);
}

// this calls try_match_path on both the original path and the canonicalized path
#[cfg(target_os = "macos")]
fn expand_firmlinks_inner(
    paths: &[PathBuf],
    firmlinks: &[(PathBuf, PathBuf)],
    cwd: Option<&PathBuf>,
) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|path| {
            // Try matching original path first
            if let Some(expanded) = try_match_path(path, firmlinks) {
                return Some(expanded);
            }

            // For relative paths, join with CWD to make them absolute
            let path_to_canonicalize = if !path.is_absolute() {
                if let Some(cwd) = cwd {
                    cwd.join(path)
                } else {
                    return None;
                }
            } else {
                path.clone()
            };

            // Try canonicalizing (resolves .. components)
            // e.g., ../Users (from /bin) -> /bin/../Users -> /Users
            if let Ok(canonical) = std::fs::canonicalize(&path_to_canonicalize)
                && let Some(expanded) = try_match_path(&canonical, firmlinks)
            {
                return Some(expanded);
            }

            None
        })
        .collect()
}
/// Given a path to ignore and a list of firmlinks, try to find a corresponding path on the other side of the firmlink.
/// For example, if the path is /System/Library and there is a firmlink mapping /System/Library to /System/Volumes/Data/System/Library,
/// then this function will return /System/Volumes/Data/System/Library.
/// The role of this is expanding the paths, so that both sides of the firmlink are considered when we check if a file is ignored or not.
#[cfg(target_os = "macos")]
fn try_match_path(path: &Path, firmlinks: &[(PathBuf, PathBuf)]) -> Option<PathBuf> {
    firmlinks.iter().find_map(|(src, dst)| {
        if path.starts_with(src) {
            Some(dst.join(path.strip_prefix(src).unwrap()))
        } else if path.starts_with(dst) {
            Some(src.join(path.strip_prefix(dst).unwrap()))
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
fn get_firmlinked_paths(firmlink_string: String) -> Vec<(PathBuf, PathBuf)> {
    firmlink_string
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let src = PathBuf::from(parts.next()?);
            let dst = PathBuf::from("/System/Volumes/Data").join(parts.next()?);
            Some((src, dst))
        })
        .collect()
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    #[test]
    fn test_get_firmlinked_paths() {
        let firmlink_string = "/System/Library\t/System/Volumes/Data/System/Library\n/Applications\t/System/Volumes/Data/Applications";
        let expected = vec![
            (
                PathBuf::from("/System/Library"),
                PathBuf::from("/System/Volumes/Data/System/Library"),
            ),
            (
                PathBuf::from("/Applications"),
                PathBuf::from("/System/Volumes/Data/Applications"),
            ),
        ];
        assert_eq!(get_firmlinked_paths(firmlink_string.to_string()), expected);
    }

    #[test]
    fn test_expand_firmlinks_with_absolute_path() {
        // Simple test, you run -X Users with the input path of /
        let firmlinks = vec![(
            PathBuf::from("/Users"),
            PathBuf::from("/System/Volumes/Data/Users"),
        )];
        let paths: Vec<PathBuf> = vec![PathBuf::from("/Users")];
        let extras = expand_firmlinks_inner(&paths, &firmlinks, None);
        assert!(
            extras.contains(&PathBuf::from("/System/Volumes/Data/Users")),
            "Expected /System/Volumes/Data/Users in extras, got: {:?}",
            extras
        );
    }

    #[test]
    fn test_expand_firmlinks_with_nested_absolute_path() {
        // Test with nested absolute path - should work
        let firmlinks = vec![(
            PathBuf::from("/Users"),
            PathBuf::from("/System/Volumes/Data/Users"),
        )];
        let paths: Vec<PathBuf> = vec![PathBuf::from("/Users/employee")];
        let extras = expand_firmlinks_inner(&paths, &firmlinks, None);
        assert!(
            extras.contains(&PathBuf::from("/System/Volumes/Data/Users/employee")),
            "Expected /System/Volumes/Data/Users/employee in extras, got: {:?}",
            extras
        );
    }

    #[test]
    fn test_expand_firmlinks_with_relative_path() {
        // Test with relative path like ./Users - should NOT match
        // ./Users is relative to CWD, NOT equivalent to /Users
        // This also means that if the user runs ./Users in /, it will break
        let firmlinks = vec![(
            PathBuf::from("/Users"),
            PathBuf::from("/System/Volumes/Data/Users"),
        )];
        let paths: Vec<PathBuf> = vec![PathBuf::from("./Users")];
        let extras = expand_firmlinks_inner(&paths, &firmlinks, None);
        assert!(
            extras.is_empty(),
            "Relative path ./Users should NOT match firmlink /Users, got: {:?}",
            extras
        );
    }

    #[test]
    fn test_expand_firmlinks_with_parent_path() {
        // Test with parent path like /bin/../Users - NOW FIXED
        // Parent paths should now canonicalize and match firmlinks
        let firmlinks = vec![(
            PathBuf::from("/Users"),
            PathBuf::from("/System/Volumes/Data/Users"),
        )];
        let paths: Vec<PathBuf> = vec![PathBuf::from("/bin/../Users")];
        let extras = expand_firmlinks_inner(&paths, &firmlinks, None);
        assert!(
            extras.contains(&PathBuf::from("/System/Volumes/Data/Users")),
            "Path /bin/../Users should canonicalize and match firmlink /Users, got: {:?}",
            extras
        );
    }

    #[test]
    fn test_expand_firmlinks_with_dst_side() {
        // Test matching against the dst side of firmlink
        let firmlinks = vec![(
            PathBuf::from("/Users"),
            PathBuf::from("/System/Volumes/Data/Users"),
        )];
        let paths: Vec<PathBuf> = vec![PathBuf::from("/System/Volumes/Data/Users")];
        let extras = expand_firmlinks_inner(&paths, &firmlinks, None);
        assert!(
            extras.contains(&PathBuf::from("/Users")),
            "Expected /Users in extras, got: {:?}",
            extras
        );
    }
    #[test]
    fn test_expand_firmlinks_with_cwd() {
        // Test: ../Users with CWD=/bin should resolve to /Users
        // This simulates: user runs `dust -X Users ../` from /bin directory
        let firmlinks = vec![(
            PathBuf::from("/Users"),
            PathBuf::from("/System/Volumes/Data/Users"),
        )];
        let paths: Vec<PathBuf> = vec![PathBuf::from("../Users")];
        let mock_cwd = PathBuf::from("/bin");

        // With mock CWD, ../Users becomes /bin/../Users which canonicalizes to /Users
        let extras = expand_firmlinks_inner(&paths, &firmlinks, Some(&mock_cwd));
        assert!(
            extras.contains(&PathBuf::from("/System/Volumes/Data/Users")),
            "Expected ../Users (from /bin) to resolve to /Users and match firmlink, got: {:?}",
            extras
        );
    }

    #[test]
    fn test_try_match_path_logic() {
        let firmlinks = vec![
            (
                PathBuf::from("/Users"),
                PathBuf::from("/System/Volumes/Data/Users"),
            ),
            (
                PathBuf::from("/usr/local"),
                PathBuf::from("/System/Volumes/Data/usr/local"),
            ),
        ];

        // 1. Map from system path to data volume path
        assert_eq!(
            try_match_path(Path::new("/Users/employee/projects"), &firmlinks),
            Some(PathBuf::from(
                "/System/Volumes/Data/Users/employee/projects"
            ))
        );

        // 2. Map from data volume path back to system path
        assert_eq!(
            try_match_path(
                Path::new("/System/Volumes/Data/Users/employee/projects"),
                &firmlinks
            ),
            Some(PathBuf::from("/Users/employee/projects"))
        );

        // 3. Map second firmlink entry (/usr/local)
        assert_eq!(
            try_match_path(Path::new("/usr/local/bin/rustc"), &firmlinks),
            Some(PathBuf::from("/System/Volumes/Data/usr/local/bin/rustc"))
        );

        // 4. Exact match on the firmlink root
        assert_eq!(
            try_match_path(Path::new("/Users"), &firmlinks),
            Some(PathBuf::from("/System/Volumes/Data/Users"))
        );

        // 5. Path that does not exist in firmlinks
        assert_eq!(
            try_match_path(Path::new("/System/Library/CoreServices"), &firmlinks),
            None
        );
    }
}
