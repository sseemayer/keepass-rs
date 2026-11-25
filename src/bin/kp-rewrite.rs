//! utility to parse a KeePass database, and then write it out again, to see if anything is lost.
use std::{
    fs::{self, File},
    io,
    path::Path,
};

use anyhow::Result;
use clap::Parser;
use tempfile::NamedTempFile;

use keepass::{Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Output file to write
    out_kdbx: String,

    /// Provide a keyfile
    #[arg(short = 'k', long)]
    keyfile: Option<String>,

    /// Do not use a password to decrypt the database
    #[arg(short = 'n', long)]
    no_password: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;
    let mut key = DatabaseKey::new();

    if let Some(f) = args.keyfile {
        key = key.with_keyfile(&mut File::open(f)?)?;
    }

    if !args.no_password {
        key = key.with_password_from_prompt("Password: ")?;
    }

    if key.is_empty() {
        return Err(anyhow::format_err!("No database key was provided."));
    }

    let db = Database::open(&mut source, key.clone())?;
    // On Windows, an open handle to the input keeps it from being replaced when it's also the output.
    drop(source);

    save(&db, Path::new(&args.out_kdbx), key)
}

/// Saves through a temporary file in the output's directory and replaces the output only once the
/// save has succeeded. An existing output must be a file that isn't read-only. It's written through
/// a symbolic link and keeps its permissions and, on Unix, its owner and group. ACLs aren't copied:
/// the new file gets the directory's defaults.
fn save(db: &Database, out_kdbx: &Path, key: DatabaseKey) -> Result<()> {
    let (out_kdbx, metadata) = match fs::canonicalize(out_kdbx) {
        Ok(out_kdbx) => {
            let metadata = fs::metadata(&out_kdbx)?;
            if !metadata.is_file() {
                return Err(anyhow::format_err!("{} is not a file", out_kdbx.display()));
            }
            if metadata.permissions().readonly() {
                return Err(anyhow::format_err!("{} is read-only", out_kdbx.display()));
            }
            (out_kdbx, Some(metadata))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if fs::symlink_metadata(out_kdbx).is_ok() {
                return Err(anyhow::format_err!(
                    "{} links to a missing file",
                    out_kdbx.display()
                ));
            }
            (out_kdbx.to_path_buf(), None)
        }
        Err(e) => return Err(e.into()),
    };

    let mut out_file = NamedTempFile::new_in(out_kdbx.parent().unwrap_or(Path::new(".")))?;
    db.save(out_file.as_file_mut(), key)?;
    out_file.as_file().sync_all()?;
    if let Some(metadata) = metadata {
        // The permissions only mean the same with the same owner and group.
        #[cfg(unix)]
        {
            use anyhow::Context;
            use std::os::unix::fs::MetadataExt;
            std::os::unix::fs::fchown(out_file.as_file(), Some(metadata.uid()), Some(metadata.gid()))
                .with_context(|| format!("{} can't keep its owner and group", out_kdbx.display()))?;
        }
        out_file.as_file().set_permissions(metadata.permissions())?;
    }
    out_file.persist(&out_kdbx)?;

    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use std::fs;

    use keepass::config::DatabaseVersion;

    use super::*;

    fn database() -> (Database, DatabaseKey) {
        let mut db = Database::new();
        db.meta.database_name = Some("rewritten".to_string());
        (db, DatabaseKey::new().with_password("demopass"))
    }

    #[test]
    fn failed_save_leaves_output_untouched() {
        let (mut db, key) = database();
        // only KDBX 4.1 databases can be saved
        db.config.version = DatabaseVersion::KDB3(1);
        let dir = tempfile::tempdir().unwrap();
        let out_kdbx = dir.path().join("out.kdbx");
        fs::write(&out_kdbx, b"previous contents").unwrap();

        assert!(save(&db, &out_kdbx, key).is_err());

        assert_eq!(fs::read(&out_kdbx).unwrap(), b"previous contents");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn save_replaces_output() {
        let (db, key) = database();
        let dir = tempfile::tempdir().unwrap();
        let out_kdbx = dir.path().join("out.kdbx");
        fs::write(&out_kdbx, b"previous contents").unwrap();

        save(&db, &out_kdbx, key.clone()).unwrap();

        let saved = Database::open(&mut File::open(&out_kdbx).unwrap(), key).unwrap();
        assert_eq!(saved.meta.database_name.as_deref(), Some("rewritten"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_an_output_it_cannot_write() {
        let (db, key) = database();
        let dir = tempfile::tempdir().unwrap();
        assert!(save(&db, dir.path(), key.clone()).is_err());

        let out_kdbx = dir.path().join("out.kdbx");
        fs::write(&out_kdbx, b"previous contents").unwrap();
        let mut permissions = fs::metadata(&out_kdbx).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&out_kdbx, permissions).unwrap();

        assert!(save(&db, &out_kdbx, key).is_err());
        assert_eq!(fs::read(&out_kdbx).unwrap(), b"previous contents");
    }

    #[cfg(unix)]
    #[test]
    fn keeps_permissions_and_symbolic_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (db, key) = database();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.kdbx");
        let link = dir.path().join("link.kdbx");
        fs::write(&target, b"previous contents").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &link).unwrap();

        save(&db, &link, key.clone()).unwrap();

        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o640);
        let saved = Database::open(&mut File::open(&target).unwrap(), key).unwrap();
        assert_eq!(saved.meta.database_name.as_deref(), Some("rewritten"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
