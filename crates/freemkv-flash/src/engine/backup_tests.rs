use super::*;

#[test]
fn confirmed_replace_preserves_old_backup_until_new_bytes_validate() {
    let path = std::env::temp_dir().join(format!("fmkv-replace-{}", std::process::id()));
    std::fs::write(&path, b"old rollback").unwrap();
    assert!(save_validated(&path, b"new rollback", |_| Ok(())).is_err());
    assert!(
        save_validated_with_replace(&path, b"invalid", true, |_| anyhow::bail!("invalid")).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old rollback");
    let count = std::cell::Cell::new(0);
    assert!(
        save_validated_with_replace(&path, b"new rollback", true, |_| {
            count.set(count.get() + 1);
            if count.get() == 2 {
                anyhow::bail!("read-back failure");
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old rollback");
    save_validated_with_replace(&path, b"new rollback", true, |_| Ok(())).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"new rollback");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unsupported_hardlinks_copy_exclusively_and_preserve_existing_files() {
    let dir = std::env::temp_dir().join(format!("fmkv-publish-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("source");
    let dest = dir.join("backup");
    std::fs::write(&source, b"rollback").unwrap();
    let unsupported =
        |_: &Path, _: &Path| Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
    publish_no_clobber(&source, &dest, unsupported).unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"rollback");
    std::fs::write(&source, b"replacement").unwrap();
    assert!(publish_no_clobber(&source, &dest, unsupported).is_err());
    assert_eq!(std::fs::read(&dest).unwrap(), b"rollback");
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn dangling_backup_symlink_is_never_replaced() {
    let path = std::env::temp_dir().join(format!("fmkv-backup-link-{}", std::process::id()));
    let target = path.with_extension("missing-target");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let result = save_validated(&path, b"rollback", |_| Ok(()));
    let still_link = std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink();
    std::fs::remove_file(&path).unwrap();
    assert!(result.is_err(), "an occupied name must refuse publication");
    assert!(still_link, "never replace an existing directory entry");
}
