//! Open a saved report or diagnostic log with the desktop's file association.

use std::path::Path;

pub fn open_path(path: &Path) -> std::io::Result<()> {
    let url = url::Url::from_file_path(path)
        .map_err(|()| std::io::Error::other("invalid diagnostic log path"))?;
    webbrowser::open(url.as_str()).map_err(std::io::Error::other)
}
