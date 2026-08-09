use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

pub(crate) const DEFAULT_OUTPUT_FILENAME: &str = "ghosthound_output.json";

/// An output-path or output-write failure with enough context to be useful from the CLI.
///
/// `main` returns a boxed error, whose termination implementation formats errors with `Debug`.
/// Keeping `Debug` identical to `Display` avoids exposing an opaque raw `io::Error` structure to
/// the user while retaining the original error as a source.
pub(crate) struct OutputError {
    message: String,
    source: Option<std::io::Error>,
}

impl OutputError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    fn with_source(message: impl Into<String>, source: std::io::Error) -> Self {
        Self {
            message: message.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for OutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Resolves a user-supplied output argument and validates its directory structure.
///
/// An existing directory receives [`DEFAULT_OUTPUT_FILENAME`]; every other path is treated as an
/// explicit file path. A trailing separator is retained as a directory hint so a missing `dir/`
/// is rejected instead of being reinterpreted as a file named `dir`. Directory checks use
/// [`Path::is_dir`] and [`fs::metadata`], which deliberately follow symlinks. This function does
/// not create or truncate anything, so it is safe to call before LDAP collection begins.
pub(crate) fn resolve_output_path(requested: &Path) -> Result<PathBuf, OutputError> {
    if requested.as_os_str().is_empty() {
        return Err(OutputError::new("output path must not be empty"));
    }

    if requested.is_dir() {
        return Ok(requested.join(DEFAULT_OUTPUT_FILENAME));
    }

    if has_trailing_separator(requested.as_os_str()) {
        return Err(OutputError::new(format!(
            "output directory '{}' does not exist or is not a directory",
            requested.display()
        )));
    }

    let parent = requested
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    match fs::metadata(parent) {
        Ok(metadata) if metadata.is_dir() => Ok(requested.to_path_buf()),
        Ok(_) => Err(OutputError::new(format!(
            "output parent path '{}' is not a directory",
            parent.display()
        ))),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Err(OutputError::with_source(
                format!(
                    "output parent directory '{}' does not exist",
                    parent.display()
                ),
                source,
            ))
        }
        Err(source) => Err(OutputError::with_source(
            format!(
                "failed to inspect output parent directory '{}'",
                parent.display()
            ),
            source,
        )),
    }
}

/// Writes the completed JSON payload to a previously resolved output path.
///
/// On Unix, permissions are set to `0600` before an existing file is truncated so data never
/// passes through a world-readable state. Windows retains the ACL behavior of the host filesystem.
pub(crate) fn write_output(path: &Path, contents: &[u8]) -> Result<(), OutputError> {
    let mut open_options = File::options();
    open_options.write(true).create(true);
    #[cfg(unix)]
    open_options.mode(0o600);

    let mut file = open_options.open(path).map_err(|source| {
        OutputError::with_source(
            format!("failed to open output file '{}'", path.display()),
            source,
        )
    })?;

    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| {
            OutputError::with_source(
                format!(
                    "failed to restrict output file '{}' to mode 0600",
                    path.display()
                ),
                source,
            )
        })?;

    file.set_len(0).map_err(|source| {
        OutputError::with_source(
            format!("failed to truncate output file '{}'", path.display()),
            source,
        )
    })?;
    file.write_all(contents).map_err(|source| {
        OutputError::with_source(
            format!("failed to write output file '{}'", path.display()),
            source,
        )
    })?;

    Ok(())
}

#[cfg(unix)]
fn has_trailing_separator(value: &OsStr) -> bool {
    value.as_bytes().last() == Some(&b'/')
}

#[cfg(windows)]
fn has_trailing_separator(value: &OsStr) -> bool {
    matches!(value.encode_wide().last(), Some(value) if value == u16::from(b'/') || value == u16::from(b'\\'))
}

#[cfg(not(any(unix, windows)))]
fn has_trailing_separator(value: &OsStr) -> bool {
    value
        .to_string_lossy()
        .chars()
        .last()
        .is_some_and(std::path::is_separator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn with_trailing_separator(path: &Path) -> PathBuf {
        let mut value = OsString::from(path.as_os_str());
        value.push(std::path::MAIN_SEPARATOR_STR);
        PathBuf::from(value)
    }

    #[test]
    fn keeps_an_explicit_file_path_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("report.json");

        assert_eq!(resolve_output_path(&requested).unwrap(), requested);
    }

    #[test]
    fn keeps_a_bare_filename_relative_to_the_current_directory() {
        let requested = Path::new("report.json");

        assert_eq!(
            resolve_output_path(requested).unwrap(),
            PathBuf::from("report.json")
        );
    }

    #[test]
    fn appends_the_default_filename_to_an_existing_directory() {
        let temp = tempfile::tempdir().unwrap();

        assert_eq!(
            resolve_output_path(temp.path()).unwrap(),
            temp.path().join(DEFAULT_OUTPUT_FILENAME)
        );
    }

    #[test]
    fn accepts_an_existing_directory_with_a_trailing_separator() {
        let temp = tempfile::tempdir().unwrap();
        let requested = with_trailing_separator(temp.path());

        assert_eq!(
            resolve_output_path(&requested).unwrap(),
            temp.path().join(DEFAULT_OUTPUT_FILENAME)
        );
    }

    #[test]
    fn rejects_a_missing_directory_indicated_by_a_trailing_separator() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let requested = with_trailing_separator(&missing);

        let error = resolve_output_path(&requested).unwrap_err();

        assert!(error.to_string().contains("output directory"));
        assert!(error.to_string().contains("does not exist"));
        assert!(!missing.exists());
    }

    #[test]
    fn rejects_a_file_path_whose_parent_does_not_exist() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("missing").join("report.json");

        let error = resolve_output_path(&requested).unwrap_err();

        assert!(error.to_string().contains("output parent directory"));
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn rejects_a_parent_path_that_is_a_file() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("not-a-directory");
        fs::write(&parent, b"existing file").unwrap();

        let error = resolve_output_path(&parent.join("report.json")).unwrap_err();

        assert!(error.to_string().contains("is not a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn follows_a_symlink_to_an_existing_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(
            resolve_output_path(&link).unwrap(),
            link.join(DEFAULT_OUTPUT_FILENAME)
        );
    }

    #[test]
    fn writes_and_truncates_the_resolved_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("report.json");
        fs::write(&path, b"a longer previous report").unwrap();

        write_output(&path, b"{}\n").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"{}\n");
    }

    #[test]
    fn creates_a_new_output_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("report.json");

        write_output(&path, b"{}\n").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"{}\n");
    }

    #[cfg(unix)]
    #[test]
    fn restricts_an_existing_file_to_owner_only_before_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("report.json");
        fs::write(&path, b"old report").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_output(&path, b"new report").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
