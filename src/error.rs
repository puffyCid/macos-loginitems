use std::fmt;

#[derive(Debug)]
pub enum LoginItemError {
    Path,
    Plist,
    Bookmark,
}

impl std::error::Error for LoginItemError {}

impl fmt::Display for LoginItemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoginItemError::Path => write!(f, "Failed to get provided path"),
            LoginItemError::Plist => write!(f, "No bookmark data"),
            LoginItemError::Bookmark => write!(f, "Could not parse bookmark data"),
        }
    }
}
