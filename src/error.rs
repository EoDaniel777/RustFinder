// Re-export the main error type from types.rs
pub use crate::types::RustFinderError;

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, RustFinderError>;

/// Helper trait for better error context
pub trait ErrorContext<T> {
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::fmt::Display,
{
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| RustFinderError::ConfigError(format!("{}: {}", f(), e)))
    }
}