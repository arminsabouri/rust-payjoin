use std::fmt;

use crate::error_codes::ErrorCode;

/// The standard format for errors that can be replied as JSON.
///
/// The JSON output includes the following fields:
/// ```json
/// {
///     "errorCode": "specific-error-code",
///     "message": "Human readable error message"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JsonReply {
    /// The error code
    error_code: ErrorCode,
    /// The error message to be displayed only in debug logs
    message: String,
    /// Additional fields to be included in the JSON response
    extra: serde_json::Map<String, serde_json::Value>,
}

impl JsonReply {
    /// Create a new Reply
    pub(crate) fn new(error_code: ErrorCode, message: impl fmt::Display) -> Self {
        Self { error_code, message: message.to_string(), extra: serde_json::Map::new() }
    }

    /// Add an additional field to the JSON response
    pub fn with_extra(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }

    /// Serialize the Reply to a JSON string
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("errorCode".to_string(), self.error_code.to_string().into());
        map.insert("message".to_string(), self.message.clone().into());
        map.extend(self.extra.clone());

        serde_json::Value::Object(map)
    }

    #[cfg(feature = "v2")]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        use std::str::FromStr;
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        Ok(Self {
            error_code: ErrorCode::from_str(value["errorCode"].as_str().unwrap_or("unavailable"))
                .unwrap_or(ErrorCode::Unavailable),
            message: value["message"].as_str().unwrap_or("Receiver error").to_string(),
            extra: value["extra"].as_object().unwrap_or(&serde_json::Map::new()).to_owned(),
        })
    }

    #[cfg(feature = "v2")]
    pub(crate) fn error_code(&self) -> ErrorCode { self.error_code }

    #[cfg(feature = "v2")]
    pub(crate) fn message(&self) -> &str { &self.message }

    /// Get the HTTP status code for the error
    pub fn status_code(&self) -> u16 {
        match self.error_code {
            ErrorCode::Unavailable => http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::NotEnoughMoney
            | ErrorCode::VersionUnsupported
            | ErrorCode::OriginalPsbtRejected => http::StatusCode::BAD_REQUEST,
        }
        .as_u16()
    }
}
