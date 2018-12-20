//! Slack Message Verification
//!
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha2::Sha256;

pub use hex::FromHexError;

/// verify returns `Result<bool, FromHexError>`
///
/// `FromHexError` occurs when `hex::decode(expected_hex)` fails
///
/// # Example
///
/// The following is from the [official Slack documentation](https://api.slack.com/docs/verifying-requests-from-slack).
///
/// ```rust
/// # use slack_verify::verify;
/// let secret = "8f742231b10e8888abcd99yyyzzz85a5";
/// let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
/// let timestamp = 1531420618;
/// // First "v=0" will be deleted
/// let expected = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
/// assert_eq!(verify(secret, body, timestamp, expected).unwrap(), true);
/// ```
pub fn verify(
    secret: &str,
    body: &str,
    timestamp: i64,
    expected_hex: &str,
) -> Result<bool, hex::FromHexError> {
    let sig_basestring = format!("v0:{}:{}", timestamp, body);

    let mut hasher = Hmac::new(Sha256::new(), secret.as_bytes());

    hasher.input(sig_basestring.as_bytes());

    let expected = hex::decode(expected_hex.replacen("v0=", "", 1).as_bytes())?;

    Ok(hasher.result() == MacResult::new_from_owned(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_sig_basestring() {
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        let timestamp = 1531420618;
        let expected = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

        let output = verify(secret, body, timestamp, expected);
        assert_eq!(output.unwrap(), true);
    }
}
