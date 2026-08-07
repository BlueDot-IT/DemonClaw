use anyhow::{Result, bail};
use tracing::info;

/// The AI assessment and defense toolkit.
pub struct DarkPrompt;

impl Default for DarkPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl DarkPrompt {
    pub fn new() -> Self {
        info!("DarkPrompt (Assessment & Defense Toolkit) initialized.");
        Self
    }

    /// Selects and prepares a specific WASM payload for adversarial simulation or enterprise scanning.
    pub fn prepare_payload(&self, payload_name: &str) -> Result<Vec<u8>> {
        validate_payload_name(payload_name)?;
        info!("Preparing DarkPrompt payload: {}", payload_name);

        let wasm_path = format!(
            "{}/payloads/{}/target/wasm32-wasip1/release/{}.wasm",
            env!("CARGO_MANIFEST_DIR"),
            payload_name,
            payload_name
        );

        Ok(std::fs::read(wasm_path)?)
    }
}

fn validate_payload_name(payload_name: &str) -> Result<()> {
    if payload_name.is_empty() || payload_name.len() > 64 {
        bail!("Invalid payload name length");
    }
    if !payload_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("Invalid payload name: only ASCII letters, digits, '_' and '-' are allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_name_validation_rejects_path_traversal() {
        assert!(validate_payload_name("test_payload").is_ok());
        assert!(validate_payload_name("../test_payload").is_err());
        assert!(validate_payload_name("test/payload").is_err());
    }
}
