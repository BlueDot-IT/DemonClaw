use anyhow::{Result, bail};
use std::net::IpAddr;
use std::process::Command;

use super::types::Target;

#[derive(Debug, Clone, Default)]
pub struct SshPolicy {
    /// Comma-separated allowlist entries (hostnames or exact destinations).
    /// If empty, SSH is denied unless `allow_any` is true.
    pub allowlist: Vec<String>,
    pub allow_any: bool,
}

impl SshPolicy {
    pub fn from_env() -> Self {
        let allow_any = std::env::var("DEMONCLAW_SSH_ALLOW_ANY")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        let allowlist = std::env::var("DEMONCLAW_SSH_ALLOWLIST")
            .ok()
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            allowlist,
            allow_any,
        }
    }

    pub fn check_destination(&self, destination: &str) -> Result<()> {
        let destination = validate_ssh_destination(destination)?;
        if self.allow_any {
            return Ok(());
        }
        if self.allowlist.is_empty() {
            bail!(
                "SSH destination '{}' denied because no allowlist is configured",
                destination
            );
        }

        if self.allowlist.iter().any(|entry| entry == destination) {
            return Ok(());
        }

        let host = destination
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(destination);
        if self.allowlist.iter().any(|entry| entry == host) {
            return Ok(());
        }

        bail!("SSH destination '{}' is not allowlisted", destination)
    }
}

fn validate_ssh_destination(destination: &str) -> Result<&str> {
    let trimmed = destination.trim();
    if trimmed != destination || trimmed.is_empty() || trimmed.len() > 255 {
        bail!("Invalid SSH destination");
    }
    if trimmed.starts_with('-')
        || trimmed
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("Invalid SSH destination syntax");
    }

    let (user, host) = match trimmed.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, trimmed),
    };

    if let Some(user) = user
        && (user.is_empty()
            || user.len() > 64
            || user.starts_with('-')
            || !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        bail!("Invalid SSH user name");
    }

    validate_ssh_host(host)?;
    Ok(trimmed)
}

fn validate_ssh_host(host: &str) -> Result<()> {
    if host.is_empty() || host.starts_with('-') {
        bail!("Invalid SSH host");
    }

    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        inner
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("Invalid bracketed SSH IP address"))?;
        return Ok(());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.contains(':') || host.len() > 253 {
        bail!("Invalid SSH host");
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("Invalid SSH host name");
        }
    }
    Ok(())
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(i32, String, String)>;
}

#[derive(Debug, Clone)]
pub struct LocalRunner;

impl CommandRunner for LocalRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(i32, String, String)> {
        let out = Command::new(program).args(args).output();
        match out {
            Ok(o) => Ok((
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            )),
            Err(e) => Ok((-1, String::new(), e.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SshRunner {
    pub destination: String,
    pub policy: SshPolicy,
}

fn shell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

impl CommandRunner for SshRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(i32, String, String)> {
        self.policy.check_destination(&self.destination)?;

        let mut remote = shell_escape(program);
        for arg in args {
            remote.push(' ');
            remote.push_str(&shell_escape(arg));
        }

        let out = Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "IdentitiesOnly=yes",
                "--",
                &self.destination,
                &remote,
            ])
            .output();

        match out {
            Ok(o) => Ok((
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            )),
            Err(e) => Ok((-1, String::new(), e.to_string())),
        }
    }
}

pub fn runner_for_target(target: &Target) -> Box<dyn CommandRunner + Send + Sync> {
    match target {
        Target::Local => Box::new(LocalRunner),
        Target::Ssh { destination } => Box::new(SshRunner {
            destination: destination.clone(),
            policy: SshPolicy::from_env(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape_wraps_and_escapes_single_quotes() {
        assert_eq!(shell_escape("abc"), "'abc'");
        assert_eq!(shell_escape("a'b"), "'a'\"'\"'b'");
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn ssh_destination_validation_rejects_option_injection() {
        assert!(validate_ssh_destination("root@10.0.0.5").is_ok());
        assert!(validate_ssh_destination("-oProxyCommand=sh").is_err());
        assert!(validate_ssh_destination("root@-oProxyCommand=sh").is_err());
    }
}
