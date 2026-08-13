//! Harness subcommands.

pub mod dial;
pub mod governance;
pub mod identity;
pub mod listen;
pub mod relay;

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};

/// Errors surfaced to the CLI.
pub type CliResult = Result<(), String>;

/// Parses a 32-byte hex network identifier, or expands a short label.
///
/// Accepts either full hex or a small integer, so scenario scripts can say
/// `--network 1` rather than repeating 64 characters. Deliberately harness-only
/// convenience: nothing in the protocol treats short network IDs as valid.
pub fn parse_network(value: &str) -> Result<NetworkId, String> {
    if let Ok(small) = value.parse::<u8>() {
        return Ok(NetworkId::from_bytes([small; 32]));
    }
    let bytes = intranet_crypto::from_hex(value)
        .ok_or_else(|| format!("network id '{value}' is not valid hex"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("network id must be 32 bytes, got {}", bytes.len()))?;
    Ok(NetworkId::from_bytes(bytes))
}

/// Resolves an identity from either a backup phrase or a deterministic seed byte.
///
/// The seed-byte form exists so multi-node scenarios can name participants
/// reproducibly (`--seed 1`, `--seed 2`) without threading mnemonics through
/// shell scripts. It is a harness affordance, never a protocol feature: a real
/// node derives from a genuine high-entropy master seed.
pub fn resolve_identity(
    phrase: Option<&str>,
    seed: Option<u8>,
    network: &NetworkId,
) -> Result<PerNetworkIdentity, String> {
    let master = match (phrase, seed) {
        (Some(phrase), _) => {
            MasterSeed::from_backup_phrase(phrase).map_err(|e| format!("bad backup phrase: {e}"))?
        }
        (None, Some(seed)) => MasterSeed::from_entropy([seed; 32]),
        (None, None) => return Err("provide either --phrase or --seed".into()),
    };
    master
        .identity_for(network)
        .map_err(|e| format!("could not derive identity: {e}"))
}
