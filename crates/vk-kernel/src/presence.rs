//! The node's own device key (spec §3.6): SP0's `SoftwareHumanKey`, made
//! durable. `vk boot` enrols it as device `node:<node_id>` with trust class
//! `full`, and a presence proof signed with it is what makes a request on the
//! local endpoint human. The ed25519 secret lives in the OS keyring (service
//! `vk`, user `node-device:<node_id>`) or, for tests and CI, in a file that
//! nobody else can read.
use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use vk_contracts::principal::HumanKey;

pub const KEYRING_SERVICE: &str = "vk";

pub enum KeySource {
    Keyring,
    File(PathBuf),
}

pub struct NodeDevice {
    node_id: String,
    key: SigningKey,
}

impl NodeDevice {
    pub fn load_or_create(source: KeySource, node_id: &str) -> Result<NodeDevice> {
        let seed = match source {
            KeySource::Keyring => keyring_seed(node_id)?,
            KeySource::File(path) => file_seed(&path)?,
        };
        Ok(NodeDevice {
            node_id: node_id.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }
}

impl HumanKey for NodeDevice {
    fn device_id(&self) -> String {
        format!("node:{}", self.node_id)
    }
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
    fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

fn keyring_seed(node_id: &str) -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("node-device:{node_id}"))?;
    match entry.get_password() {
        Ok(b64) => decode(&b64),
        Err(keyring::Error::NoEntry) => {
            let seed = fresh();
            entry.set_password(&encode(&seed))?;
            Ok(seed)
        }
        Err(e) => Err(e.into()),
    }
}

/// Mirrors `vk_store::keys`: an atomic `create_new` so there is no
/// exists-then-write window, born `0o600` on Unix, and an existing file that
/// others could read is refused rather than trusted.
fn file_seed(path: &Path) -> Result<[u8; 32]> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut file) => {
            let seed = fresh();
            file.write_all(encode(&seed).as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
            Ok(seed)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    anyhow::bail!("{} is readable by others; refusing", path.display());
                }
            }
            decode(std::fs::read_to_string(path)?.trim())
        }
        Err(err) => Err(err).with_context(|| format!("create {}", path.display())),
    }
}

fn fresh() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

fn encode(seed: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(seed)
}

fn decode(b64: &str) -> Result<[u8; 32]> {
    let v = base64::engine::general_purpose::STANDARD.decode(b64)?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("node device key must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealKernel;
    use vk_contracts::principal::DeviceRegistry;
    use vk_contracts::syscalls::{Kernel, KernelError};

    fn open(dir: &Path) -> RealKernel {
        RealKernel::open(
            dir,
            vk_store::keys::KeySource::File(dir.join("master.key")),
            "n1",
        )
        .unwrap()
    }

    fn enrolled_events(k: &RealKernel) -> usize {
        k.ledger()
            .events()
            .iter()
            .filter(|e| e.kind == "device.enrolled")
            .count()
    }

    #[test]
    fn file_source_creates_once_and_reloads_the_same_key() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("node.key");
        let a = NodeDevice::load_or_create(KeySource::File(path.clone()), "n1").unwrap();
        let b = NodeDevice::load_or_create(KeySource::File(path), "n1").unwrap();
        assert_eq!(a.device_id(), "node:n1");
        assert_eq!(a.verifying_key_bytes(), b.verifying_key_bytes());
        // A signature by the reloaded key verifies against the first's public key.
        let mut reg = DeviceRegistry::default();
        reg.register(a.device_id(), a.verifying_key_bytes());
        assert!(reg
            .verify(&b.device_id(), b"hello", &b.sign(b"hello"))
            .is_ok());
    }

    #[test]
    fn a_corrupt_key_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("node.key");
        std::fs::write(&path, "not base64 of 32 bytes").unwrap();
        assert!(NodeDevice::load_or_create(KeySource::File(path), "n1").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("node.key");
        NodeDevice::load_or_create(KeySource::File(path.clone()), "n1").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = NodeDevice::load_or_create(KeySource::File(path), "n1").unwrap_err();
        assert!(err.to_string().contains("readable by others"), "{err}");
    }

    #[test]
    fn enroll_node_device_is_idempotent_and_refuses_a_different_key() {
        let d = tempfile::tempdir().unwrap();
        let mut k = open(d.path());
        let dev =
            NodeDevice::load_or_create(KeySource::File(d.path().join("a.key")), "n1").unwrap();
        k.enroll_node_device(&dev).unwrap();
        k.enroll_node_device(&dev).unwrap();
        assert_eq!(enrolled_events(&k), 1, "a re-enrolment is a no-op");
        assert!(k
            .devices()
            .verify(&dev.device_id(), b"m", &dev.sign(b"m"))
            .is_ok());

        let other =
            NodeDevice::load_or_create(KeySource::File(d.path().join("b.key")), "n1").unwrap();
        let err = k.enroll_node_device(&other).unwrap_err();
        assert!(matches!(err, KernelError::I1(_)), "{err}");
        assert_eq!(enrolled_events(&k), 1);
        // The original key still answers for the device; the other never did.
        assert!(k
            .devices()
            .verify(&dev.device_id(), b"m", &dev.sign(b"m"))
            .is_ok());
        assert!(k
            .devices()
            .verify(&other.device_id(), b"m", &other.sign(b"m"))
            .is_err());

        // A device for another node is not this node's device.
        let foreign =
            NodeDevice::load_or_create(KeySource::File(d.path().join("c.key")), "n2").unwrap();
        assert!(matches!(
            k.enroll_node_device(&foreign).unwrap_err(),
            KernelError::I1(_)
        ));
    }

    #[test]
    fn the_enrolment_survives_a_reopen() {
        let d = tempfile::tempdir().unwrap();
        let dev =
            NodeDevice::load_or_create(KeySource::File(d.path().join("a.key")), "n1").unwrap();
        open(d.path()).enroll_node_device(&dev).unwrap();
        let k = open(d.path());
        assert!(k
            .devices()
            .verify(&dev.device_id(), b"m", &dev.sign(b"m"))
            .is_ok());
    }
}
