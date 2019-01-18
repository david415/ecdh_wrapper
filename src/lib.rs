// lib.rs - wrapping library for curve25519 dh operations
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
extern crate rand;
extern crate x25519_dalek;
extern crate clear_on_drop;
extern crate pem;
extern crate base64;

pub mod errors;


use std::io::prelude::*;
use std::fs::{File, write};
use rand::{Rng};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use clear_on_drop::{ClearOnDrop};
use pem::{Pem, parse, encode};

use errors::KeyError;

const PUBLIC_KEY_TYPE: &str = "X25519 PUBLIC KEY";
const PRIVATE_KEY_TYPE: &str = "X25519 PRIVATE KEY";
const CURVE25519_SIZE: usize = 32;

/// KEY_SIZE is the size in bytes of the keys.
pub const KEY_SIZE: usize = CURVE25519_SIZE;


/// exp performs elliptic curve scalar multiplication
pub fn exp(x: &[u8; KEY_SIZE], y: &[u8; KEY_SIZE]) -> [u8; 32] {
    x25519(*y, *x)
}

/// exp_g performs elliptic curve base scalar multiplication
pub fn exp_g(x: &[u8; KEY_SIZE]) -> [u8; 32] {
    x25519(*x, X25519_BASEPOINT_BYTES)
}

/// PublicKey, a public key for performing ECDH and blinding operations.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey {
    public_bytes: [u8; KEY_SIZE],
}

impl PublicKey {
    /// from_pem_file loads a key from a PEM file.
    pub fn from_pem_file(pub_file: String) -> Result<PublicKey, KeyError> {
        let mut file = File::open(pub_file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let pem = parse(&contents)?;
        if pem.tag != PUBLIC_KEY_TYPE {
            return Err(KeyError::InvalidKeyType);
        }
        if pem.contents.len() != CURVE25519_SIZE {
            return Err(KeyError::InvalidSize);
        }
        let mut k = PublicKey::default();
        k.from_bytes(&pem.contents)?;
        Ok(k)
    }

    /// to_pem_file writes the key into a file in PEM format.
    pub fn to_pem_file(&self, pub_file: String) -> Result<(), KeyError> {
        let pem = Pem {
            tag: String::from(PUBLIC_KEY_TYPE),
            contents: self.public_bytes.to_vec(),
        };
        let pem_str = encode(&pem);
        write(pub_file, pem_str)?;
        Ok(())
    }

    /// perform a blinding operation on the key
    pub fn blind(&mut self, blinding_factor: &[u8; KEY_SIZE]) {
        self.public_bytes = exp(&self.public_bytes, blinding_factor)
    }

    /// to_vec returns the key as a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.public_bytes.to_vec()
    }

    /// as_array returns the key as an array [u8; KEY_SIZE]
    pub fn as_array(&self) -> [u8; KEY_SIZE] {
        self.public_bytes
    }

    /// from_bytes resets the key to the given bytes
    pub fn from_bytes(&mut self, b: &[u8]) -> Result<(), KeyError> {
        if b.len() != KEY_SIZE {
            return Err(KeyError::InvalidSize);
        }
        self.public_bytes.clone_from_slice(b);
        Ok(())
    }

    /// to_base64 encodes the key as base64 string.
    pub fn to_base64(&self) -> String {
            base64::encode(&self.public_bytes)
    }

    /// from_base64 returns a PublicKey given a base64 string.
    pub fn from_base64(base64_string: String) -> Result<PublicKey, KeyError> {
        let mut key = PublicKey::default();
        let bytes = base64::decode(&base64_string).unwrap();
        key.public_bytes.clone_from_slice(&bytes);
        Ok(key)
    }

    /// reset resets the key to explicit zeros
    pub fn reset(&mut self) {
        let zeros = [0u8; KEY_SIZE];
        self.public_bytes.copy_from_slice(&zeros);
    }
}

/// Privatekey, a keypair for performing ECDH and blinding operations.
#[derive(Clone, Debug, PartialEq)]
pub struct PrivateKey {
    public_key: PublicKey,
    private_bytes: ClearOnDrop<Box<[u8; KEY_SIZE]>>,
}

impl Default for PrivateKey {
    fn default() -> Self {
        PrivateKey {
            public_key: PublicKey::default(),
            private_bytes: ClearOnDrop::new(Box::new([0u8; KEY_SIZE])),
        }
    }
}

impl PrivateKey {
    /// from_bytes creates a new keypair from the given bytes
    pub fn from_bytes(b: &[u8]) -> Result<PrivateKey, KeyError> {
        let mut keypair = PrivateKey::default();
        keypair.load_bytes(b)?;
        Ok(keypair)
    }

    /// Load private and public PEM files.
    pub fn from_pem_files(priv_file: String, pub_file: String) -> Result<PrivateKey, KeyError> {
        let mut file = File::open(priv_file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let pem = parse(&contents)?;
        if pem.tag != PRIVATE_KEY_TYPE {
            return Err(KeyError::InvalidKeyType);
        }
        if pem.contents.len() != CURVE25519_SIZE {
            return Err(KeyError::InvalidSize);
        }
        let priv_key = PrivateKey::from_bytes(&pem.contents)?;
        let pub_key = PublicKey::from_pem_file(pub_file)?;
        if !priv_key.public_key.eq(&pub_key) {
            return Err(KeyError::InvalidPublicKey);
        }
        Ok(priv_key)
    }

    /// generate creates a new key pair
    ///
    /// # Arguments
    ///
    /// * `rng` - an implementation of Rng, a random number generator.
    ///
    /// # Returns
    ///
    /// * Returns a PrivateKey or an error.
    ///
    pub fn generate<R: Rng>(rng: &mut R) -> Result<PrivateKey, KeyError> {
        let mut key = PrivateKey::default();
        key.regenerate(rng)?;
        Ok(key)
    }

    /// load_bytes loads a key from the given bytes.
    pub fn load_bytes(&mut self, b: &[u8]) -> Result<(), KeyError> {
        if b.len() != KEY_SIZE {
            return Err(KeyError::InvalidSize)
        }
        let mut raw_key = Box::new([0u8; KEY_SIZE]);
        raw_key.copy_from_slice(&b);
        let pub_key = PublicKey{
            public_bytes: exp_g(&raw_key),
        };
        self.public_key = pub_key;
        self.private_bytes = ClearOnDrop::new(raw_key);
        Ok(())
    }

    /// to_pem_files writes the public and privates keys to two PEM files.
    pub fn to_pem_files(&self, priv_file: String, pub_file: String) -> Result<(), KeyError> {
        let pem = Pem {
            tag: String::from(PRIVATE_KEY_TYPE),
            contents: self.private_bytes.to_vec(),
        };
        let pem_str = encode(&pem);
        write(priv_file, pem_str)?;
        self.public_key.to_pem_file(pub_file)?;
        Ok(())
    }

    /// regenerate uses the given rng to generate a new key.
    pub fn regenerate<R: Rng>(&mut self, rng: &mut R) -> Result<(), KeyError> {
        let mut raw_key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut raw_key);
        self.load_bytes(&raw_key)?;
        Ok(())
    }

    /// public_key returns the PublicKey
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Exp calculates the shared secret with the provided public key.
    pub fn exp(&self, public_key: &PublicKey) -> [u8; KEY_SIZE] {
        exp(&public_key.public_bytes, &self.private_bytes)
    }

    /// to_vec returns the private key as a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.private_bytes.to_vec()
    }

    /// as_array returns the private key as an array [u8; KEY_SIZE]
    pub fn as_array(self) -> [u8; KEY_SIZE] {
        *ClearOnDrop::into_uncleared_place(self.private_bytes)
    }

    /// reset resets the key to explicit zeros
    pub fn reset(&mut self) {
        let zeros = [0u8; KEY_SIZE];
        self.private_bytes.copy_from_slice(&zeros);
        self.public_key.reset();
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate tempfile;

    use super::*;
    use self::rand::{Rng};
    use self::rand::os::OsRng;
    use self::tempfile::NamedTempFile;

    #[test]
    fn dh_ops_test() {
        let mut rng = OsRng::new().unwrap();
        let alice_private_key = PrivateKey::generate(&mut rng).unwrap();
        let mut bob_sk = [0u8; KEY_SIZE];
        let raw = rng.gen_iter::<u8>().take(KEY_SIZE).collect::<Vec<u8>>();
        bob_sk.copy_from_slice(raw.as_slice());
        let bob_pk = exp_g(&bob_sk);
        let tmp1 = exp_g(&alice_private_key.clone().as_array());
        assert_eq!(tmp1, alice_private_key.public_key.public_bytes);
        let alice_s = exp(&bob_pk, &alice_private_key.clone().as_array());
        let bob_s = exp(&alice_private_key.public_key.public_bytes, &bob_sk);
        assert_eq!(alice_s, bob_s);
    }

    #[test]
    fn write_read_pem_file_test() {
        let mut rng = OsRng::new().unwrap();
        let private_key = PrivateKey::generate(&mut rng).unwrap();
        let priv_key_file = NamedTempFile::new().unwrap();
        let pub_key_file = NamedTempFile::new().unwrap();
        let priv_key_path_str = priv_key_file.path().to_str().unwrap();
        let pub_key_path_str = pub_key_file.path().to_str().unwrap();
        let priv_key = priv_key_path_str.to_string();
        let pub_key = pub_key_path_str.to_string();
        private_key.to_pem_files(priv_key.clone(), pub_key.clone()).unwrap();

        let mut file = File::open(priv_key_file.path()).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        println!("contents:\n{}", contents);

        let private_key2 = PrivateKey::from_pem_files(priv_key, pub_key).unwrap();
        assert_eq!(private_key, private_key2);
    }

    #[test]
    fn encode_decode_base64_test() {
        let mut rng = OsRng::new().unwrap();
        let private_key = PrivateKey::generate(&mut rng).unwrap();
        let public_key = private_key.public_key();
        let str1 = public_key.to_base64();
        println!("pub key as base64:\n{}", str1);
        let public_key2 = PublicKey::from_base64(str1).unwrap();
        assert_eq!(public_key, public_key2);
    }
}
