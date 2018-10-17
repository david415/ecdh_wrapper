// lib.rs - wrapping library for curve25519 dh operations
// Copyright (C) 2018  David Anthony Stainton.
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
    
extern crate rand;
extern crate x25519_dalek;

pub mod errors;
use self::rand::{Rng};
use x25519_dalek::{generate_public, diffie_hellman};

use errors::KeyError;

const CURVE25519_SIZE: usize = 32;

// KEY_SIZE is the size in bytes of the keys.
pub const KEY_SIZE: usize = CURVE25519_SIZE;


/// exp performs elliptic curve scalar multiplication
pub fn exp(x: &[u8; KEY_SIZE], y: &[u8; KEY_SIZE]) -> [u8; 32] {
    diffie_hellman(y, x)
}

/// exp_g performs elliptic curve base scalar multiplication
pub fn exp_g(x: &[u8; KEY_SIZE]) -> [u8; 32] {
    generate_public(x).to_bytes()
}

/// PublicKey, a public key for performing ECDH and blinding operations.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct PublicKey {
    _key: [u8; KEY_SIZE],
}

impl PublicKey {
    /// perform a blinding operation on the key
    pub fn blind(&mut self, blinding_factor: &[u8; KEY_SIZE]) {
        self._key = exp(&self._key, blinding_factor)
    }

    /// to_vec returns the key as a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self._key.to_vec()
    }

    /// as_array returns the key as an array [u8; KEY_SIZE]
    pub fn as_array(&self) -> [u8; KEY_SIZE] {
        self._key
    }

    /// from_bytes resets the key to the given bytes
    pub fn from_bytes(&mut self, b: &[u8]) -> Result<(), KeyError> {
        if b.len() != KEY_SIZE {
            return Err(KeyError::InvalidSize);
        }
        self._key.copy_from_slice(b);
        Ok(())
    }

    /// reset resets the key to explicit zeros
    pub fn reset(&mut self) {
        let zeros = [0u8; KEY_SIZE];
        self._key.copy_from_slice(&zeros);
    }
}

/// Privatekey, a keypair for performing ECDH and blinding operations.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct PrivateKey {
    public_key: PublicKey,
    _priv_bytes: [u8; KEY_SIZE],
}

impl PrivateKey {
    /// from_bytes creates a new keypair from the given bytes
    pub fn from_bytes(b: &[u8]) -> Result<PrivateKey, KeyError> {
        let mut keypair = PrivateKey::default();
        keypair.load_bytes(b)?;
        Ok(keypair)
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
    pub fn generate<R: Rng>(rng: &mut R) -> PrivateKey {
        let mut key = PrivateKey::default();
        key.regenerate(rng);
        key
    }

    pub fn load_bytes(&mut self, b: &[u8]) -> Result<(), KeyError> {
        if b.len() != KEY_SIZE {
            return Err(KeyError::InvalidSize)
        }
        let mut raw_key = [0u8; KEY_SIZE];
        raw_key.copy_from_slice(&b);
        let pub_key = PublicKey{
            _key: exp_g(&raw_key),
        };
        self.public_key = pub_key;
        self._priv_bytes = raw_key;
        Ok(())
    }

    pub fn regenerate<R: Rng>(&mut self, rng: &mut R) {
        let mut raw_key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut raw_key);
        self.load_bytes(&raw_key);
    }

    /// public_key returns the PublicKey
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Exp calculates the shared secret with the provided public key.
    pub fn exp(&self, public_key: &PublicKey) -> [u8; KEY_SIZE] {
        exp(&public_key._key, &self._priv_bytes)
    }

    /// to_vec returns the private key as a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self._priv_bytes.to_vec()
    }

    /// as_array returns the private key as an array [u8; KEY_SIZE]
    pub fn as_array(&self) -> [u8; KEY_SIZE] {
        self._priv_bytes
    }

    /// reset resets the key to explicit zeros
    pub fn reset(&mut self) {
        let zeros = [0u8; KEY_SIZE];
        self._priv_bytes.copy_from_slice(&zeros);
        self.public_key.reset();
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use self::rand::{Rng};
    use self::rand::os::OsRng;

    #[test]
    fn dh_ops_test() {
        let mut rng = OsRng::new().expect("failure to create an OS RNG");
        let alice_private_key = PrivateKey::generate(&mut rng);
        let mut bob_sk = [0u8; KEY_SIZE];
        let raw = rng.gen_iter::<u8>().take(KEY_SIZE).collect::<Vec<u8>>();
        bob_sk.copy_from_slice(raw.as_slice());
        let bob_pk = exp_g(&bob_sk);
        let tmp1 = exp_g(&alice_private_key.as_array());
        assert_eq!(tmp1, alice_private_key.public_key._key);
        let alice_s = exp(&bob_pk, &alice_private_key.as_array());
        let bob_s = exp(&alice_private_key.public_key._key, &bob_sk);
        assert_eq!(alice_s, bob_s);
    }
}
