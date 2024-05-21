//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use std::iter::{zip, Cycle};

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [10, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let number_pad_bytes = data[data.len() - 1];

    let data_len = data.len();
    data.into_iter()
        .take(data_len - number_pad_bytes as usize)
        .collect()
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    blocks.into_iter().flatten().collect()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let padded = pad(plain_text);
    let grouped = group(padded);

    let encrypted_groups: Vec<_> = grouped.into_iter().map(|v| aes_encrypt(v, &key)).collect();

    un_group(encrypted_groups)
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let encrypted_groups = group(cipher_text);

    let grouped: Vec<_> = encrypted_groups
        .into_iter()
        .map(|v| aes_decrypt(v, &key))
        .collect();
    un_pad(un_group(grouped))
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut iv: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        iv[i] = rand::thread_rng().gen_range(1..u8::MAX)
    }

    let padded = pad(plain_text);
    let grouped = group(padded);

    let mut result = vec![iv.clone()];
    for group in grouped {
        let mut xored: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = iv[i] ^ group[i];
        }
        let cipher_text = aes_encrypt(xored, &key);
        result.push(cipher_text);

        iv = cipher_text.clone();
    }

    un_group(result)
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let encrypted_groups = group(cipher_text);

    let mut blocks = vec![];
    let mut iv = encrypted_groups[0];
    for group in &encrypted_groups[1..] {
        let mut decrypted = aes_decrypt(group.to_owned(), &key);
        for i in 0..BLOCK_SIZE {
            decrypted[i] = iv[i] ^ decrypted[i];
        }

        iv = group.to_owned();
        blocks.push(decrypted);
    }

    un_pad(un_group(blocks))
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut nonce: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];
    for i in 0..(BLOCK_SIZE / 2) {
        nonce[i] = rand::thread_rng().gen_range(1..u8::MAX)
    }
    let mut counter: u64 = 0;

    let padded = pad(plain_text);
    let grouped = group(padded);

    let mut result = vec![nonce.clone()];
    for group in grouped {
        nonce[BLOCK_SIZE / 2..].copy_from_slice(&counter.to_le_bytes());

        let block_key = aes_encrypt(nonce, &key);
        let mut xored: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = block_key[i] ^ group[i];
        }
        result.push(xored);

        counter += 1;
    }

    un_group(result)
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let encrypted_groups = group(cipher_text);
    let mut counter: u64 = 0;

    let mut result = vec![];
    let mut nonce = encrypted_groups[0];
    for group in &encrypted_groups[1..] {
        nonce[BLOCK_SIZE / 2..].copy_from_slice(&counter.to_le_bytes());

        let block_key = aes_encrypt(nonce, &key);
        let mut xored: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = block_key[i] ^ group[i];
        }
        result.push(xored);

        counter += 1;
    }

    un_pad(un_group(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        let a = vec![1, 2, 3];
        assert_eq!(a.clone(), un_pad(pad(a)));
        let b = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(b.clone(), un_pad(pad(b)));
    }

    #[test]
    fn grouping() {
        let a = vec![0; BLOCK_SIZE * 2];
        assert_eq!(a.clone(), un_group(group(a)));
    }

    #[test]
    fn cbc() {
        let a = vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20, 0x61, 0x6E, 0x6F,
            0x74, 0x68, 0x65, 0x72, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64,
        ];
        assert_eq!(
            a.clone(),
            cbc_decrypt(cbc_encrypt(a, [1; BLOCK_SIZE]), [1; BLOCK_SIZE])
        );
    }

    #[test]
    fn ctr() {
        let a = vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20, 0x61, 0x6E, 0x6F,
            0x74, 0x68, 0x65, 0x72, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64,
        ];
        assert_eq!(
            a.clone(),
            ctr_decrypt(ctr_encrypt(a, [1; BLOCK_SIZE]), [1; BLOCK_SIZE])
        );
    }
}
