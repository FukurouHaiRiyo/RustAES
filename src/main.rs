use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{Rng, rngs::OsRng};
use hex::{encode, decode};
use std::io::{self, Write};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

struct AesEncryptor {
    cipher: Aes128Cbc,
}

impl AesEncryptor {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, Box<dyn std::error::Error>> { 
        let cipher = Aes128Cbc::new_from_slices(key, iv)?;
        Ok(AesEncryptor { cipher })
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        self.cipher.clone().encrypt_vec(plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, block_modes::BlockModeError> {
        self.cipher.clone().decrypt_vec(ciphertext)
    }

    fn generate_random_key() -> [u8; 16] {
        let mut rng = OsRng;
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        key
    }

    fn generate_random_iv() -> [u8; 16] {
        let mut rng = OsRng;
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        iv
    }
}


fn main() {
    let key = AesEncryptor::generate_random_key();
    let iv = AesEncryptor::generate_random_iv();

    let cipher = AesEncryptor::new(&key, &iv).expect("Failed to create encryptor");

    loop {
        println!("Enter option:");
        println!("1: Encrypt a message");
        println!("2: Decrypt a message");
        println!("3: Exit");

        let mut option = String::new();
        io::stdin().read_line(&mut option).expect("Failed to read line");
        let option = option.trim();

        match option {
            "1" => {
                println!("Enter plaintext to encrypt:");
                let mut plaintext = String::new();
                io::stdin().read_line(&mut plaintext).expect("Failed to read line");
                let encrypted_data = cipher.encrypt(plaintext.trim().as_bytes());
                println!("Encrypted text: {}", base64::encode(&encrypted_data)); // base64 encode encrypted data for easy copy/paste
                // print the key and iv for easy copy/paste
                println!("Key: {}", base64::encode(&key));
            }
            "2" => {
                println!("Enter encoded ciphertext to decrypt:");
                let mut ciphertext_hex = String::new();
                io::stdin().read_line(&mut ciphertext_hex).expect("Failed to read line");
                if let Ok(ciphertext) = decode(ciphertext_hex.trim()) {
                    match cipher.decrypt(&ciphertext) {
                        Ok(decrypted_data) => println!("Decrypted text: {}", String::from_utf8_lossy(&decrypted_data)),
                        Err(_) => println!("Decryption failed. Invalid ciphertext."),
                    }
                } else {
                    println!("Invalid input.");
                }
            }
            "3" => break,
            _ => println!("Invalid option, please enter 1, 2, or 3"),
        }
    }
}