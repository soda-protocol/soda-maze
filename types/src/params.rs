use anyhow::Result;
use std::{path::PathBuf, fs::OpenOptions};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{from_reader, to_writer_pretty};

pub trait JsonParser: Serialize + DeserializeOwned {
    fn from_file(path: &PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)?;
        let res = from_reader(&file)?;
        Ok(res)
    }

    fn to_file(&self, path: &PathBuf) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)?;
        to_writer_pretty(&mut file, self)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct RabinPrimes {
    pub prime_a: String,
    pub prime_b: String,
}

impl JsonParser for RabinPrimes {}

#[derive(Serialize, Deserialize)]
pub struct RabinParameters {
    pub modulus: String,
    pub modulus_len: usize,
    pub bit_size: usize,
    pub cipher_batch: usize,
}

impl JsonParser for RabinParameters {}