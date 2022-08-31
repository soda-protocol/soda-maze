use anyhow::Result;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use std::{path::PathBuf, fs::OpenOptions, io::Read};
use serde::{Serialize, de::DeserializeOwned};
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

pub fn borsh_de_from_file<D: BorshDeserialize>(path: &PathBuf) -> Result<D> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let res = BorshDeserialize::deserialize(&mut &buffer[..])?;

    Ok(res)
}

pub fn borsh_se_to_file<S: BorshSerialize>(se: &S, path: &PathBuf) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap();
    se.serialize(&mut file)?;

    Ok(())
}

pub fn from_hex_string<D: CanonicalDeserialize>(s: String) -> Result<D> {
    let buf = hex::decode(s)?;
    let res = D::deserialize(&buf[..])?;

    Ok(res)
}

pub fn to_hex_string<S: CanonicalSerialize>(se: &S) -> Result<String> {
    let mut buf = Vec::new();
    se.serialize(&mut buf[..])?;
    
    Ok(hex::encode(buf))
}
