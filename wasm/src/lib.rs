pub mod deposit;
pub mod withdraw;
pub mod params;

use ark_bn254::Fr;
use ark_std::UniformRand;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand_core::OsRng;
use js_sys::Uint8Array;
use serde::{Serialize, Deserialize};
use solana_program::instruction::Instruction;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::pubkey::Pubkey;
use soda_maze_program::{Packer, ID};
use soda_maze_program::params::HEIGHT;
use soda_maze_program::core::vault::Vault;
use soda_maze_program::core::node::get_merkle_node_pda;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Serialize, Deserialize)]
pub struct Instructions {
    pub credential: Instruction,
    pub verifier: Instruction,
    pub verify: Vec<Instruction>,
    pub finalize: Instruction,
}

#[derive(Serialize, Deserialize)]
pub struct ProofResult {
    pub instructions: Instructions,
    pub output: (u64, u64),
}

#[derive(Serialize, Deserialize)]
pub struct VaultInfo {
    pub enable: bool,
    pub index: u64,
    pub friends: Vec<Pubkey>,
}

fn to_hex<Se: CanonicalSerialize>(data: &Se) -> String {
    let mut buf = Vec::new();
    data.serialize(&mut buf).expect("serialize failed");
    hex::encode(buf)
}

pub fn from_hex<De: CanonicalDeserialize>(s: String) -> De {
    let buf = hex::decode(s).expect("failed to parse hex string");
    CanonicalDeserialize::deserialize(&buf[..]).expect("Canonical deserialize failed")
}

#[wasm_bindgen]
pub fn get_vault_info(vault_key: Pubkey, data: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let vault_data = data.to_vec();
    let vault = Vault::unpack(&vault_data)
        .expect("vault data can not unpack");

    let friends = (0..HEIGHT)
        .into_iter()
        .map(|layer| {
            let index = vault.index >> layer;
            let (layer, index) = if index % 2 == 0 {
                (layer as u8, index + 1)
            } else {
                (layer as u8, index - 1)
            };
            let (friend, _) = get_merkle_node_pda(&vault_key, layer, index, &ID);
            
            friend
        })
        .collect::<Vec<_>>();

    let vault_info = VaultInfo {
        enable: vault.enable,
        index: vault.index,
        friends,
    };
    JsValue::from_serde(&vault_info).expect("serde error")
}

#[wasm_bindgen]
pub fn gen_new_secret() -> JsValue {
    let secret = Fr::rand(&mut OsRng);
    JsValue::from_str(&to_hex(&secret))
}