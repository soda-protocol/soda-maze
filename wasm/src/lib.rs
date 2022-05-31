pub mod deposit;
pub mod withdraw;
pub mod params;

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
pub struct UserCredential {
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub balance: u64,
    pub index: u64,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProofResult {
    pub instructions: Instructions,
    pub user_credential: UserCredential,
}

#[wasm_bindgen]
pub fn get_merkle_friends_pubkeys(key: Pubkey, data: Uint8Array) -> JsValue {
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
            let (friend, _) = get_merkle_node_pda(&key, layer, index, &ID);
            
            friend
        })
        .collect::<Vec<_>>();

    JsValue::from_serde(&friends).expect("serde error")
}