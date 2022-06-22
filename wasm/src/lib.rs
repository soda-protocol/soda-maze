pub mod deposit;
pub mod withdraw;
pub mod params;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use js_sys::Uint8Array;
use serde::{Serialize, Deserialize};
use easy_aes::{full_decrypt, BLOCK, Keys};
use soda_maze_program::core::nullifier::Nullifier;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_program::hash::hash;
use soda_maze_program::{Packer, ID};
use soda_maze_program::params::HEIGHT;
use soda_maze_program::store::utxo::{UTXO, Amount, get_utxo_pda};
use soda_maze_program::core::{vault::Vault, node::get_merkle_node_pda};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    index: u64,
    amount: u64,
    nullifier: Pubkey,
}

#[derive(Serialize, Deserialize)]
pub struct Instructions {
    pub reset: Instruction,
    pub credential: Instruction,
    pub verifier: Instruction,
    pub verify: Vec<Instruction>,
    pub finalize: Instruction,
}

fn get_nullifier_pubkey(index: u64, secret: Fr) -> Pubkey {
    use soda_maze_lib::params::poseidon::get_poseidon_bn254_for_nullifier;
    use soda_maze_lib::vanilla::hasher::{FieldHasher, poseidon::PoseidonHasher};
    use soda_maze_program::bn::BigInteger256;
    use soda_maze_program::core::nullifier::get_nullifier_pda;

    let ref params = get_poseidon_bn254_for_nullifier();
    let nullifier = PoseidonHasher::hash(params, &[Fr::from(index), secret]).expect("poseidon hash error");
    let nullifier = BigInteger256::new(nullifier.into_repr().0);
    let (nullifier, _) = get_nullifier_pda(&nullifier, &ID);

    nullifier
}

#[wasm_bindgen]
pub fn get_vault_info(data: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let vault = Vault::unpack(&data.to_vec()).expect("vault data can not unpack");
    JsValue::from_serde(&vault).expect("serde error")
}

#[wasm_bindgen]
pub fn get_merkle_neighbor_nodes(vault_key: Pubkey, leaf_index: u64) -> JsValue {
    console_error_panic_hook::set_once();

    let neighbors = (0..HEIGHT)
        .into_iter()
        .map(|layer| {
            let index = leaf_index >> layer;
            let (layer, index) = if index % 2 == 0 {
                (layer as u8, index + 1)
            } else {
                (layer as u8, index - 1)
            };
            let (neighbor, _) = get_merkle_node_pda(&vault_key, layer, index, &ID);
            
            neighbor
        })
        .collect::<Vec<_>>();
    JsValue::from_serde(&neighbors).expect("serde error")
}

#[wasm_bindgen]
pub fn get_utxo_keys(sig: Uint8Array, num: u64) -> JsValue {
    console_error_panic_hook::set_once();

    let sig = &sig.to_vec()[..];
    let pubkeys = (0..num).map(|id| {
        let key = hash(&[sig, &id.to_le_bytes()].concat());
        let (pubkey, _) = get_utxo_pda(key.as_ref(), &ID);
        pubkey
    }).collect::<Vec<_>>();

    JsValue::from_serde(&pubkeys).expect("serde error")
}

#[wasm_bindgen]
pub fn parse_utxo(sig: Uint8Array, utxo: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let sig = sig.to_vec();
    let utxo = UTXO::unpack(&utxo.to_vec())
        .expect("UTXO data can not unpack");
    let amount = match utxo.amount {
        Amount::Cipher(cipher) => {
            let seed = hash(&sig);

            let key1 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&seed.as_ref()[..16]).expect("invalid key")));
            let key2 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&seed.as_ref()[16..]).expect("invalid key")));

            let mut block = BLOCK::new(cipher);
            full_decrypt(&mut block, &key1);
            full_decrypt(&mut block, &key2);

            u128::from_le_bytes(block.stringify_block()) as u64
        }
        Amount::Origin(amount) => amount,
    };
    let secret = Fr::from_le_bytes_mod_order(&sig);
    let nullifier = get_nullifier_pubkey(utxo.index, secret);

    let utxo = Utxo {
        index: utxo.index,
        amount,
        nullifier,
    };

    JsValue::from_serde(&utxo).expect("serde error")
}

#[wasm_bindgen]
pub fn get_nullifier(data: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let data = data.to_vec();
    let used = if data.is_empty() {
        false
    } else {
        let nullifier = Nullifier::unpack(&data.to_vec()).expect("invalid nullifier");
        nullifier.used
    };
    JsValue::from_bool(used)
}