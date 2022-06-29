pub mod deposit;
pub mod withdraw;
pub mod params;
pub mod utils;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use js_sys::Uint8Array;
use serde::{Serialize, Deserialize};
use soda_maze_program::core::nullifier::Nullifier;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::pubkey::Pubkey;
use soda_maze_program::{Packer, ID};
use soda_maze_program::params::HEIGHT;
use soda_maze_program::store::utxo::{UTXO, Amount, get_utxo_pda};
use soda_maze_program::core::{vault::Vault, node::get_merkle_node_pda};
use utils::{decrypt_balance, gen_utxo_key, gen_secret};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    leaf_index: u64,
    amount: u64,
    nullifier: Pubkey,
}

fn get_nullifier_pubkey(leaf_index: u64, secret: Fr) -> Pubkey {
    use soda_maze_lib::params::poseidon::get_poseidon_bn254_for_nullifier;
    use soda_maze_lib::vanilla::hasher::{FieldHasher, poseidon::PoseidonHasher};
    use soda_maze_program::bn::BigInteger256;
    use soda_maze_program::core::nullifier::get_nullifier_pda;

    let ref params = get_poseidon_bn254_for_nullifier();
    let nullifier = PoseidonHasher::hash(params, &[Fr::from(leaf_index), secret]).expect("Error: poseidon hash error");
    let nullifier = BigInteger256::new(nullifier.into_repr().0);
    let (nullifier, _) = get_nullifier_pda(&nullifier, &ID);

    nullifier
}

#[wasm_bindgen]
pub fn get_vault_info(data: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let vault = Vault::unpack(&data.to_vec()).expect("Error: vault data can not unpack");
    JsValue::from_serde(&vault).expect("Error: serde vault error")
}

#[wasm_bindgen]
pub fn get_merkle_neighbor_nodes(vault_key: &Pubkey, leaf_index: u64) -> JsValue {
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
    JsValue::from_serde(&neighbors).expect("Error: serde neighbors error")
}

#[wasm_bindgen]
pub fn get_utxo_keys(sig: Uint8Array, vault: &Pubkey, num: u64) -> JsValue {
    console_error_panic_hook::set_once();

    let sig = &sig.to_vec()[..];
    assert_eq!(sig.len(), 64, "Error: sig length should be 64");

    let pubkeys = (0..num).map(|nonce| {
        let key = gen_utxo_key(sig, &vault, nonce);
        let (pubkey, _) = get_utxo_pda(key.as_ref(), &ID);
        pubkey
    }).collect::<Vec<_>>();

    JsValue::from_serde(&pubkeys).expect("Error: serde pubkeys error")
}

#[wasm_bindgen]
pub fn parse_utxo(sig: Uint8Array, vault: &Pubkey, utxo: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let sig = sig.to_vec();
    assert_eq!(sig.len(), 64, "Error: sig length should be 64");

    let utxo = UTXO::unpack(&utxo.to_vec())
        .expect("Error: UTXO data can not unpack");
    let amount = match utxo.amount {
        Amount::Cipher(cipher) => decrypt_balance(&sig, &vault, cipher),
        Amount::Origin(amount) => amount,
    };
    let secret = gen_secret(&sig, &vault);
    let nullifier = get_nullifier_pubkey(utxo.leaf_index, secret);

    let utxo = Utxo {
        leaf_index: utxo.leaf_index,
        amount,
        nullifier,
    };

    JsValue::from_serde(&utxo).expect("Error: serde utxo error")
}

#[wasm_bindgen]
pub fn get_nullifier(data: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let data = data.to_vec();
    let used = if data.is_empty() {
        false
    } else {
        let nullifier = Nullifier::unpack(&data).expect("Error: invalid nullifier");
        nullifier.used
    };
    JsValue::from_bool(used)
}