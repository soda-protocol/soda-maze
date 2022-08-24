pub mod deposit;
pub mod withdraw;
pub mod params;
pub mod utils;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use js_sys::{Uint8Array, Array};
use serde::{Serialize, Deserialize};
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::{pubkey::Pubkey, hash::Hash, instruction::Instruction, message::{v0::Message as V0Message, VersionedMessage}};
use solana_sdk::{address_lookup_table_account::AddressLookupTableAccount, signature::Signature, transaction::VersionedTransaction};
use soda_maze_program::{Packer, ID};
use soda_maze_program::params::HEIGHT;
use soda_maze_program::core::{vault::Vault, node::get_merkle_node_pda, nullifier::Nullifier, utxo::{UTXO, Amount, get_utxo_pda}};
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
    let nullifier = PoseidonHasher::hash(params, &[Fr::from(leaf_index), secret]).unwrap();
    let nullifier = BigInteger256::new(nullifier.into_repr().0);
    let (nullifier, _) = get_nullifier_pda(&nullifier, &ID);

    nullifier
}

#[wasm_bindgen]
pub fn get_vault_info(data: Uint8Array) -> JsValue {
    console_error_panic_hook::set_once();

    let vault = Vault::unpack(&data.to_vec()).expect("Error: vault data can not unpack");
    JsValue::from_serde(&vault).unwrap()
}

#[wasm_bindgen]
pub fn get_merkle_neighbor_nodes(vault_key: &Pubkey, leaf_index: u64) -> Array {
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
            
            JsValue::from_serde(&neighbor).unwrap()
        });

    Array::from_iter(neighbors)
}

#[wasm_bindgen]
pub fn get_utxo_keys(sig: Uint8Array, vault: &Pubkey, num: u64) -> Array {
    console_error_panic_hook::set_once();

    let sig = &sig.to_vec()[..];
    assert_eq!(sig.len(), 64, "Error: sig length should be 64");

    let pubkeys = (0..num).map(|nonce| {
        let key = gen_utxo_key(sig, &vault, nonce);
        let (pubkey, _) = get_utxo_pda(key.as_ref(), &ID);
        
        JsValue::from_serde(&pubkey).unwrap()
    });

    Array::from_iter(pubkeys)
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

    JsValue::from_serde(&utxo).unwrap()
}

#[wasm_bindgen]
pub fn get_nullifier(data: Uint8Array) -> bool {
    console_error_panic_hook::set_once();

    let data = data.to_vec();
    if data.is_empty() {
        false
    } else {
        if Nullifier::unpack(&data).is_ok() {
            true
        } else {
            false
        }
    }
}

#[wasm_bindgen]
pub fn compile_versioned_message_data(
    payer: &Pubkey,
    lookup_table_key: &Pubkey,
    addresses: Array,
    instructions: Array,
    blockhash: &Hash,
) -> Uint8Array {
    console_error_panic_hook::set_once();

    let addresses = addresses.iter().map(|address| {
        address.into_serde().expect("Error: unparse addresses error")
    }).collect::<Vec<Pubkey>>();
    let address_lookup_table_account = AddressLookupTableAccount {
        key: *lookup_table_key,
        addresses,
    };

    let instructions = instructions.iter().map(|instruction| {
        instruction.into_serde().expect("Error: unparse instructions error")
    }).collect::<Vec<Instruction>>();

    let message = V0Message::try_compile(
        payer,
        &instructions,
        &[address_lookup_table_account],
        *blockhash,
    ).expect("Error: try compile v0 message error");
    let message_data = VersionedMessage::V0(message).serialize();

    Uint8Array::from(&message_data[..])
}

#[wasm_bindgen]
pub fn pack_versioned_transaction_data(
    message_data: Uint8Array,
    sig: Uint8Array,
) -> Uint8Array {
    console_error_panic_hook::set_once();

    let sig = sig.to_vec();
    assert_eq!(sig.len(), 64, "Error: sig length should be 64");
    let message_data = message_data.to_vec();
    let message = bincode::deserialize(&message_data).expect("Error: deserialize message data error");
    let tx = VersionedTransaction {
        message,
        signatures: vec![Signature::new(&sig)],
    };
    let tx_data = bincode::serialize(&tx).unwrap();

    Uint8Array::from(&tx_data[..])
}
