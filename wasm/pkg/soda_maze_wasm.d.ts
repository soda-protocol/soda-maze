/* tslint:disable */
/* eslint-disable */
/**
* @param {Pubkey} vault
* @param {Pubkey} mint
* @param {Pubkey} owner
* @param {BigInt} leaf_index
* @param {BigInt} deposit_amount
* @param {Array<any>} neighbors
* @param {Uint8Array} sig
* @param {BigInt} nonce
* @returns {any}
*/
export function gen_deposit_proof(vault: Pubkey, mint: Pubkey, owner: Pubkey, leaf_index: BigInt, deposit_amount: BigInt, neighbors: Array<any>, sig: Uint8Array, nonce: BigInt): any;
/**
* @param {Uint8Array} data
* @returns {any}
*/
export function get_vault_info(data: Uint8Array): any;
/**
* @param {Pubkey} vault_key
* @param {BigInt} leaf_index
* @returns {any}
*/
export function get_merkle_neighbor_nodes(vault_key: Pubkey, leaf_index: BigInt): any;
/**
* @param {Uint8Array} sig
* @param {Pubkey} vault
* @param {BigInt} num
* @returns {any}
*/
export function get_utxo_keys(sig: Uint8Array, vault: Pubkey, num: BigInt): any;
/**
* @param {Uint8Array} sig
* @param {Pubkey} vault
* @param {Uint8Array} utxo
* @returns {any}
*/
export function parse_utxo(sig: Uint8Array, vault: Pubkey, utxo: Uint8Array): any;
/**
* @param {Uint8Array} data
* @returns {any}
*/
export function get_nullifier(data: Uint8Array): any;
/**
* @param {Pubkey} vault
* @param {Pubkey} mint
* @param {Pubkey} owner
* @param {Pubkey} delegator
* @param {BigInt} src_leaf_index
* @param {BigInt} balance
* @param {BigInt} dst_leaf_index
* @param {BigInt} withdraw_amount
* @param {Uint8Array} sig
* @param {Array<any>} src_neighbors
* @param {Array<any>} dst_neighbors
* @param {BigInt} nonce
* @returns {any}
*/
export function gen_withdraw_proof(vault: Pubkey, mint: Pubkey, owner: Pubkey, delegator: Pubkey, src_leaf_index: BigInt, balance: BigInt, dst_leaf_index: BigInt, withdraw_amount: BigInt, sig: Uint8Array, src_neighbors: Array<any>, dst_neighbors: Array<any>, nonce: BigInt): any;
/**
* Initialize Javascript logging and panic handler
*/
export function solana_program_init(): void;
/**
*/
export class Hash {
  free(): void;
/**
* Create a new Hash object
*
* * `value` - optional hash as a base58 encoded string, `Uint8Array`, `[number]`
* @param {any} value
*/
  constructor(value: any);
/**
* Return the base58 string representation of the hash
* @returns {string}
*/
  toString(): string;
/**
* Checks if two `Hash`s are equal
* @param {Hash} other
* @returns {boolean}
*/
  equals(other: Hash): boolean;
/**
* Return the `Uint8Array` representation of the hash
* @returns {Uint8Array}
*/
  toBytes(): Uint8Array;
}
/**
* A directive for a single invocation of a Solana program.
*
* An instruction specifies which program it is calling, which accounts it may
* read or modify, and additional data that serves as input to the program. One
* or more instructions are included in transactions submitted by Solana
* clients. Instructions are also used to describe [cross-program
* invocations][cpi].
*
* [cpi]: https://docs.solana.com/developing/programming-model/calling-between-programs
*
* During execution, a program will receive a list of account data as one of
* its arguments, in the same order as specified during `Instruction`
* construction.
*
* While Solana is agnostic to the format of the instruction data, it has
* built-in support for serialization via [`borsh`] and [`bincode`].
*
* [`borsh`]: https://docs.rs/borsh/latest/borsh/
* [`bincode`]: https://docs.rs/bincode/latest/bincode/
*
* # Specifying account metadata
*
* When constructing an [`Instruction`], a list of all accounts that may be
* read or written during the execution of that instruction must be supplied as
* [`AccountMeta`] values.
*
* Any account whose data may be mutated by the program during execution must
* be specified as writable. During execution, writing to an account that was
* not specified as writable will cause the transaction to fail. Writing to an
* account that is not owned by the program will cause the transaction to fail.
*
* Any account whose lamport balance may be mutated by the program during
* execution must be specified as writable. During execution, mutating the
* lamports of an account that was not specified as writable will cause the
* transaction to fail. While _subtracting_ lamports from an account not owned
* by the program will cause the transaction to fail, _adding_ lamports to any
* account is allowed, as long is it is mutable.
*
* Accounts that are not read or written by the program may still be specified
* in an `Instruction`'s account list. These will affect scheduling of program
* execution by the runtime, but will otherwise be ignored.
*
* When building a transaction, the Solana runtime coalesces all accounts used
* by all instructions in that transaction, along with accounts and permissions
* required by the runtime, into a single account list. Some accounts and
* account permissions required by the runtime to process a transaction are
* _not_ required to be included in an `Instruction`s account list. These
* include:
*
* - The program ID &mdash; it is a separate field of `Instruction`
* - The transaction's fee-paying account &mdash; it is added during [`Message`]
*   construction. A program may still require the fee payer as part of the
*   account list if it directly references it.
*
* [`Message`]: crate::message::Message
*
* Programs may require signatures from some accounts, in which case they
* should be specified as signers during `Instruction` construction. The
* program must still validate during execution that the account is a signer.
*/
export class Instruction {
  free(): void;
}
/**
*/
export class Instructions {
  free(): void;
/**
*/
  constructor();
/**
* @param {Instruction} instruction
*/
  push(instruction: Instruction): void;
}
/**
* A Solana transaction message (legacy).
*
* See the [`message`] module documentation for further description.
*
* [`message`]: crate::message
*
* Some constructors accept an optional `payer`, the account responsible for
* paying the cost of executing a transaction. In most cases, callers should
* specify the payer explicitly in these constructors. In some cases though,
* the caller is not _required_ to specify the payer, but is still allowed to:
* in the `Message` structure, the first account is always the fee-payer, so if
* the caller has knowledge that the first account of the constructed
* transaction's `Message` is both a signer and the expected fee-payer, then
* redundantly specifying the fee-payer is not strictly required.
*/
export class Message {
  free(): void;
/**
* The id of a recent ledger entry.
*/
  recent_blockhash: Hash;
}
/**
*/
export class Pubkey {
  free(): void;
/**
* Create a new Pubkey object
*
* * `value` - optional public key as a base58 encoded string, `Uint8Array`, `[number]`
* @param {any} value
*/
  constructor(value: any);
/**
* Return the base58 string representation of the public key
* @returns {string}
*/
  toString(): string;
/**
* Check if a `Pubkey` is on the ed25519 curve.
* @returns {boolean}
*/
  isOnCurve(): boolean;
/**
* Checks if two `Pubkey`s are equal
* @param {Pubkey} other
* @returns {boolean}
*/
  equals(other: Pubkey): boolean;
/**
* Return the `Uint8Array` representation of the public key
* @returns {Uint8Array}
*/
  toBytes(): Uint8Array;
/**
* Derive a Pubkey from another Pubkey, string seed, and a program id
* @param {Pubkey} base
* @param {string} seed
* @param {Pubkey} owner
* @returns {Pubkey}
*/
  static createWithSeed(base: Pubkey, seed: string, owner: Pubkey): Pubkey;
/**
* Derive a program address from seeds and a program id
* @param {any[]} seeds
* @param {Pubkey} program_id
* @returns {Pubkey}
*/
  static createProgramAddress(seeds: any[], program_id: Pubkey): Pubkey;
/**
* Find a valid program address
*
* Returns:
* * `[PubKey, number]` - the program address and bump seed
* @param {any[]} seeds
* @param {Pubkey} program_id
* @returns {any}
*/
  static findProgramAddress(seeds: any[], program_id: Pubkey): any;
}
export class SystemInstruction {
  free(): void;
/**
* @param {Pubkey} from_pubkey
* @param {Pubkey} to_pubkey
* @param {BigInt} lamports
* @param {BigInt} space
* @param {Pubkey} owner
* @returns {Instruction}
*/
  static createAccount(from_pubkey: Pubkey, to_pubkey: Pubkey, lamports: BigInt, space: BigInt, owner: Pubkey): Instruction;
/**
* @param {Pubkey} from_pubkey
* @param {Pubkey} to_pubkey
* @param {Pubkey} base
* @param {string} seed
* @param {BigInt} lamports
* @param {BigInt} space
* @param {Pubkey} owner
* @returns {Instruction}
*/
  static createAccountWithSeed(from_pubkey: Pubkey, to_pubkey: Pubkey, base: Pubkey, seed: string, lamports: BigInt, space: BigInt, owner: Pubkey): Instruction;
/**
* @param {Pubkey} pubkey
* @param {Pubkey} owner
* @returns {Instruction}
*/
  static assign(pubkey: Pubkey, owner: Pubkey): Instruction;
/**
* @param {Pubkey} pubkey
* @param {Pubkey} base
* @param {string} seed
* @param {Pubkey} owner
* @returns {Instruction}
*/
  static assignWithSeed(pubkey: Pubkey, base: Pubkey, seed: string, owner: Pubkey): Instruction;
/**
* @param {Pubkey} from_pubkey
* @param {Pubkey} to_pubkey
* @param {BigInt} lamports
* @returns {Instruction}
*/
  static transfer(from_pubkey: Pubkey, to_pubkey: Pubkey, lamports: BigInt): Instruction;
/**
* @param {Pubkey} from_pubkey
* @param {Pubkey} from_base
* @param {string} from_seed
* @param {Pubkey} from_owner
* @param {Pubkey} to_pubkey
* @param {BigInt} lamports
* @returns {Instruction}
*/
  static transferWithSeed(from_pubkey: Pubkey, from_base: Pubkey, from_seed: string, from_owner: Pubkey, to_pubkey: Pubkey, lamports: BigInt): Instruction;
/**
* @param {Pubkey} pubkey
* @param {BigInt} space
* @returns {Instruction}
*/
  static allocate(pubkey: Pubkey, space: BigInt): Instruction;
/**
* @param {Pubkey} address
* @param {Pubkey} base
* @param {string} seed
* @param {BigInt} space
* @param {Pubkey} owner
* @returns {Instruction}
*/
  static allocateWithSeed(address: Pubkey, base: Pubkey, seed: string, space: BigInt, owner: Pubkey): Instruction;
/**
* @param {Pubkey} from_pubkey
* @param {Pubkey} nonce_pubkey
* @param {Pubkey} authority
* @param {BigInt} lamports
* @returns {Array<any>}
*/
  static createNonceAccount(from_pubkey: Pubkey, nonce_pubkey: Pubkey, authority: Pubkey, lamports: BigInt): Array<any>;
/**
* @param {Pubkey} nonce_pubkey
* @param {Pubkey} authorized_pubkey
* @returns {Instruction}
*/
  static advanceNonceAccount(nonce_pubkey: Pubkey, authorized_pubkey: Pubkey): Instruction;
/**
* @param {Pubkey} nonce_pubkey
* @param {Pubkey} authorized_pubkey
* @param {Pubkey} to_pubkey
* @param {BigInt} lamports
* @returns {Instruction}
*/
  static withdrawNonceAccount(nonce_pubkey: Pubkey, authorized_pubkey: Pubkey, to_pubkey: Pubkey, lamports: BigInt): Instruction;
/**
* @param {Pubkey} nonce_pubkey
* @param {Pubkey} authorized_pubkey
* @param {Pubkey} new_authority
* @returns {Instruction}
*/
  static authorizeNonceAccount(nonce_pubkey: Pubkey, authorized_pubkey: Pubkey, new_authority: Pubkey): Instruction;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly gen_deposit_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => number;
  readonly get_vault_info: (a: number) => number;
  readonly get_merkle_neighbor_nodes: (a: number, b: number, c: number) => number;
  readonly get_utxo_keys: (a: number, b: number, c: number, d: number) => number;
  readonly parse_utxo: (a: number, b: number, c: number) => number;
  readonly get_nullifier: (a: number) => number;
  readonly gen_withdraw_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => number;
  readonly __wbg_pubkey_free: (a: number) => void;
  readonly systeminstruction_createAccount: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
  readonly systeminstruction_createAccountWithSeed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
  readonly systeminstruction_assign: (a: number, b: number) => number;
  readonly systeminstruction_assignWithSeed: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly systeminstruction_transfer: (a: number, b: number, c: number, d: number) => number;
  readonly systeminstruction_transferWithSeed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
  readonly systeminstruction_allocate: (a: number, b: number, c: number) => number;
  readonly systeminstruction_allocateWithSeed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
  readonly systeminstruction_createNonceAccount: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly systeminstruction_advanceNonceAccount: (a: number, b: number) => number;
  readonly systeminstruction_withdrawNonceAccount: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly systeminstruction_authorizeNonceAccount: (a: number, b: number, c: number) => number;
  readonly __wbg_instruction_free: (a: number) => void;
  readonly pubkey_constructor: (a: number, b: number) => void;
  readonly pubkey_toString: (a: number, b: number) => void;
  readonly pubkey_isOnCurve: (a: number) => number;
  readonly pubkey_equals: (a: number, b: number) => number;
  readonly pubkey_toBytes: (a: number, b: number) => void;
  readonly pubkey_createWithSeed: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly pubkey_createProgramAddress: (a: number, b: number, c: number, d: number) => void;
  readonly pubkey_findProgramAddress: (a: number, b: number, c: number, d: number) => void;
  readonly solana_program_init: () => void;
  readonly __wbg_instructions_free: (a: number) => void;
  readonly instructions_constructor: () => number;
  readonly instructions_push: (a: number, b: number) => void;
  readonly __wbg_hash_free: (a: number) => void;
  readonly __wbg_message_free: (a: number) => void;
  readonly __wbg_get_message_recent_blockhash: (a: number) => number;
  readonly __wbg_set_message_recent_blockhash: (a: number, b: number) => void;
  readonly hash_constructor: (a: number, b: number) => void;
  readonly hash_toString: (a: number, b: number) => void;
  readonly hash_equals: (a: number, b: number) => number;
  readonly hash_toBytes: (a: number, b: number) => void;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
}

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
