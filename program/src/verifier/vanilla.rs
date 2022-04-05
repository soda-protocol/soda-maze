use arrayref::array_refs;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::{pubkey::Pubkey, entrypoint::ProgramResult};

use crate::{params::{Fr, G1Projective254}, HEIGHT, error::MazeError, DEPOSIT_INPUTS, bn::BigInteger256, WITHDRAW_INPUTS, OperationType, verifier::fsm::PrepareInputs};

use super::{fsm::VerifyStage, context::InitializeContext};

fn pubkey_to_fr(pubkey: Pubkey) -> Fr {
    let pubkey = &pubkey.to_bytes();
    let (d0, d1, d2, d3) = array_refs![pubkey, 8, 8, 8, 8];
    let fr_data = [
        u64::from_le_bytes(*d0),
        u64::from_le_bytes(*d1),
        u64::from_le_bytes(*d2),
        u64::from_le_bytes(*d3) & 0x1FFF_FFFF_FFFF_FFFF,
    ];

    Fr::new(BigInteger256::new(fr_data))
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositInfo {
    pub mint: Pubkey,
    pub deposit_amount: u64,
    pub old_root: Fr,
    pub leaf: Fr,
    pub leaf_index: u32,
    pub update_nodes: Vec<Fr>,
}

impl DepositInfo {
    pub fn check_valid(&self) -> ProgramResult {
        if !self.old_root.is_valid() {
            return Err(MazeError::DepositTooSmall.into());
        }
        if !self.leaf.is_valid() {
            return Err(MazeError::DepositTooSmall.into());
        }
        if !self.update_nodes.iter().all(|x| x.is_valid()) {
            return Err(MazeError::DepositTooSmall.into());
        }
        if self.update_nodes.len() != HEIGHT {
            return Err(MazeError::DepositTooSmall.into());
        }
        if self.leaf_index >= 1 << HEIGHT {
            return Err(MazeError::DepositTooSmall.into());
        }
        
        Ok(())
    }

    pub fn to_public_inputs(self) -> Vec<Fr> {
        let mut inputs = Vec::with_capacity(DEPOSIT_INPUTS);

        inputs.push(pubkey_to_fr(self.mint));
        inputs.push(Fr::new(BigInteger256::from(self.deposit_amount)));
        inputs.push(self.old_root);
        inputs.push(Fr::new(BigInteger256::from(self.leaf_index as u64)));
        inputs.push(self.leaf);
        inputs.extend(self.update_nodes);

        assert_eq!(inputs.len(), DEPOSIT_INPUTS);

        inputs
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct WithdrawInfo {
    pub mint: Pubkey,
    pub withdraw_amount: u64,
    pub nullifier: Fr,
    pub old_root: Fr,
    pub new_leaf: Fr,
    pub new_leaf_index: u32,
    pub update_nodes: Vec<Fr>,
}

impl WithdrawInfo {
    pub fn check_valid(&self) -> ProgramResult {
        if !self.old_root.is_valid() {
            return Err(MazeError::DepositTooSmall.into());
        }
        if !self.new_leaf.is_valid() {
            return Err(MazeError::DepositTooSmall.into());
        }
        if !self.update_nodes.iter().all(|x| x.is_valid()) {
            return Err(MazeError::DepositTooSmall.into());
        }
        if self.update_nodes.len() != HEIGHT {
            return Err(MazeError::DepositTooSmall.into());
        }
        if self.new_leaf_index >= 1 << HEIGHT {
            return Err(MazeError::DepositTooSmall.into());
        }

        Ok(())
    }

    pub fn to_public_inputs(self) -> Vec<Fr> {
        let mut inputs = Vec::with_capacity(WITHDRAW_INPUTS);

        inputs.push(pubkey_to_fr(self.mint));
        inputs.push(Fr::new(BigInteger256::from(self.withdraw_amount)));
        inputs.push(self.nullifier);
        inputs.push(self.old_root);
        inputs.push(Fr::new(BigInteger256::from(self.new_leaf_index as u64)));
        inputs.push(self.new_leaf);
        inputs.extend(self.update_nodes);

        assert_eq!(inputs.len(), WITHDRAW_INPUTS);

        inputs
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum Operation {
    Deposit(DepositInfo),
    Withdarw(WithdrawInfo),
}

impl Operation {
    pub fn operation_type(&self) -> OperationType {
        match self {
            Operation::Deposit(_) => OperationType::Deposit,
            Operation::Withdarw(_) => OperationType::Withdraw,
        }
    }

    pub fn check_valid(&self) -> ProgramResult {
        match self {
            Operation::Deposit(deposit) => deposit.check_valid(),
            Operation::Withdarw(withdraw) => withdraw.check_valid(),
        }
    }

    pub fn to_verify_stage(
        self,
        prepare_inputs_ctx: &InitializeContext<Vec<Fr>>,
        g_ic_ctx: &InitializeContext<G1Projective254>,
        tmp_ctx: &InitializeContext<G1Projective254>,
    ) -> VerifyStage {
        let operation_type = &self.operation_type();
        let pvk = operation_type.verifying_key();
        g_ic_ctx.fill_with(*pvk.g_ic_init);
        tmp_ctx.fill_with(G1Projective254::zero());

        let public_inputs = match self {
            Operation::Deposit(deposit) => deposit.to_public_inputs(),
            Operation::Withdarw(withdraw) => withdraw.to_public_inputs(),
        };
        prepare_inputs_ctx.fill_with(public_inputs);

        VerifyStage::PrepareInputs(PrepareInputs {
            input_index: 0,
            bit_index: 0,
            public_inputs: prepare_inputs_ctx.pubkey(),
            g_ic: g_ic_ctx.pubkey(),
            tmp: tmp_ctx.pubkey(),
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct VanillaInfo {
    pub is_initialized: bool,
    pub pool: Pubkey,
    pub operator: Pubkey,
    pub operation: Operation,
}


