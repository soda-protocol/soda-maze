use arrayref::array_refs;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::{pubkey::Pubkey, entrypoint::ProgramResult, program_pack::IsInitialized, program_error::ProgramError};

use crate::{params::{Fr, G1Projective254}, HEIGHT, error::MazeError, DEPOSIT_INPUTS, bn::BigInteger256, WITHDRAW_INPUTS, OperationType, verifier::fsm::{PrepareInputs, VerifyState}, Packer};
use crate::verifier::{fsm::FSM};
use crate::context::Context;

#[inline]
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

    pub fn to_verify_state(
        self,
        public_inputs_1_ctx: &Context<Vec<Fr>>,
        public_inputs_2_ctx: &Context<Vec<Fr>>,
        public_inputs_3_ctx: &Context<Vec<Fr>>,
        g_ic_ctx: &Context<G1Projective254>,
        tmp_ctx: &Context<G1Projective254>,
    ) -> Result<VerifyState, ProgramError> {
        let proof_type = self.operation_type();
        let pvk = proof_type.verifying_key();
        g_ic_ctx.fill(*pvk.g_ic_init)?;
        tmp_ctx.fill(G1Projective254::zero())?;

        let public_inputs = match self {
            Operation::Deposit(deposit) => deposit.to_public_inputs(),
            Operation::Withdarw(withdraw) => withdraw.to_public_inputs(),
        };
        
        let batch_len = public_inputs.len() / 3;
        let mut public_inputs_1 = Vec::with_capacity(batch_len);
        let mut public_inputs_2 = Vec::with_capacity(batch_len);
        let mut public_inputs_3 = Vec::with_capacity(public_inputs.len() - batch_len * 2);

        public_inputs
            .into_iter()
            .enumerate()
            .for_each(|(i, p_i)| {
                if i < batch_len {
                    public_inputs_1.push(p_i);
                } else if i < batch_len * 2 {
                    public_inputs_2.push(p_i);
                } else {
                    public_inputs_3.push(p_i);
                }
            });

        public_inputs_1_ctx.fill(public_inputs_1)?;
        public_inputs_2_ctx.fill(public_inputs_2)?;
        public_inputs_3_ctx.fill(public_inputs_3)?;

        let fsm = FSM::PrepareInputs(PrepareInputs {
            input_index: 0,
            bit_index: 0,
            public_inputs_1: *public_inputs_1_ctx.pubkey(),
            public_inputs_2: *public_inputs_2_ctx.pubkey(),
            public_inputs_3: *public_inputs_3_ctx.pubkey(),
            g_ic: *g_ic_ctx.pubkey(),
            tmp: *tmp_ctx.pubkey(),
        });

        Ok(VerifyState {
            is_initialized: true,
            proof_type,
            fsm,
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct VanillaInfo {
    pub is_initialized: bool,
    pub operation: Operation,
    pub operator: Pubkey,
    pub verify_state: Pubkey,
}

impl VanillaInfo {
    pub fn new(operation: Operation, operator: Pubkey, verify_state: Pubkey) -> Self {
        Self {
            is_initialized: true,
            operation,
            operator,
            verify_state,
        }
    }
}

impl IsInitialized for VanillaInfo {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for VanillaInfo {
    const LEN: usize = 1024;
}
