use std::{cell::{RefCell, RefMut}, ops::{DerefMut, Deref}};
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{pubkey::Pubkey, account_info::AccountInfo, program_error::ProgramError, entrypoint::ProgramResult, rent::Rent};

use crate::{state::StateWrapper, Packer, error::MazeError};

#[derive(Debug, PartialEq)]
enum Status {
    NotInitialized,
    Pending,
    Took,
    Filled,
    Updating,
    Erased,
    Closed,
}

pub struct RefMutWrapper<'a, S>(RefMut<'a, Option<S>>);

impl<'a, S: Clone + BorshSerialize + BorshDeserialize> Deref for RefMutWrapper<'a, S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl<'a, S: Clone + BorshSerialize + BorshDeserialize> DerefMut for RefMutWrapper<'a, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

pub type Context512<'a, 'b, S> = Context<'a, 'b, S, 512>;
pub type Context1024<'a, 'b, S> = Context<'a, 'b, S, 1024>;
pub type Context1536<'a, 'b, S> = Context<'a, 'b, S, 1536>;
pub type Context2048<'a, 'b, S> = Context<'a, 'b, S, 2048>;

pub struct Context<'a, 'b, S: Clone + BorshSerialize + BorshDeserialize, const LEN: usize> {
    state_info: &'a AccountInfo<'b>,
    status: RefCell<Status>,
    state: RefCell<Option<S>>,
}

impl<'a, 'b, S: Clone + BorshSerialize + BorshDeserialize, const LEN: usize> Context<'a, 'b, S, LEN> {
    pub fn new(state_info: &'a AccountInfo<'b>, program_id: &Pubkey) -> Result<Self, ProgramError> {
        let ctx = if let Some(state_wrapper)
            = StateWrapper::<S, LEN>::unchecked_unpack_from_account_info(state_info, program_id)? {
            Self {
                state_info,
                status: RefCell::new(Status::Pending),
                state: RefCell::new(Some(state_wrapper.unwrap_state())),
            }
        } else {
            Self {
                state_info,
                status: RefCell::new(Status::NotInitialized),
                state: RefCell::new(None),
            }
        };

        Ok(ctx)
    }

    pub fn pubkey(&self) -> &Pubkey {
        self.state_info.key
    }

    pub fn take(&self) -> Result<S, ProgramError> {
        if *self.status.borrow() != Status::Pending {
            return Err(MazeError::InvalidContextStatus.into());
        }

        *self.status.borrow_mut() = Status::Took;
        Ok(self.state.take().unwrap())
    }

    pub fn borrow_mut(&self) -> Result<RefMutWrapper<'_, S>, ProgramError> {
        if *self.status.borrow() != Status::Pending {
            return Err(MazeError::InvalidContextStatus.into());
        }

        *self.status.borrow_mut() = Status::Updating;
        Ok(RefMutWrapper(self.state.borrow_mut()))
    }

    pub fn fill(&self, state: S) -> ProgramResult {
        if *self.status.borrow() != Status::NotInitialized {
            Err(MazeError::InvalidContextStatus.into())
        } else {
            *self.status.borrow_mut() = Status::Filled;
            *self.state.borrow_mut() = Some(state);

            Ok(())
        }
    }

    pub fn erase(&self) -> ProgramResult {
        let status = &*self.status.borrow();
        if status != &Status::Took && status != &Status::Updating {
            Err(MazeError::InvalidContextStatus.into())
        } else {
            *self.status.borrow_mut() = Status::Erased;

            Ok(())
        }
    }

    pub fn close(&self) -> ProgramResult {
        let status = &*self.status.borrow();
        if status != &Status::Took && status != &Status::Updating {
            Err(MazeError::InvalidContextStatus.into())
        } else {
            *self.status.borrow_mut() = Status::Closed;

            Ok(())
        }
    }
    
    pub fn finalize(
        self,
        rent: &Rent,
        receiver_info: &AccountInfo,
    ) -> ProgramResult {
        let state_info = self.state_info;
        let state = self.state.into_inner();
        let status = self.status.into_inner();

        match status {
            Status::Filled => {
                StateWrapper::<S, LEN>::new(state.unwrap())
                    .unchecked_initialize_to_account_info(rent, state_info)?;
            }
            Status::Updating => {
                StateWrapper::<S, LEN>::new(state.unwrap()).pack_to_account_info(state_info)?;
            }
            Status::Erased => {
                StateWrapper::<S, LEN>::erase_account_info(state_info)?;
            }
            Status::Closed => {
                **receiver_info.lamports.borrow_mut() = receiver_info
                    .lamports()
                    .checked_add(state_info.lamports())
                    .ok_or(MazeError::MathOverflow)?;
                **state_info.lamports.borrow_mut() = 0;
            }
            _ => {}
        };

        Ok(())
    }
}
