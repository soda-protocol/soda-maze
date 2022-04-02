use std::cell::{RefCell, RefMut};
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::pubkey::Pubkey;

pub struct UpdateContext<'a, S: Clone + BorshSerialize + BorshDeserialize> {
    pubkey: Pubkey,
    is_closed: RefCell<bool>,
    state: RefCell<&'a mut S>,
}

impl<'a, S: Clone + BorshSerialize + BorshDeserialize> UpdateContext<'a, S> {
    pub fn new(pubkey: Pubkey, state: &'a mut S) -> Self {
        Self {
            pubkey,
            is_closed: RefCell::new(false),
            state: RefCell::new(state),
        }
    }

    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    pub fn close(&self) {
        *self.is_closed.borrow_mut() = true;
    }

    pub fn is_closed(&self) -> bool {
        *self.is_closed.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, &'a mut S> {
        self.state.borrow_mut()
    }
}

pub struct ReadOnlyContext<'a, S: Clone + BorshSerialize + BorshDeserialize> {
    pubkey: Pubkey,
    is_closed: RefCell<bool>,
    state: &'a S,
}

impl<'a, S: Clone + BorshSerialize + BorshDeserialize> AsRef<S> for ReadOnlyContext<'a, S> {
    fn as_ref(&self) -> &S {
        self.state
    }
}

impl<'a, S: Clone + BorshSerialize + BorshDeserialize> ReadOnlyContext<'a, S> {
    pub fn new(pubkey: Pubkey, state: &'a S) -> Self {
        Self {
            pubkey,
            is_closed: RefCell::new(false),
            state,
        }
    }
    
    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    pub fn close(&self) {
        *self.is_closed.borrow_mut() = true;
    }

    pub fn is_closed(&self) -> bool {
        *self.is_closed.borrow()
    }
}

pub struct InitializeContext<S: Clone + BorshSerialize + BorshDeserialize> {
    pubkey: Pubkey,
    state: RefCell<Option<S>>,
}

impl<S: Clone + BorshSerialize + BorshDeserialize> InitializeContext<S> {
    pub fn new(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            state: RefCell::new(None),
        }
    }

    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    pub fn fill_with(&self, state: S) {
        *self.state.borrow_mut() = Some(state)
    }

    pub fn unwrap_state(self) -> S {
        self.state.take().unwrap()
    }
}
