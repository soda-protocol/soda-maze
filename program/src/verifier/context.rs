use std::cell::{RefCell, RefMut, Ref};
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::pubkey::Pubkey;

pub struct UpdateContext<S: Clone + BorshSerialize + BorshDeserialize> {
    pubkey: Pubkey,
    is_closed: RefCell<bool>,
    state: RefCell<S>,
}

impl<S: Clone + BorshSerialize + BorshDeserialize> UpdateContext<S> {
    pub fn new(pubkey: Pubkey, state: S) -> Self {
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

    pub fn borrow_mut(&self) -> RefMut<'_, S> {
        self.state.borrow_mut()
    }

    pub fn take(self) -> S {
        self.state.into_inner()
    }
}

pub struct ReadOnlyContext<S: Clone + BorshSerialize + BorshDeserialize> {
    pubkey: Pubkey,
    is_closed: RefCell<bool>,
    state: RefCell<Option<S>>,
}

impl<S: Clone + BorshSerialize + BorshDeserialize> ReadOnlyContext<S> {
    pub fn new(pubkey: Pubkey, state: S) -> Self {
        Self {
            pubkey,
            is_closed: RefCell::new(false),
            state: RefCell::new(Some(state)),
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

    pub fn take(&self) -> S {
        self.state.take().unwrap()
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

    pub fn take(self) -> S {
        self.state.into_inner().unwrap()
    }
}
