use std::ops::{MulAssign, Mul};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::One;
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::params::proof::PreparedVerifyingKey;
use crate::{bn::BnParameters as Bn, bn::Field, error::MazeError};
use crate::params::{bn::*, bn::Bn254Parameters as BnParameters};
use crate::context::Context512;

use super::fsm::FSM;

fn exp_by_neg_x(
    index: &mut u8,
    res: &mut Fqk254,
    fe: &Fqk254,
    fe_inv: &Fqk254,
) -> bool {
    let naf = <BnParameters as Bn>::NAF;

    const MAX_LOOP: usize = 8;
    for _ in 0..MAX_LOOP {
        res.square_in_place();

        let value = naf[*index as usize];
        *index += 1;

        if value > 0 {
            res.mul_assign(fe);
        } else if value < 0 {
            res.mul_assign(fe_inv);
        }

        if (*index as usize) >= naf.len() {
            if !<BnParameters as Bn>::X_IS_NEGATIVE {
                res.conjugate();
            }
            // finished
            return true;
        }
    }
    // next loop
    false
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentEasyPart {
    pub r: Pubkey, // Fqk254
}

impl FinalExponentEasyPart {
    pub fn process(
        self,
        r_ctx: &Context512<Fqk254>,
        r_inv_ctx: &Context512<Fqk254>,
        y0_ctx: &Context512<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut r = r_ctx.borrow_mut()?;

        if let Some(mut f2) = r.inverse() {
            r.conjugate();

            // f2 = f^(-1);
            // r = f^(p^6 - 1)
            r.mul_assign(&f2);

            // f2 = f^(p^6 - 1)
            f2 = *r;

            // r = f^((p^6 - 1)(p^2))
            r.frobenius_map(2);

            r.mul_assign(f2);

            // goto hard part 1
            let mut r_inv = *r;
            r_inv.conjugate();

            r_inv_ctx.fill(r_inv)?;
            y0_ctx.fill(Fqk254::one())?;
            Ok(FSM::FinalExponentHardPart1(FinalExponentHardPart1 {
                index: 0,
                r: self.r,
                r_inv: *r_inv_ctx.pubkey(),
                y0: *y0_ctx.pubkey(),
            }))
        } else {
            // proof failed
            Ok(FSM::Finished(false))
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart1 {
    pub index: u8,
    pub r: Pubkey, // Fqk254
    pub r_inv: Pubkey, // Fqk254
    pub y0: Pubkey, // Fqk254
}

impl FinalExponentHardPart1 {
    pub fn process(
        mut self,
        r_ctx: &Context512<Fqk254>,
        r_inv_ctx: &Context512<Fqk254>,
        y0_ctx: &Context512<Fqk254>,
        y3_ctx: &Context512<Fqk254>,
        y4_ctx: &Context512<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_inv_ctx.pubkey() != &self.r_inv {
            msg!("r_inv_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y0_ctx.pubkey() != &self.y0 {
            msg!("y0_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let r = r_ctx.take()?;
        let mut r_inv = r_inv_ctx.borrow_mut()?;
        let mut y0 = y0_ctx.borrow_mut()?;

        let finished = exp_by_neg_x(
            &mut self.index,
            &mut y0,
            &r,
            &r_inv,
        );
        if finished {
            let y1 = y0.cyclotomic_square();
            let y2 = y1.cyclotomic_square();
            
            let y3 = y2 * &y1;
            let mut y3_inv = y3;
            y3_inv.conjugate();

            // goto hard part 2
            // replace y0 to y1
            *y0 = y1;
            // replace r_inv to y3_inv
            *r_inv = y3_inv;
            y3_ctx.fill(y3)?;
            y4_ctx.fill(Fqk254::one())?;
            Ok(FSM::FinalExponentHardPart2(FinalExponentHardPart2 {
                index: 0,
                r: self.r,
                y1: self.y0,
                y3: *y3_ctx.pubkey(),
                y3_inv: self.r_inv,
                y4: *y4_ctx.pubkey(),
            }))
        } else {
            // next loop
            Ok(FSM::FinalExponentHardPart1(self))
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart2 {
    pub index: u8,
    pub r: Pubkey, // Fqk254
    pub y1: Pubkey, // Fqk254
    pub y3: Pubkey, // Fqk254
    pub y3_inv: Pubkey, // Fqk254
    pub y4: Pubkey, // Fqk254
}

impl FinalExponentHardPart2 {
    pub fn process(
        mut self,
        y3_ctx: &Context512<Fqk254>,
        y3_inv_ctx: &Context512<Fqk254>,
        y4_ctx: &Context512<Fqk254>,
        y5_ctx: &Context512<Fqk254>,
        y6_ctx: &Context512<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y3_ctx.pubkey() != &self.y3 {
            msg!("y3_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y3_inv_ctx.pubkey() != &self.y3_inv {
            msg!("y3_inv_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y4_ctx.pubkey() != &self.y4 {
            msg!("y4_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y3 = y3_ctx.take()?;
        let mut y3_inv = y3_inv_ctx.borrow_mut()?;
        let mut y4 = y4_ctx.borrow_mut()?;

        let finished = exp_by_neg_x(
            &mut self.index,
            &mut y4,
            &y3,
            &y3_inv,
        );
        if finished {
            let y5 = y4.cyclotomic_square();
            let mut y5_inv = y5;
            y5_inv.conjugate();

            // goto hard part 3
            // replace y3_inv to y5_inv
            *y3_inv = y5_inv;
            y5_ctx.fill(y5)?;
            y6_ctx.fill(Fqk254::one())?;
            Ok(FSM::FinalExponentHardPart3(FinalExponentHardPart3 {
                index: 0,
                r: self.r,
                y1: self.y1,
                y3: self.y3,
                y4: self.y4,
                y5: *y5_ctx.pubkey(),
                y5_inv: self.y3_inv,
                y6: *y6_ctx.pubkey(),
            }))
        } else {
            Ok(FSM::FinalExponentHardPart2(self))
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart3 {
    pub index: u8,
    pub r: Pubkey,
    pub y1: Pubkey,
    pub y3: Pubkey,
    pub y4: Pubkey,
    pub y5: Pubkey,
    pub y5_inv: Pubkey,
    pub y6: Pubkey,
}

impl FinalExponentHardPart3 {
    pub fn process(
        mut self,
        y3_ctx: &Context512<Fqk254>,
        y4_ctx: &Context512<Fqk254>,
        y5_ctx: &Context512<Fqk254>,
        y5_inv_ctx: &Context512<Fqk254>,
        y6_ctx: &Context512<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y5_ctx.pubkey() != &self.y5 {
            msg!("y5_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y5_inv_ctx.pubkey() != &self.y5_inv {
            msg!("y5_inv_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y6_ctx.pubkey() != &self.y6 {
            msg!("y6_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y5 = y5_ctx.take()?;
        let y5_inv = y5_inv_ctx.take()?;
        let mut y6 = y6_ctx.take()?;

        let finished = exp_by_neg_x(
            &mut self.index,
            &mut y6,
            &y5,
            &y5_inv,
        );
        if finished {
            if y3_ctx.pubkey() != &self.y3 {
                msg!("y3_ctx pubkey mismatch");
                return Err(MazeError::UnmatchedAccounts.into());
            }
            if y4_ctx.pubkey() != &self.y4 {
                msg!("y4_ctx pubkey mismatch");
                return Err(MazeError::UnmatchedAccounts.into());
            }

            let y4 = y4_ctx.take()?;
            let mut y3 = y3_ctx.borrow_mut()?;

            y3.conjugate();
            y6.conjugate();

            let y7 = y6 * &y4;
            let y8 = y7 * &(*y3);

            // goto hard part 4
            // replace y3 to y8
            *y3 = y8;
            y5_ctx.erase()?;
            y5_inv_ctx.erase()?;
            y6_ctx.erase()?;
            Ok(FSM::FinalExponentHardPart4(FinalExponentHardPart4 {
                r: self.r,
                y1: self.y1,
                y4: self.y4,
                y8: self.y3,
            }))
        } else {
            Ok(FSM::FinalExponentHardPart3(self))
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart4 {
    pub r: Pubkey,
    pub y1: Pubkey,
    pub y4: Pubkey,
    pub y8: Pubkey,
}

impl FinalExponentHardPart4 {
    pub fn process(
        self,
        pvk: &PreparedVerifyingKey,
        r_ctx: &Context512<Box<Fqk254>>,
        y1_ctx: &Context512<Box<Fqk254>>,
        y4_ctx: &Context512<Box<Fqk254>>,
        y8_ctx: &Context512<Box<Fqk254>>,
    ) -> Result<FSM, ProgramError> {
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y1_ctx.pubkey() != &self.y1 {
            msg!("y1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y4_ctx.pubkey() != &self.y4 {
            msg!("y4_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y8_ctx.pubkey() != &self.y8 {
            msg!("y8_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut r = r_ctx.take()?;
        let y1 = y1_ctx.take()?;
        let y4 = y4_ctx.take()?;
        let mut y8 = y8_ctx.take()?;

        let y9 = y8.mul(y1.as_ref());
        let y10 = y8.mul(y4.as_ref());
        let y11 = y10 * r.as_ref();
        let mut y12 = y9;
        y12.frobenius_map(1);
        let y13 = y12 * &y11;
        y8.frobenius_map(2);
        let y14 = y8.mul(&y13);
        r.conjugate();
        let mut y15 = r.mul(&y9);
        y15.frobenius_map(3);
        let y16 = y15 * &y14;

        // finished
        r_ctx.close()?;
        y1_ctx.close()?;
        y4_ctx.close()?;
        y8_ctx.close()?;
        Ok(FSM::Finished(&y16 == pvk.alpha_g1_beta_g2))
    }
}
