use std::ops::{MulAssign, Mul};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::{bn::BnParameters as Bn, OperationType, error::MazeError};
use crate::bn::{Field, Fp12ParamsWrapper, QuadExtParameters, Fp6ParamsWrapper, CubicExtParameters, Fp2ParamsWrapper};
use crate::params::{*, Bn254Parameters as BnParameters};
use crate::context::Context;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentInverse {
    pub f: Fqk254, // Fqk254
}

impl FinalExponentInverse {
    pub fn process(
        self,
    ) -> Result<(), ProgramError> {
        let mut f1 = self.f.clone();
        f1.conjugate();

        if let Some(mut f2) = self.f.inverse() {
            // f2 = f^(-1);
            // r = f^(p^6 - 1)
            f1.mul_assign(&f2);

            // f2 = f^(p^6 - 1)
            f2 = f1;

            // r = f^((p^6 - 1)(p^2))
            f1.frobenius_map(2);

            f1.mul_assign(f2);

            // goto exp by neg x
            Ok(())
        } else {
            // proof failed
            Ok(())
        }
        // let mut r_inv = f1.clone();
        // r_inv.conjugate();
        // let y0 = Fqk254::one();
    }
}

#[inline]
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

pub struct ExpByNegX1 {
    pub index: u8,
    pub r: Fqk254,
    pub r_inv: Fqk254,
    pub y0: Fqk254,
}

impl ExpByNegX1 {
    pub fn process(mut self) -> Result<(), ProgramError> {
        let finished = exp_by_neg_x(
            &mut self.index,
            &mut self.y0,
            &self.r,
            &self.r_inv,
        );
        if finished {
            // there is some rest compute uint to calculate y1, y2, y3
            let y1 = self.y0.cyclotomic_square();
            let y2 = y1.cyclotomic_square();
            let mut y3 = y2 * y1;
            y3.conjugate();
            let _y4 = Fqk254::one();

            // finished
            Ok(())
        } else {
            // next loop
            Ok(())
        }
    }
}

pub struct ExpByNegX2 {
    pub index: u8,
    pub y3: Fqk254,
    pub y3_inv: Fqk254,
    pub y4: Fqk254,
}

impl ExpByNegX2 {
    pub fn process(mut self) -> Result<(), ProgramError> {
        let finished = exp_by_neg_x(
            &mut self.index,
            &mut self.y4,
            &self.y3,
            &self.y3_inv,
        );
        if finished {
            let _y5 = self.y4.cyclotomic_square();
            let _y6 = Fqk254::one();

            Ok(())
        } else {
            Ok(())
        }
    }
}

pub struct FinalExponentMulStep3 {
    pub index: u8,
    pub y3: Fqk254,
    pub y5: Fqk254,
    pub y5_inv: Fqk254,
    pub y6: Fqk254,
}

impl FinalExponentMulStep3 {
    pub fn process(mut self) -> Result<(), ProgramError> {
        let finished = exp_by_neg_x(
            &mut self.index,
            &mut self.y6,
            &self.y5,
            &self.y5_inv,
        );
        if finished {
            self.y3.conjugate();
            self.y6.conjugate();

            Ok(())
        } else {
            Ok(())
        }
    }
}

pub struct FinalExponentMulStep4 {
    pub r: Box<Fqk254>,
    pub y1: Box<Fqk254>,
    pub y3: Box<Fqk254>,
    pub y4: Box<Fqk254>,
    pub y6: Box<Fqk254>,
}

impl FinalExponentMulStep4 {
    #[inline(never)]
    pub fn process(&mut self) -> Result<(), ProgramError> {
        let y7 = self.y6.mul(self.y4.as_ref());
        let mut y8 = y7.mul(self.y3.as_ref());
        let y9 = y8.mul(self.y1.as_ref());
        let y10 = y8.mul(self.y4.as_ref());
        let y11 = y10.mul(self.r.as_ref());
        let mut y12 = y9;
        y12.frobenius_map(1);
        let y13 = y12 * &y11;
        y8.frobenius_map(2);
        let y14 = y8 * &y13;
        self.r.conjugate();
        let mut y15 = self.r.mul(y9);
        y15.frobenius_map(3);
        let _y16 = y15 * &y14;

        Ok(())
    }
}

// impl_fqk_mul_struct!(FinalExponentMul11, r, y8, y9, y11);

// impl FinalExponentMul11 {
//     pub fn process(
//         self,
//         y9_ctx: &Context<Fqk254>,
//         y11_ctx: &Context<Fqk254>,
//         y13_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y9_ctx.pubkey() != &self.y9 {
//             msg!("y9_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y11_ctx.pubkey() != &self.y11 {
//             msg!("y11_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y11 = y11_ctx.take()?;
//         let mut y12 = y9_ctx.take()?;
        
//         y12.frobenius_map(1);
//         let y13 = y12 * y11;

//         y11_ctx.erase()?;
//         y13_ctx.fill(y13)?;
//         Ok(FSM::FinalExponentMul12(FinalExponentMul12 {
//             r: self.r,
//             y8: self.y8,
//             y9: self.y9,
//             y13: *y13_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul12, r, y8, y9, y13);

// impl FinalExponentMul12 {
//     pub fn process(
//         self,
//         y8_ctx: &Context<Fqk254>,
//         y13_ctx: &Context<Fqk254>,
//         y14_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y8_ctx.pubkey() != &self.y8 {
//             msg!("y8_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y13_ctx.pubkey() != &self.y13 {
//             msg!("y13_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut y8 = y8_ctx.take()?;
//         let y13 = y13_ctx.take()?;

//         y8.frobenius_map(2);
//         let y14 = y8 * y13;

//         y8_ctx.close()?;
//         y13_ctx.erase()?;
//         y14_ctx.fill(y14)?;
//         Ok(FSM::FinalExponentMul13(FinalExponentMul13 {
//             r: self.r,
//             y9: self.y9,
//             y14: *y14_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul13, r, y9, y14);

// impl FinalExponentMul13 {
//     pub fn process(
//         self,
//         r_ctx: &Context<Fqk254>,
//         y9_ctx: &Context<Fqk254>,
//         y15_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if r_ctx.pubkey() != &self.r {
//             msg!("r_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y9_ctx.pubkey() != &self.y9 {
//             msg!("y9_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut r = r_ctx.take()?;
//         let y9 = y9_ctx.take()?;

//         r.conjugate();
//         let y15 = r * y9;

//         r_ctx.close()?;
//         y9_ctx.close()?;
//         y15_ctx.fill(y15)?;
//         Ok(FSM::FinalExponentFinalize(FinalExponentFinalize {
//             r: self.r,
//             y14: self.y14,
//             y15: *y15_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentFinalize, r, y14, y15);

// impl FinalExponentFinalize {
//     pub fn process(
//         self,
//         proof_type: &OperationType,
//         y14_ctx: &Context<Fqk254>,
//         y15_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y14_ctx.pubkey() != &self.y14 {
//             msg!("y14_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y15_ctx.pubkey() != &self.y15 {
//             msg!("y15_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y14 = y14_ctx.take()?;
//         let mut y15 = y15_ctx.take()?;

//         y15.frobenius_map(3);
//         let y16 = y15 * y14;

//         y14_ctx.close()?;
//         y15_ctx.close()?;
//         let pvk = proof_type.verifying_key();
//         Ok(FSM::Finished(&y16 == pvk.alpha_g1_beta_g2))
//     }
// }