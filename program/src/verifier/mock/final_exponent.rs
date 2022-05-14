use std::ops::MulAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::{bn::BnParameters as Bn, OperationType, error::MazeError};
use crate::bn::{Field, Fp12ParamsWrapper, QuadExtParameters, Fp6ParamsWrapper, CubicExtParameters, Fp2ParamsWrapper};
use crate::params::{*, Bn254Parameters as BnParameters};
use crate::context::Context;

macro_rules! impl_exp_by_negx_struct {
    ($name:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey, // Fqk254
        }
    };
    ($name:ident, $field0:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident, $field4:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
            pub $field4: Pubkey,
        }
    };
}

macro_rules! impl_exp_by_neg_x {
    ($name:ident) => {
        impl $name {
            #[inline]
            fn process_inner(
                mut self,
            ) -> (Self, bool) {
                let naf = <BnParameters as Bn>::NAF;

                const MAX_LOOP: usize = 4;
                for _ in 0..MAX_LOOP {
                    self.y0.square_in_place();
        
                    let value = naf[self.index as usize];
                    self.index += 1;

                    self.y0.mul_assign(&self.r);
                    // if value > 0 {
                    //     self.y0.mul_assign(&self.r);
                    // } else {
                    //     self.y0.mul_assign(&self.r_inv);
                    // }
        
                    if (self.index as usize) >= naf.len() {
                        if !<BnParameters as Bn>::X_IS_NEGATIVE {
                            self.y0.conjugate();
                        }
                        // finished
                        return (self, true);
                    }
                }
                // next loop
                (self, false)
            }
        }
    };
}

macro_rules! impl_exp_by_neg_xx {
    ($name:ident) => {
        impl $name {
            #[inline]
            fn process_1_inner(
                mut self,
                f_ctx: &Context<Fqk254>,
                res_ctx: &Context<Fqk254>,
            ) -> Result<(Self, bool), ProgramError> {
                let mut res = res_ctx.borrow_mut()?;
                let f = f_ctx.take()?;

                let naf = <BnParameters as Bn>::NAF;
                let value = naf[self.index as usize];
                self.index += 1;

                if value != 0 {
                    self.step = 0;
        
                    if value > 0 {
                        res.mul_assign(f);
                    } else {
                        let mut f_inv = f;
                        f_inv.conjugate();
                        res.mul_assign(f_inv);
                    }
                }

                if (self.index as usize) < naf.len() {
                    Ok((self, true))
                } else {
                    if !<BnParameters as Bn>::X_IS_NEGATIVE {
                        res.conjugate();
                    }
        
                    Ok((self, false))
                }
            }
        }
    };
}

macro_rules! impl_fqk_mul_struct {
    ($name:ident, $field0:ident, $field1:ident, $field2:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident, $field4: ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
            pub $field4: Pubkey,
        }
    };
}

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

impl_exp_by_negx_struct!(FinalExponentMul1, y0);
impl_exp_by_neg_x!(ExpByNegX);

pub struct ExpByNegX {
    pub index: u8,
    pub r: Fqk254,
    pub r_inv: Fqk254,
    pub y0: Fqk254,
}

impl ExpByNegX {
    pub fn process(self) -> Result<(), ProgramError> {
        let (s, finished) = self.process_inner();

        if finished {
            // there is some rest compute uint to calculate y1, y2, y3
            let y1 = s.y0.cyclotomic_square();
            let y2 = y1.cyclotomic_square();
            let _y3 = y2 * y1;
            // finished
            Ok(())
        } else {
            // next loop
            Ok(())
        }
    }
}

// #[derive(Clone, BorshSerialize, BorshDeserialize)]
// pub struct FinalExponentMul2 {
//     pub r: Fqk254, // Fqk254
//     pub y0: Fqk254, // Fqk254
// }

// impl FinalExponentMul2 {
//     pub fn process(
//         self,
//     ) -> Result<(), ProgramError> {
//         let y1 = self.y0.cyclotomic_square();
//         let y2 = y1.cyclotomic_square();
//         let y3 = y2 * y1;

//         Ok(())
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul3, r, y1, y2);

// impl FinalExponentMul3 {
//     pub fn process(
//         self,
//         y1_ctx: &Context<Fqk254>,
//         y2_ctx: &Context<Fqk254>,
//         y3_ctx: &Context<Fqk254>,
//         y4_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y1_ctx.pubkey() != &self.y1 {
//             msg!("y1_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y2_ctx.pubkey() != &self.y2 {
//             msg!("y2_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y1 = y1_ctx.take()?;
//         let y2 = y2_ctx.take()?;

//         let y3 = y2 * y1;

//         y2_ctx.erase()?;
//         y3_ctx.fill(y3)?;
//         y4_ctx.fill(Fqk254::one())?;
//         Ok(FSM::FinalExponentMul4(FinalExponentMul4 {
//             step: 1,
//             index: 0,
//             r: self.r,
//             y1: self.y1,
//             y3: *y3_ctx.pubkey(),
//             y4: *y4_ctx.pubkey(),
//         }))
//     }
// }

// impl_exp_by_negx_struct!(FinalExponentMul4, y1, y3, y4);
// impl_exp_by_neg_x!(FinalExponentMul4);

// impl FinalExponentMul4 {
//     pub fn process_0(
//         mut self,
//         y4_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y4_ctx.pubkey() != &self.y4 {
//             msg!("y4_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut res = y4_ctx.borrow_mut()?;

//         res.square_in_place();

//         self.step += 1;
//         Ok(FSM::FinalExponentMul4(self))
//     }

//     pub fn process_1(
//         self,
//         y3_ctx: &Context<Fqk254>,
//         y4_ctx: &Context<Fqk254>,
//         y5_ctx: &Context<Fqk254>,
//         y6_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y3_ctx.pubkey() != &self.y3 {
//             msg!("y3_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y4_ctx.pubkey() != &self.y4 {
//             msg!("y4_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let (s, is_self) = self.process_1_inner(y3_ctx, y4_ctx)?;
//         if is_self {
//             Ok(FSM::FinalExponentMul4(s))
//         } else {
//             let y5 = y4_ctx.borrow_mut()?.cyclotomic_square();

//             y5_ctx.fill(y5)?;
//             y6_ctx.fill(Fqk254::one())?;
//             Ok(FSM::FinalExponentMul5(FinalExponentMul5 {
//                 step: 1,
//                 index: 0,
//                 r: s.r,
//                 y1: s.y1,
//                 y3: s.y3,
//                 y4: s.y4,
//                 y5: *y5_ctx.pubkey(),
//                 y6: *y6_ctx.pubkey(),
//             }))
//         }
//     }
// }

// impl_exp_by_negx_struct!(FinalExponentMul5, y1, y3, y4, y5, y6);
// impl_exp_by_neg_x!(FinalExponentMul5);

// impl FinalExponentMul5 {
//     pub fn process_0(
//         mut self,
//         y6_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y6_ctx.pubkey() != &self.y4 {
//             msg!("y6_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut res = y6_ctx.borrow_mut()?;

//         res.square_in_place();

//         self.step += 1;
//         Ok(FSM::FinalExponentMul5(self))
//     }

//     pub fn process_1(
//         self,
//         y3_ctx: &Context<Fqk254>,
//         y5_ctx: &Context<Fqk254>,
//         y6_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y3_ctx.pubkey() != &self.y3 {
//             msg!("y3_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y5_ctx.pubkey() != &self.y5 {
//             msg!("y5_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y6_ctx.pubkey() != &self.y6 {
//             msg!("y6_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let (s, is_self) = self.process_1_inner(y5_ctx, y6_ctx)?;
//         if is_self {
//             Ok(FSM::FinalExponentMul5(s))
//         } else {
//             y3_ctx.borrow_mut()?.conjugate();
//             y6_ctx.borrow_mut()?.conjugate();
            
//             y5_ctx.erase()?;
//             Ok(FSM::FinalExponentMul6(FinalExponentMul6 {
//                 r: s.r,
//                 y1: s.y1,
//                 y3: s.y3,
//                 y4: s.y4,
//                 y6: s.y6,
//             }))
//         }
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul6, r, y1, y3, y4, y6);

// impl FinalExponentMul6 {
//     pub fn process(
//         self,
//         y4_ctx: &Context<Fqk254>,
//         y6_ctx: &Context<Fqk254>,
//         y7_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y4_ctx.pubkey() != &self.y4 {
//             msg!("y4_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y6_ctx.pubkey() != &self.y6 {
//             msg!("y6_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y4 = y4_ctx.take()?;
//         let y6 = y6_ctx.take()?;

//         let y7 = y6 * y4;

//         y6_ctx.erase()?;
//         y7_ctx.fill(y7)?;
//         Ok(FSM::FinalExponentMul7(FinalExponentMul7 {
//             r: self.r,
//             y1: self.y1,
//             y3: self.y3,
//             y4: self.y4,
//             y7: *y7_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul7, r, y1, y3, y4, y7);

// impl FinalExponentMul7 {
//     pub fn process(
//         self,
//         y3_ctx: &Context<Fqk254>,
//         y7_ctx: &Context<Fqk254>,
//         y8_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y3_ctx.pubkey() != &self.y3 {
//             msg!("y3_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y7_ctx.pubkey() != &self.y7 {
//             msg!("y7_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y3 = y3_ctx.take()?;
//         let y7 = y7_ctx.take()?;

//         let y8 = y7 * y3;

//         y3_ctx.erase()?;
//         y7_ctx.erase()?;
//         y8_ctx.fill(y8)?;
//         Ok(FSM::FinalExponentMul8(FinalExponentMul8 {
//             r: self.r,
//             y1: self.y1,
//             y4: self.y4,
//             y8: *y8_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul8, r, y1, y4, y8);

// impl FinalExponentMul8 {
//     pub fn process(
//         self,
//         y1_ctx: &Context<Fqk254>,
//         y8_ctx: &Context<Fqk254>,
//         y9_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y1_ctx.pubkey() != &self.y1 {
//             msg!("y1_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y8_ctx.pubkey() != &self.y8 {
//             msg!("y8_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y1 = y1_ctx.take()?;
//         let y8 = y8_ctx.take()?;

//         let y9 = y8 * y1;

//         y1_ctx.erase()?;
//         y9_ctx.fill(y9)?;
//         Ok(FSM::FinalExponentMul9(FinalExponentMul9 {
//             r: self.r,
//             y4: self.y4,
//             y8: self.y8,
//             y9: *y9_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul9, r, y4, y8, y9);

// impl FinalExponentMul9 {
//     pub fn process(
//         self,
//         y4_ctx: &Context<Fqk254>,
//         y8_ctx: &Context<Fqk254>,
//         y10_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if y4_ctx.pubkey() != &self.y4 {
//             msg!("y4_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y8_ctx.pubkey() != &self.y8 {
//             msg!("y8_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let y4 = y4_ctx.take()?;
//         let y8 = y8_ctx.take()?;

//         let y10 = y8 * y4;

//         y4_ctx.close()?;
//         y10_ctx.fill(y10)?;
//         Ok(FSM::FinalExponentMul10(FinalExponentMul10 {
//             r: self.r,
//             y8: self.y8,
//             y9: self.y9,
//             y10: *y10_ctx.pubkey(),
//         }))
//     }
// }

// impl_fqk_mul_struct!(FinalExponentMul10, r, y8, y9, y10);

// impl FinalExponentMul10 {
//     pub fn process(
//         self,
//         r_ctx: &Context<Fqk254>,
//         y10_ctx: &Context<Fqk254>,
//         y11_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if r_ctx.pubkey() != &self.r {
//             msg!("r_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if y10_ctx.pubkey() != &self.y10 {
//             msg!("y10_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let r = r_ctx.take()?;
//         let y10 = y10_ctx.take()?;

//         let y11 = y10 * r;

//         y10_ctx.erase()?;
//         y11_ctx.fill(y11)?;
//         Ok(FSM::FinalExponentMul11(FinalExponentMul11 {
//             r: self.r,
//             y8: self.y8,
//             y9: self.y9,
//             y11: *y11_ctx.pubkey(),
//         }))
//     }
// }

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