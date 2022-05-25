use std::ops::{MulAssign, Mul};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::One;

use crate::bn::{Field, BnParameters as Bn};
use crate::params::bn::{*, Bn254Parameters as BnParameters};
use crate::params::proof::PreparedVerifyingKey;
use super::program::Program;

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

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentEasyPart {
    pub r: Fqk254, // Fqk254
}

impl FinalExponentEasyPart {
    pub fn process(mut self) -> Program {
        if let Some(mut f2) = self.r.inverse() {
            self.r.conjugate();

            // f2 = f^(-1);
            // r = f^(p^6 - 1)
            self.r.mul_assign(&f2);

            // f2 = f^(p^6 - 1)
            f2 = self.r;

            // r = f^((p^6 - 1)(p^2))
            self.r.frobenius_map(2);

            self.r.mul_assign(f2);

            // goto hard part 1
            let mut r_inv = self.r;
            r_inv.conjugate();

            Program::FinalExponentHardPart1(FinalExponentHardPart1 {
                index: 0,
                r: self.r,
                r_inv,
                y0: Fqk254::one(),
            })
        } else {
            // proof failed
            Program::Finish(false)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart1 {
    pub index: u8,
    pub r: Fqk254,
    pub r_inv: Fqk254,
    pub y0: Fqk254,
}

impl FinalExponentHardPart1 {
    pub fn process(mut self) -> Program {
        let finished = exp_by_neg_x(
            &mut self.index,
            &mut self.y0,
            &self.r,
            &self.r_inv,
        );
        if finished {
            // there is some rest compute uint to calculate y1, y2, y3
            let y1 = Box::new(self.y0.cyclotomic_square());
            let y2 = Box::new(y1.cyclotomic_square());
            let y3 = Box::new(y2.mul(y1.as_ref()));
            let mut y3_inv = Box::new(*y3);
            y3_inv.conjugate();

            // goto hard part 2
            Program::FinalExponentHardPart2(FinalExponentHardPart2 {
                index: 0,
                r: Box::new(self.r),
                y1,
                y3,
                y3_inv,
                y4: Box::new(Fqk254::one()),
            })
        } else {
            // next loop
            Program::FinalExponentHardPart1(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart2 {
    pub index: u8,
    pub r: Box<Fqk254>,
    pub y1: Box<Fqk254>,
    pub y3: Box<Fqk254>,
    pub y3_inv: Box<Fqk254>,
    pub y4: Box<Fqk254>,
}

impl FinalExponentHardPart2 {
    pub fn process(mut self) -> Program {
        let finished = exp_by_neg_x(
            &mut self.index,
            &mut self.y4,
            &self.y3,
            &self.y3_inv,
        );
        if finished {
            let y5 = Box::new(self.y4.cyclotomic_square());
            let mut y5_inv = Box::new(*y5);
            y5_inv.conjugate();

            // goto hard part 3
            Program::FinalExponentHardPart3(FinalExponentHardPart3 {
                index: 0,
                r: self.r,
                y1: self.y1,
                y3: self.y3,
                y4: self.y4,
                y5,
                y5_inv,
                y6: Box::new(Fqk254::one()),
            })
        } else {
            Program::FinalExponentHardPart2(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart3 {
    pub index: u8,
    pub r: Box<Fqk254>,
    pub y1: Box<Fqk254>,
    pub y3: Box<Fqk254>,
    pub y4: Box<Fqk254>,
    pub y5: Box<Fqk254>,
    pub y5_inv: Box<Fqk254>,
    pub y6: Box<Fqk254>,
}

impl FinalExponentHardPart3 {
    pub fn process(mut self) -> Program {
        let finished = exp_by_neg_x(
            &mut self.index,
            &mut self.y6,
            &self.y5,
            &self.y5_inv,
        );
        if finished {
            self.y3.conjugate();
            self.y6.conjugate();

            let y7 = self.y6.mul(self.y4.as_ref());
            let y8 = Box::new(y7.mul(self.y3.as_ref()));

            // goto hard part 4
            Program::FinalExponentHardPart4(FinalExponentHardPart4 {
                r: self.r,
                y1: self.y1,
                y4: self.y4,
                y8,
            })
        } else {
            Program::FinalExponentHardPart3(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart4 {
    pub r: Box<Fqk254>,
    pub y1: Box<Fqk254>,
    pub y4: Box<Fqk254>,
    pub y8: Box<Fqk254>,
}

impl FinalExponentHardPart4 {
    #[inline(never)]
    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let y9 = self.y8.mul(self.y1.as_ref());
        let y10 = self.y8.mul(self.y4.as_ref());
        let y11 = y10.mul(self.r.as_ref());
        let mut y12 = y9;
        y12.frobenius_map(1);
        let y13 = y12 * &y11;
        self.y8.frobenius_map(2);
        let y14 = self.y8.mul(&y13);
        self.r.conjugate();
        let mut y15 = self.r.mul(y9);
        y15.frobenius_map(3);
        let y16 = y15 * &y14;

        Program::Finish(&y16 == pvk.alpha_g1_beta_g2)
    }
}
