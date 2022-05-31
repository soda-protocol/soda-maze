use std::ops::{MulAssign, Mul};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::One;

use crate::bn::{Field, BnParameters as Bn};
use crate::params::bn::{*, Bn254Parameters as BnParameters};
use crate::params::verify::PreparedVerifyingKey;
use super::program::Program;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
enum ComputeStep {
    Step0,
    Step1,
    Step2,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct ExpByNegX {
    none_zero: bool,
    step: ComputeStep,
    index: u8,
    res: Box<Fqk254>,
}

impl ExpByNegX {
    fn new() -> Self {
        Self {
            none_zero: false,
            step: ComputeStep::Step0,
            index: 0,
            res: Box::new(Fqk254::one()),
        }
    }

    fn cyclotomic_exp(
        &mut self,
        fe: &Fqk254,
        fe_inv: &Fqk254,
        reserve_uints: usize,
    ) -> bool {
        let naf_inv = <BnParameters as Bn>::NAF_INV;

        const MAX_UNITS: usize = 1350000;
        let mut used_units = 0;
        loop {
            match self.step {
                ComputeStep::Step0 => {
                    if self.none_zero {
                        if used_units + 100000 >= MAX_UNITS {
                            break;
                        }
                        self.res.square_in_place();
                        used_units += 100000;
                    }
                    self.step = ComputeStep::Step1;
                }
                ComputeStep::Step1 => {
                    if used_units + 100000 >= MAX_UNITS {
                        break;
                    }
                    let value = naf_inv[self.index as usize];
                    if value > 0 {
                        self.none_zero = true;
                        self.res.mul_assign(fe);
                        used_units += 100000;
                    } else if value < 0 {
                        self.none_zero = true;
                        self.res.mul_assign(fe_inv);
                        used_units += 100000;
                    }
                    self.index += 1;
                    
                    if (self.index as usize) >= naf_inv.len() {
                        self.step = ComputeStep::Step2;
                    } else {
                        self.step = ComputeStep::Step0;
                    }
                }
                ComputeStep::Step2 => {
                    if used_units + reserve_uints >= MAX_UNITS {
                        break;
                    }
                    if !<BnParameters as Bn>::X_IS_NEGATIVE {
                        self.res.conjugate();
                    }
                    // finished
                    return true;
                }
            }
        }
        // next loop
        false
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentEasyPart {
    f: Box<Fqk254>, // Fqk254
}

impl FinalExponentEasyPart {
    pub fn new(f: Box<Fqk254>) -> Self {
        Self { f }
    }

    pub fn process(mut self) -> Program {
        if let Some(mut f2) = self.f.inverse() {
            // f1 = r.conjugate() = f^(p^6)
            self.f.conjugate();

            // f2 = f^(-1);
            // r = f^(p^6 - 1)
            let mut r = self.f.mul(&f2);

            // f2 = f^(p^6 - 1)
            f2 = r;

            // r = f^((p^6 - 1)(p^2))
            r.frobenius_map(2);

            // r = f^((p^6 - 1)(p^2) + (p^6 - 1))
            // r = f^((p^6 - 1)(p^2 + 1))
            r *= &f2;

            // goto hard part 1
            let mut r_inv = r;
            r_inv.conjugate();

            Program::FinalExponentHardPart1(FinalExponentHardPart1 {
                exp_by_neg_x: ExpByNegX::new(),
                r: Box::new(r),
                r_inv: Box::new(r_inv),
            })
        } else {
            // proof failed
            Program::Finish(false)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart1 {
    exp_by_neg_x: ExpByNegX,
    r: Box<Fqk254>,
    r_inv: Box<Fqk254>,
}

impl FinalExponentHardPart1 {
    pub fn process(mut self) -> Program {
        let finished = self.exp_by_neg_x.cyclotomic_exp(
            &self.r,
            &self.r_inv,
            200000,
        );
        if finished {
            let y0 = self.exp_by_neg_x.res;
            // there is some rest compute uint to calculate y1, y2, y3
            let y1 = y0.cyclotomic_square();
            let y2 = y1.cyclotomic_square();
            let y3 = y2 * &y1;
            let mut y3_inv = y3;
            y3_inv.conjugate();

            // goto hard part 2
            Program::FinalExponentHardPart2(FinalExponentHardPart2 {
                exp_by_neg_x: ExpByNegX::new(),
                r: self.r,
                y1: Box::new(y1),
                y3: Box::new(y3),
                y3_inv: Box::new(y3_inv),
            })
        } else {
            // next loop
            Program::FinalExponentHardPart1(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart2 {
    exp_by_neg_x: ExpByNegX,
    r: Box<Fqk254>,
    y1: Box<Fqk254>,
    y3: Box<Fqk254>,
    y3_inv: Box<Fqk254>,
}

impl FinalExponentHardPart2 {
    pub fn process(mut self) -> Program {
        let finished = self.exp_by_neg_x.cyclotomic_exp(
            &self.y3,
            &self.y3_inv,
            100000,
        );
        if finished {
            let y4 = self.exp_by_neg_x.res;
            let y5 = y4.cyclotomic_square();
            let mut y5_inv = y5;
            y5_inv.conjugate();

            // goto hard part 3
            Program::FinalExponentHardPart3(FinalExponentHardPart3 {
                exp_by_neg_x: ExpByNegX::new(),
                r: self.r,
                y1: self.y1,
                y3: self.y3,
                y4,
                y5: Box::new(y5),
                y5_inv: Box::new(y5_inv),
            })
        } else {
            Program::FinalExponentHardPart2(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart3 {
    exp_by_neg_x: ExpByNegX,
    r: Box<Fqk254>,
    y1: Box<Fqk254>,
    y3: Box<Fqk254>,
    y4: Box<Fqk254>,
    y5: Box<Fqk254>,
    y5_inv: Box<Fqk254>,
}

impl FinalExponentHardPart3 {
    pub fn process(mut self) -> Program {
        let finished = self.exp_by_neg_x.cyclotomic_exp(
            &self.y5,
            &self.y5_inv,
            200000,
        );
        if finished {
            let mut y6 = self.exp_by_neg_x.res;
            self.y3.conjugate();
            y6.conjugate();

            let y7 = y6.mul(self.y4.as_ref());
            let y8 = y7 * self.y3.as_ref();

            // goto hard part 4
            Program::FinalExponentHardPart4(FinalExponentHardPart4 {
                r: self.r,
                y1: self.y1,
                y4: self.y4,
                y8: Box::new(y8),
            })
        } else {
            Program::FinalExponentHardPart3(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentHardPart4 {
    r: Box<Fqk254>,
    y1: Box<Fqk254>,
    y4: Box<Fqk254>,
    y8: Box<Fqk254>,
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
