
use borsh::{BorshSerialize, BorshDeserialize};

use crate::bn::{Fp2, Field};

use super::{BnParameters, ModelParameters, GroupAffine, GroupProjective, TwistType};

pub type G2Affine<P> = GroupAffine<<P as BnParameters>::G2Parameters>;
pub type G2Projective<P> = GroupProjective<<P as BnParameters>::G2Parameters>;

pub(crate) type EllCoeff<F> = (F, F, F);

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct G2HomProjective<P: BnParameters> {
    pub x: Fp2<P::Fp2Params>,
    pub y: Fp2<P::Fp2Params>,
    pub z: Fp2<P::Fp2Params>,
}

pub fn mul_by_char<P: BnParameters>(r: G2Affine<P>) -> G2Affine<P> {
    // multiply by field characteristic

    let mut s = r;
    s.x.frobenius_map(1);
    s.x *= &P::TWIST_MUL_BY_Q_X;
    s.y.frobenius_map(1);
    s.y *= &P::TWIST_MUL_BY_Q_Y;

    s
}

pub fn doubling_step<B: BnParameters>(
    r: &mut G2HomProjective<B>,
    two_inv: &B::Fp,
) -> EllCoeff<Fp2<B::Fp2Params>> {
    // Formula for line function when working with
    // homogeneous projective coordinates.

    let mut a = r.x * &r.y;
    a.mul_assign_by_fp(two_inv);
    let b = r.y.square();
    let c = r.z.square();
    let e = B::G2Parameters::COEFF_B * &(c.double() + &c);
    let f = e.double() + &e;
    let mut g = b + &f;
    g.mul_assign_by_fp(two_inv);
    let h = (r.y + &r.z).square() - &(b + &c);
    let i = e - &b;
    let j = r.x.square();
    let e_square = e.square();

    r.x = a * &(b - &f);
    r.y = g.square() - &(e_square.double() + &e_square);
    r.z = b * &h;
    match B::TWIST_TYPE {
        TwistType::M => (i, j.double() + &j, -h),
        TwistType::D => (-h, j.double() + &j, i),
    }
}

pub fn addition_step<B: BnParameters>(
    r: &mut G2HomProjective<B>,
    q: &G2Affine<B>,
) -> EllCoeff<Fp2<B::Fp2Params>> {
    // Formula for line function when working with
    // homogeneous projective coordinates.
    let theta = r.y - &(q.y * &r.z);
    let lambda = r.x - &(q.x * &r.z);
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * &d;
    let f = r.z * &c;
    let g = r.x * &d;
    let h = e + &f - &g.double();
    r.x = lambda * &h;
    r.y = theta * &(g - &h) - &(e * &r.y);
    r.z *= &e;
    let j = theta * &q.x - &(lambda * &q.y);

    match B::TWIST_TYPE {
        TwistType::M => (j, -theta, lambda),
        TwistType::D => (lambda, -theta, j),
    }
}
