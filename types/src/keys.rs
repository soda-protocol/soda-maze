use borsh::{BorshDeserialize, BorshSerialize};
use soda_maze_program::params::bn::{G1Affine254 as MazeG1Affine, G2Affine254 as MazeG2Affine, Fq as MazeFq, Fq2 as MazeFq2};
use soda_maze_program::bn::BigInteger256 as MazeBigInteger;
use ark_ff::BigInteger256 as BigInteger;
use ark_bn254::{Bn254, G1Affine, G2Affine, Fq, Fq2};
use ark_groth16::{VerifyingKey, ProvingKey};

#[inline]
pub fn fq_to_maze_fq(fq: Fq) -> MazeFq {
    MazeFq::new(MazeBigInteger::new(fq.0.0))
}

#[inline]
pub fn maze_fq_to_fq(fq: MazeFq) -> Fq {
    Fq::new(BigInteger::new(fq.0.0))
}

#[inline]
pub fn fq2_to_maze_fq2(fq2: Fq2) -> MazeFq2 {
    MazeFq2::new(
        fq_to_maze_fq(fq2.c0),
        fq_to_maze_fq(fq2.c1),
    )
}

#[inline]
pub fn maze_fq2_to_fq2(fq2: MazeFq2) -> Fq2 {
    Fq2::new(
        maze_fq_to_fq(fq2.c0),
        maze_fq_to_fq(fq2.c1),
    )
}

#[inline]
pub fn g1_affine_to_maze_g1_affine(g1_affine: G1Affine) -> MazeG1Affine {
    MazeG1Affine::new(
        fq_to_maze_fq(g1_affine.x),
        fq_to_maze_fq(g1_affine.y),
        g1_affine.infinity,
    )
}

#[inline]
pub fn maze_g1_affine_to_g1_affine(g1_affine: MazeG1Affine) -> G1Affine {
    G1Affine::new(
        maze_fq_to_fq(g1_affine.x),
        maze_fq_to_fq(g1_affine.y),
        g1_affine.infinity,
    )
}

#[inline]
pub fn g2_affine_to_maze_g2_affine(g2_affine: G2Affine) -> MazeG2Affine {
    MazeG2Affine::new(
        fq2_to_maze_fq2(g2_affine.x),
        fq2_to_maze_fq2(g2_affine.y),
        g2_affine.infinity,
    )
}

#[inline]
pub fn maze_g2_affine_to_g2_affine(g2_affine: MazeG2Affine) -> G2Affine {
    G2Affine::new(
        maze_fq2_to_fq2(g2_affine.x),
        maze_fq2_to_fq2(g2_affine.y),
        g2_affine.infinity,
    )
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MazeVerifyingKey {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: MazeG1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: MazeG2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: MazeG2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: MazeG2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g1: Vec<MazeG1Affine>,
}

impl From<VerifyingKey<Bn254>> for MazeVerifyingKey {
    fn from(vk: VerifyingKey<Bn254>) -> Self {
        Self {
            alpha_g1: g1_affine_to_maze_g1_affine(vk.alpha_g1),
            beta_g2: g2_affine_to_maze_g2_affine(vk.beta_g2),
            gamma_g2: g2_affine_to_maze_g2_affine(vk.gamma_g2),
            delta_g2: g2_affine_to_maze_g2_affine(vk.delta_g2),
            gamma_abc_g1: vk.gamma_abc_g1.into_iter().map(g1_affine_to_maze_g1_affine).collect(),
        }
    }
}

impl Into<VerifyingKey<Bn254>> for MazeVerifyingKey {
    fn into(self) -> VerifyingKey<Bn254> {
        VerifyingKey {
            alpha_g1: maze_g1_affine_to_g1_affine(self.alpha_g1),
            beta_g2: maze_g2_affine_to_g2_affine(self.beta_g2),
            gamma_g2: maze_g2_affine_to_g2_affine(self.gamma_g2),
            delta_g2: maze_g2_affine_to_g2_affine(self.delta_g2),
            gamma_abc_g1: self.gamma_abc_g1.into_iter().map(maze_g1_affine_to_g1_affine).collect(),
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MazeProvingKey {
    /// The underlying verification key.
    pub vk: MazeVerifyingKey,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: MazeG1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: MazeG1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<MazeG1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<MazeG1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<MazeG2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<MazeG1Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<MazeG1Affine>,
}

impl From<ProvingKey<Bn254>> for MazeProvingKey {
    fn from(pk: ProvingKey<Bn254>) -> Self {
        Self {
            vk: MazeVerifyingKey::from(pk.vk),
            beta_g1: g1_affine_to_maze_g1_affine(pk.beta_g1),
            delta_g1: g1_affine_to_maze_g1_affine(pk.delta_g1),
            a_query: pk.a_query.into_iter().map(g1_affine_to_maze_g1_affine).collect(),
            b_g1_query: pk.b_g1_query.into_iter().map(g1_affine_to_maze_g1_affine).collect(),
            b_g2_query: pk.b_g2_query.into_iter().map(g2_affine_to_maze_g2_affine).collect(),
            h_query: pk.h_query.into_iter().map(g1_affine_to_maze_g1_affine).collect(),
            l_query: pk.l_query.into_iter().map(g1_affine_to_maze_g1_affine).collect(),
        }
    }
}

impl Into<ProvingKey<Bn254>> for MazeProvingKey {
    fn into(self) -> ProvingKey<Bn254> {
        ProvingKey {
            vk: self.vk.into(),
            beta_g1: maze_g1_affine_to_g1_affine(self.beta_g1),
            delta_g1: maze_g1_affine_to_g1_affine(self.delta_g1),
            a_query: self.a_query.into_iter().map(maze_g1_affine_to_g1_affine).collect(),
            b_g1_query: self.b_g1_query.into_iter().map(maze_g1_affine_to_g1_affine).collect(),
            b_g2_query: self.b_g2_query.into_iter().map(maze_g2_affine_to_g2_affine).collect(),
            h_query: self.h_query.into_iter().map(maze_g1_affine_to_g1_affine).collect(),
            l_query: self.l_query.into_iter().map(maze_g1_affine_to_g1_affine).collect(),
        }
    }
}
