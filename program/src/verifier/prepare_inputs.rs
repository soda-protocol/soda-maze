use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;

use crate::bn::{BigInteger256 as BigInteger, BitIteratorBE};
use crate::params::bn::{G1Projective254, G1Affine254};
use crate::params::verify::PreparedVerifyingKey;
use crate::verifier::Proof;
use super::program::Program;
use super::miller_loop::MillerLoop;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    bit_index: u16,
    public_inputs: Box<Vec<BigInteger>>,
    g_ic: Box<G1Projective254>,
    tmp: Box<G1Projective254>,
    proof: Box<Proof>,
}

impl PrepareInputs {
    pub fn new(pvk: &PreparedVerifyingKey, public_inputs: Box<Vec<BigInteger>>, proof: Box<Proof>) -> Self {
        Self {
            input_index: 0,
            bit_index: 0,
            public_inputs,
            g_ic: Box::new(*pvk.g_ic_init),
            tmp: Box::new(G1Projective254::zero()),
            proof,
        }
    }

    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let mut public_input = self.public_inputs[self.input_index as usize];
        let mut bits_iter = BitIteratorBE::without_leading_zeros(public_input)
            .skip(self.bit_index as usize);

        const MAX_UINTS: usize = 1360000;
        let mut used_units = 0;
        loop {
            if let Some(bit) = bits_iter.next() {
                self.tmp.double_in_place();
                used_units += 13000;
                if bit {
                    self.tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                    used_units += 21000;
                }
                self.bit_index += 1;
            } else {
                self.g_ic.add_assign(&self.tmp);
                self.input_index += 1;
                used_units += 13000;

                if self.input_index as usize >= self.public_inputs.len() {
                    let prepared_input = G1Affine254::from(*self.g_ic);
                    return Program::MillerLoop(MillerLoop::new(Box::new(prepared_input), self.proof));
                } else {
                    self.bit_index = 0;
                    self.tmp = Box::new(G1Projective254::zero());

                    public_input = self.public_inputs[self.input_index as usize];
                    bits_iter = BitIteratorBE::without_leading_zeros(public_input).skip(0);
                    used_units += 1000;
                }
            }

            if used_units >= MAX_UINTS {
                break;
            }
        }

        Program::PrepareInputs(self)
    }
}

#[cfg(test)]
mod tests {
    use solana_program::pubkey::Pubkey;

    use crate::params::{bn::{G1Affine254, G2Affine254, G1Projective254}, verify::{PreparedVerifyingKey, ProofType}};
    use crate::{params::bn::{Fq, Fq2}, verifier::{Proof, program::Program}};
    use crate::bn::BigInteger256 as BigInteger;
    use crate::core::{VanillaData, deposit::DepositVanillaData};

    const PVK: &PreparedVerifyingKey = ProofType::Deposit.pvk();

    fn get_deposit_verifying_program() -> (Box<Vec<BigInteger>>, Program) {
        let deposit_amount = 100;
        let leaf_index = 0;
        let leaf = BigInteger::new([3542236639209175990, 16910505828447755939, 15985469206914547775, 2949265978052157896]);
        let prev_root = BigInteger::new([15731961227988085298, 1152253436246937880, 10067708109528847282, 2453386543983348226]);
        let updating_nodes = vec![
            BigInteger::new([15532250321868931685, 772932733899588440, 12868310124187153130, 438462560823777455]),
            BigInteger::new([11847340026267790185, 10820144684227279182, 3897917803026447095, 1211025166583652450]),
            BigInteger::new([13871474726796312921, 2045639111475989628, 12481963867359042585, 1654720166251331239]),
            BigInteger::new([7522360132978259117, 14771120575066486403, 10596590224358807127, 3157651300534472347]),
            BigInteger::new([7507876248263243529, 5715413346482742507, 12957876777088811968, 2510703228340708577]),
            BigInteger::new([133315792692492865, 15293309774567381972, 14334463947285336696, 1723563495644442414]),
            BigInteger::new([1928085400153529539, 1698449431575688062, 5445397574952319768, 1143000330999000263]),
            BigInteger::new([12979161123112243949, 10519306232363901245, 7410924906293113533, 441442420902499555]),
            BigInteger::new([13623320368263364327, 8828774309128316872, 10934886998453446221, 1177057120107296621]),
            BigInteger::new([17522708475201759282, 412032152261673971, 16434968819987934970, 57110405472686226]),
            BigInteger::new([12273231996521786577, 8864960514473101270, 7255808797058973254, 2024561412595145600]),
            BigInteger::new([8041353708081998109, 4408055454208809679, 7467631578407169415, 174481746946129969]),
            BigInteger::new([15759627427490212038, 2342726286939514839, 3188233064319415482, 206053989429984523]),
            BigInteger::new([3862288674501080527, 4414699166683294138, 7867804525257430666, 2497191292622968527]),
            BigInteger::new([18111671256300872493, 9560658010795795413, 11128501249746692797, 3218688909781081982]),
            BigInteger::new([11621730998744754762, 6316575933548212603, 1290755564488270042, 1649482600435840483]),
            BigInteger::new([14372000062670910161, 12363655746768868914, 2239893263450009019, 1148238205359365334]),
            BigInteger::new([7047592107069037456, 15046063210205594002, 8658295702548938809, 1627711097087034838]),
            BigInteger::new([778320942488412995, 1973661381734835396, 12584060032923075028, 1668508506270919639]),
            BigInteger::new([15541703251344978826, 10978453290527186359, 10233791787923230785, 179983619992156155]),
            BigInteger::new([1403833390002913823, 14192997889125093942, 2057500286915250275, 2091709604487301396]),
        ];
        let commitment = vec![
            BigInteger::new([16722997434160713798, 11403452488286244511, 18318868681545149281, 21754274364414989]),
            BigInteger::new([11611806235245355479, 5424040539426569871, 7513338721988059883, 35367902979566062]),
            BigInteger::new([220681830571333505, 13034651635228622148, 14955611269817919911, 36862314553737607]),
            BigInteger::new([3646867184726427713, 5600318523685585750, 7642679702590823310, 40280276519090518]),
            BigInteger::new([2053746354640544201, 5271193340300995188, 15781609477155030499, 33238881268910210]),
            BigInteger::new([4886134654328406654, 12634074070563300144, 17891432476597062324, 71955938858561633]),
            BigInteger::new([2559727239711704880, 6392075204380784424, 12055047205046880238, 9598153984261654]),
            BigInteger::new([8099615302498656019, 17681822004623220591, 4278720356088691622, 20549192218165015]),
            BigInteger::new([1479306651680053975, 16970454663387229825, 1219617339513386804, 9996197586358739]),
            BigInteger::new([12513940028146829811, 16771911556576546385, 12887667978113417874, 36027991776611425]),
            BigInteger::new([18410058132998784786, 13401630289159459721, 14914310748430415085, 18313255534332353]),
            BigInteger::new([5826441929749290616, 11335202586746830014, 10903293645248433631, 36117579937827459]),
        ];
        let a = G1Affine254::new_const(
            Fq::new(BigInteger::new([3750417186220724512, 3978078781434640716, 15163791108043952614, 2453596515077279990])),
            Fq::new(BigInteger::new([5354853820532153524, 8883007908664368954, 470161243035897903, 1359038641147964963])),
            false
        );
        let b = G2Affine254::new_const(
            Fq2::new_const(
                Fq::new(BigInteger::new([12118601996045181130, 896706683785346415, 4709517509465227924, 1819241630933245065])),
                Fq::new(BigInteger::new([16349181015735361827, 4843110160248729036, 17714835083434401718, 2754712195795085383])),
            ),
            Fq2::new_const(
                Fq::new(BigInteger::new([3167422245359854874, 15117403505212976980, 14561078193533486427, 992932037830603307])),
                Fq::new(BigInteger::new([10453996433908490996, 4951364747808814581, 1077088453432665796, 3244165116791247838])),
            ),
            false
        );
        let c = G1Affine254::new_const(
            Fq::new(BigInteger::new([6745960168647187300, 7304089792560402287, 5467772039812183716, 1531927553351135845])),
            Fq::new(BigInteger::new([2914263778726088111, 9472631376659388131, 16215105594981982902, 939471742250680668])),
            false
        );
        let proof = Proof { a, b, c };

        let mut deposit_data = DepositVanillaData::new(
            deposit_amount,
            leaf_index,
            leaf,
            prev_root,
            Box::new(updating_nodes),
        );
        deposit_data.fill_commitment(Box::new(commitment)).unwrap();

        let public_inputs = deposit_data.clone().to_public_inputs();
        let verifier = deposit_data.to_verifier(Pubkey::default(), Box::new(proof));

        (public_inputs, verifier.program)
    }

    fn transform_biginteger(i: BigInteger) -> ark_ff::BigInteger256 {
        use ark_ff::BigInteger256;

        BigInteger256::new(i.0)
    }

    fn transform_g1_affine(g: &G1Affine254) -> ark_bn254::G1Affine {
        use ark_ff::BigInteger256;
        use ark_bn254::{Fq, G1Affine};

        G1Affine::new(
            Fq::new(BigInteger256::new(g.x.0.0)),
            Fq::new(BigInteger256::new(g.y.0.0)),
            g.infinity,
        )
    }

    fn transform_g1_projective(g: &G1Projective254) -> ark_bn254::G1Projective {
        use ark_ff::BigInteger256;
        use ark_bn254::{Fq, G1Projective};

        G1Projective::new(
            Fq::new(BigInteger256::new(g.x.0.0)),
            Fq::new(BigInteger256::new(g.y.0.0)),
            Fq::new(BigInteger256::new(g.z.0.0)),
        )
    }

    #[test]
    fn test_prepare_inputs() {
        let (public_inputs, mut program) = get_deposit_verifying_program();

        loop {
            program = program.process(PVK);
            if let Program::MillerLoop(_ml) = &program {
                // println!("prepared_input_x {:?}", &ml.prepared_input.x.0.0);
                // println!("prepared_input_y {:?}", &ml.prepared_input.y.0.0);
                break;
            }
        }

        {
            use std::ops::AddAssign;
            use ark_ec::{AffineCurve, ProjectiveCurve};

            let mut g_ic = transform_g1_projective(PVK.g_ic_init);
            public_inputs.into_iter().zip(PVK.gamma_abc_g1).for_each(|(i, b)| {
                let i = transform_biginteger(i);
                let b = transform_g1_affine(b);
                g_ic.add_assign(&b.mul(i));
            });

            let public_input = g_ic.into_affine();

            println!("public_input_x {:?}", public_input.x.0.0);
            println!("public_input_y {:?}", public_input.y.0.0);
        }
    }
}