use borsh::BorshDeserialize;
use num_traits::{One, Zero};
use solana_program::{pubkey::Pubkey, account_info::AccountInfo, entrypoint::ProgramResult};

use crate::{verifier::{fsm::*, mock::{prepare_input::PrepareInputs, miller_loop::{MillerLoop, MillerLoopFinalize}, final_exponent::{FinalExponentInverse, FinalExponentMulStep4, FinalExponentMulStep3}}, ProofA, ProofB, ProofC}, params::{bn::{Fr, G1Projective254}, hasher::get_params_bn254_x3_3}, context::Context, vanilla::merkle::{PoseidonMerkleHasher, LeafHasher}, HEIGHT};
use crate::params::bn::{G1Affine254, G2Affine254, Fq, Fq2, G2HomProjective254, Fqk254, Fq6};
use crate::bn::BigInteger256 as BigInteger;

const PROOF_A: ProofA = G1Affine254::new_const(
    Fq::new(BigInteger::new([14715620368662735844, 9563436648438579353, 9817845158629706665, 2420889558595263392])),
    Fq::new(BigInteger::new([8640892419674201321, 14834230856296141528, 4198848546444402927, 1517119377864516134])),
    false,
);

const PROOF_B: ProofB = G2Affine254::new_const(
    Fq2::new_const(
        Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
        Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    ),
    Fq2::new_const(
        Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
        Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    ),
    false,
);

const PROOF_C: ProofC = G1Affine254::new_const(
    Fq::new(BigInteger::new([5823303549099682051, 11298647609364880259, 17539675314511186284, 556302735522023958])),
    Fq::new(BigInteger::new([2083577888616351182, 10916945937534065039, 1520021691683278293, 2748969749429754277])),
    false,
);

const G1_AFFINE_VALUE: G1Affine254 = G1Affine254::new_const(
    Fq::new(BigInteger::new([9497411607956386375, 268351533763702874, 18353951159736685747, 1825167008963268151])),
    Fq::new(BigInteger::new([5487945063526916415, 2251437326952299004, 2432273193309581731, 2595211258581520627])),
    false
);

const G2_AFFINE_VALUE: G2Affine254 = G2Affine254::new_const(
    Fq2::new_const(
        Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
        Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    ),
    Fq2::new_const(
        Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
        Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    ),
    false,
);

const G1_PROJECTIVE_VALUE: G1Projective254 = G1Projective254::new_const(
    Fq::new(BigInteger::new([8702585202244274910, 9214718725403065568, 17690655619678158896, 1222195394398354666])),
    Fq::new(BigInteger::new([3439699351422384141, 18051431940401055444, 13194437363659758174, 2607686238957372954])),
    Fq::new(BigInteger::new([15230403791020821917, 754611498739239741, 7381016538464732716, 1011752739694698287])),
);

const G2_HOMPROJECTIVE_VALUE: G2HomProjective254 = G2HomProjective254 {
    x: Fq2::new_const(
        Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
        Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    ),
    y: Fq2::new_const(
        Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
        Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    ),
    z: Fq2::new_const(
        Fq::new(BigInteger::new([3532409656519188228, 12641690916115292936, 6589099094191591462, 1809238093247962847])),
        Fq::new(BigInteger::new([981268461116076129, 13375361363019721926, 7507922250100515756, 2718044965993879389])),
    ),
};

const FQK254_VALUE: Fqk254 = Fqk254::new_const(
    Fq6::new_const(
        Fq2::new_const(
            Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
            Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
        ),
        Fq2::new_const(
            Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
            Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
        ),
        Fq2::new_const(
            Fq::new(BigInteger::new([4153767206144153341, 4757445080423304776, 7392391047398498789, 735036359864433540])),
            Fq::new(BigInteger::new([786726130547703630, 11930992407036731514, 3203034900645816634, 1625741866668428970])),
        ),
    ),
    Fq6::new_const(
        Fq2::new_const(
            Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
            Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
        ),
        Fq2::new_const(
            Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
            Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
        ),
        Fq2::new_const(
            Fq::new(BigInteger::new([4153767206144153341, 4757445080423304776, 7392391047398498789, 735036359864433540])),
            Fq::new(BigInteger::new([786726130547703630, 11930992407036731514, 3203034900645816634, 1625741866668428970])),
        ),
    ),
);

const PUBLIC_INPUTS: &[Fr; 31] = &[
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
];

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    // let stage = PrepareInputs {
    //     input_index: input[0],
    //     bit_index: input[1] as u16,
    //     public_inputs: PUBLIC_INPUTS.to_vec(),
    //     g_ic: G1_PROJECTIVE_VALUE.clone(),
    //     tmp: G1_PROJECTIVE_VALUE.clone(),
    // };
    // stage.process()

    // let stage = MillerLoop {
    //     index: input[0],
    //     coeff_index: input[1],
    //     f: FQK254_VALUE.clone(),
    //     r: G2_HOMPROJECTIVE_VALUE.clone(),
    //     prepared_input: G1_AFFINE_VALUE.clone(),
    //     proof_a: PROOF_A.clone(),
    //     proof_b: PROOF_B.clone(),
    //     proof_c: PROOF_C.clone(),
    // };
    // stage.process(&proof_type)

    // let stage = MillerLoopFinalize {
    //     coeff_index: input[0],
    //     prepared_input: G1_AFFINE_VALUE.clone(),
    //     proof_a: PROOF_A.clone(),
    //     proof_c: PROOF_C.clone(),
    //     q1: G2_AFFINE_VALUE.clone(),
    //     q2: G2_AFFINE_VALUE.clone(),
    //     r: G2HOMPROJECTIVE_VALUE.clone(),
    //     f: FQK254_VALUE.clone(),
    // };
    // stage.process(&proof_type)

    // let stage = FinalExponentInverse {
    //     f: FQK254_VALUE.clone(),
    // };
    // stage.process()

    // let mut r_inv = FQK254_VALUE.clone();
    // r_inv.conjugate();
    // let stage = ExpByNegX1 {
    //     index: input[0],
    //     r: FQK254_VALUE.clone(),
    //     r_inv,
    //     y0: Fqk254::one(),
    // };
    // stage.process()

    // let mut r_inv = FQK254_VALUE.clone();
    // r_inv.conjugate();
    // let stage = Box::new(FinalExponentMulStep3 {
    //     index: input[0],
    //     y3: Box::new(FQK254_VALUE.clone()),
    //     y4: Box::new(FQK254_VALUE.clone()),
    //     y5: Box::new(FQK254_VALUE.clone()),
    //     y5_inv: Box::new(r_inv),
    //     y6: Box::new(FQK254_VALUE.clone()),
    // });
    // stage.process()

    // let mut stage = Box::new(FinalExponentMulStep4 {
    //     r: Box::new(FQK254_VALUE.clone()),
    //     y1: Box::new(FQK254_VALUE.clone()),
    //     y4: Box::new(FQK254_VALUE.clone()),
    //     y8: Box::new(FQK254_VALUE.clone()),
    // });
    // stage.process()

    // let mut friend_nodes = Box::new(Vec::with_capacity(HEIGHT));
    // (0..HEIGHT).for_each(|i| {
    //     friend_nodes.push((false, PUBLIC_INPUTS[i]));
    // });
    // let leaf = Fr::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900]));

    // let state = vec![
    //     Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    //     Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    //     Fr::zero(),
    // ];

    // let mut hasher = PoseidonMerkleHasher {
    //     friend_nodes,
    //     updating_nodes: Box::new(Vec::new()),
    //     layer: input[0],
    //     round: input[1],
    //     state,
    // };

    let state = vec![
        Fr::zero(),
        Fr::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
        Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
        Fr::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    ];

    let mut hasher = LeafHasher {
        round: input[0],
        state,
        leaf: None,
    };

    hasher.process()?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use solana_program::instruction::Instruction;
    use solana_sdk::{transaction::Transaction, commitment_config::{CommitmentConfig, CommitmentLevel}, signature::Keypair, signer::Signer};
    use solana_client::rpc_client::{RpcClient};

    use crate::id;

    const USER_KEYPAIR: &str = "25VtdefYWzk4fvyfAg3RzSrhwmy4HhgPyYcxetmHRmPrkCsDqSJw8Jav7tWCXToV6e1L7nGxhyEDnWYVsDHUgiZ7";
    const DEVNET: &str = "https://api.devnet.solana.com";

    #[test]
    fn test_instruction() {
        let client = RpcClient::new_with_commitment(DEVNET, CommitmentConfig {
            commitment: CommitmentLevel::Processed,
        });

        let blockhash = client.get_latest_blockhash().unwrap();
        let user = Keypair::from_base58_string(USER_KEYPAIR);

        let transaction = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: id(),
                accounts: vec![],
                data: vec![25, 40],
            }],
            Some(&user.pubkey()),
            &[&user],
            blockhash,
        );

        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }
}