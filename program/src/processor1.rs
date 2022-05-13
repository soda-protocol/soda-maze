use borsh::BorshDeserialize;
use num_traits::{One, Zero};
use solana_program::{pubkey::Pubkey, account_info::AccountInfo, entrypoint::ProgramResult};

use crate::{verifier::{fsm::*, mock::{prepare_input::PrepareInputs, miller_loop::MillerLoop}, ProofA, ProofB, ProofC}, params::{Fr, G1Projective254}, OperationType, context::Context};
use crate::params::{G1Affine254, G2Affine254, Fq, Fq2, G2HomProjective254, Fqk254, Fq6};
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

const G1_PROJECTIVE_VALUE: G1Projective254 = G1Projective254::new_const(
    Fq::new(BigInteger::new([8702585202244274910, 9214718725403065568, 17690655619678158896, 1222195394398354666])),
    Fq::new(BigInteger::new([3439699351422384141, 18051431940401055444, 13194437363659758174, 2607686238957372954])),
    Fq::new(BigInteger::new([15230403791020821917, 754611498739239741, 7381016538464732716, 1011752739694698287])),
);

const G2HOMPROJECTIVE: G2HomProjective254 = G2HomProjective254 {
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

const PUBLIC_INPUTS: &[Fr; 32] = &[
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
    Fr::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
];

const F: &[u8] = &[
    126, 152, 201, 175, 249, 33, 161, 199, 1, 172, 76, 87, 210, 207,
    252, 5, 30, 17, 90, 205, 21, 228, 187, 87, 89, 223, 220, 186, 220, 23, 104, 30, 134,
    34, 52, 42, 1, 58, 128, 66, 234, 38, 103, 89, 145, 224, 178, 180, 170, 155, 214, 79,
    206, 105, 59, 179, 116, 29, 186, 0, 105, 72, 201, 39, 217, 22, 28, 183, 157, 121, 151,
    30, 16, 36, 158, 17, 67, 41, 218, 68, 55, 39, 135, 162, 109, 82, 76, 44, 36, 184, 73,
    6, 81, 85, 0, 25, 250, 62, 154, 131, 104, 82, 77, 183, 59, 130, 101, 173, 44, 107, 172,
    172, 15, 193, 202, 92, 229, 189, 241, 127, 90, 21, 118, 88, 226, 7, 74, 44, 253, 150,
    227, 49, 68, 37, 165, 57, 72, 142, 15, 57, 24, 215, 5, 66, 229, 33, 247, 180, 125, 12,
    151, 102, 132, 59, 183, 198, 172, 95, 51, 10, 78, 63, 208, 90, 63, 3, 235, 10, 122, 160,
    78, 143, 97, 102, 147, 165, 58, 41, 44, 144, 69, 119, 115, 44, 170, 142, 64, 59, 157, 203,
    143, 22, 126, 152, 201, 175, 249, 33, 161, 199, 1, 172, 76, 87, 210, 207, 252, 5, 30, 17,
    90, 205, 21, 228, 187, 87, 89, 223, 220, 186, 220, 23, 104, 30, 134, 34, 52, 42, 1, 58,
    128, 66, 234, 38, 103, 89, 145, 224, 178, 180, 170, 155, 214, 79, 206, 105, 59, 179, 116,
    29, 186, 0, 105, 72, 201, 39, 217, 22, 28, 183, 157, 121, 151, 30, 16, 36, 158, 17, 67, 41,
    218, 68, 55, 39, 135, 162, 109, 82, 76, 44, 36, 184, 73, 6, 81, 85, 0, 25, 250, 62, 154, 131,
    104, 82, 77, 183, 59, 130, 101, 173, 44, 107, 172, 172, 15, 193, 202, 92, 229, 189, 241, 127,
    90, 21, 118, 88, 226, 7, 74, 44, 253, 150, 227, 49, 68, 37, 165, 57, 72, 142, 15, 57, 24, 215,
    5, 66, 229, 33, 247, 180, 125, 12, 151, 102, 132, 59, 183, 198, 172, 95, 51, 10, 78, 63, 208,
    90, 63, 3, 235, 10, 122, 160, 78, 143, 97, 102, 147, 165, 58, 41, 44, 144, 69, 119, 115, 44,
    170, 142, 64, 59, 157, 203, 143, 22,
];

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let proof_type = OperationType::Deposit;

    // let stage = PrepareInputs {
    //     input_index: input[0],
    //     bit_index: input[1],
    //     public_inputs: G1_AFFINE_VALUE.to_vec(),
    //     g_ic: G1_PROJECTIVE_VALUE.clone(),
    //     tmp: G1_PROJECTIVE_VALUE.clone(),
    // };

    // let proof_type = OperationType::Deposit;

    // stage.process(&proof_type)

    let stage = MillerLoop {
        step: input[0],
        index: input[1],
        coeff_index: input[2],
        f: FQK254_VALUE.clone(),
        r: G2HOMPROJECTIVE.clone(),
        prepared_input: G1_AFFINE_VALUE.clone(),
        proof_a: PROOF_A.clone(),
        proof_b: PROOF_B.clone(),
        proof_c: PROOF_C.clone(),
    };

    stage.process(&proof_type)

    // let f_ctx = UpdateContext::new(stage.f, f);
    // let s0_ctx = ReadOnlyContext::new(stage.s0, f.c0.c0);
    // let s1_ctx = ReadOnlyContext::new(stage.s1, f.c0.c1);
    // let s2_ctx = ReadOnlyContext::new(stage.s2, f.c1.c0);
    // let t6_ctx = ReadOnlyContext::new(stage.t6, f.c1.c1);
    // let v0_ctx = ReadOnlyContext::new(stage.v0, PROOF.a.x);
    // let f2_ctx = InitializeContext::new(Pubkey::default());

    // let r_ctx = UpdateContext::new(stage.r, r);
    // let proof_b_ctx = ReadOnlyContext::new(stage.proof_b, PROOF.b);
    // let proof_c_ctx = ReadOnlyContext::new(stage.proof_c, PROOF.c);
    // let q1_ctx = InitializeContext::new(Pubkey::default());
    // let q2_ctx = InitializeContext::new(Pubkey::default());
    
    // stage.process(
    //     &f_ctx,
    //     &s0_ctx,
    //     &s1_ctx,
    //     &s2_ctx,
    //     &t6_ctx,
    //     &v0_ctx,
    //     &f2_ctx,
    // );
    
    // let y14_ctx = ReadOnlyContext::new(ctx.y14, f);
    // let y15_ctx = ReadOnlyContext::new(ctx.y15, f2);
    // // let y15_ctx = InitializeContext::new(Pubkey::default());
    // ctx.process(OperationType::Deposit, &y14_ctx, &y15_ctx);

    // match ctx.step {
    //     0 => {
    //         let f1_ctx = UpdateContext::new(ctx.f1, f);
    //         let f2_ctx = UpdateContext::new(ctx.f2, f2);
    //         ctx.process_0(&f1_ctx, &f2_ctx);
    //     }
    //     1 => {
    //         let f1_ctx = UpdateContext::new(ctx.f1, f);
    //         let f2_ctx = ReadOnlyContext::new(ctx.f2, f2);
    //         let y0_ctx = InitializeContext::new(Pubkey::default());
    //         // let y5_ctx = InitializeContext::new(Pubkey::default());
    //         // let y6_ctx = InitializeContext::new(Pubkey::default());

    //         ctx.process_1(&f1_ctx, &f2_ctx, &y0_ctx);
    //     }
    //     _ => {}
    // }
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
                data: vec![1, 1, 1],
            }],
            Some(&user.pubkey()),
            &[&user],
            blockhash,
        );

        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }
}