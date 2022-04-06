use borsh::BorshDeserialize;
use num_traits::{One, Zero};
use solana_program::{pubkey::Pubkey, account_info::AccountInfo, entrypoint::ProgramResult};

use crate::{verifier::{fsm::*, context::{UpdateContext, ReadOnlyContext, InitializeContext}}, params::{Fr, G1Projective254}, OperationType};
use crate::params::{G1Affine254, G2Affine254, Fq, Fq2, G2HomProjective254, Fqk254, Fq6};
use crate::bn::BigInteger256 as BigInteger;

const PROOF: Proof = Proof {
    a: G1Affine254::new_const(
        Fq::new(BigInteger::new([14715620368662735844, 9563436648438579353, 9817845158629706665, 2420889558595263392])),
        Fq::new(BigInteger::new([8640892419674201321, 14834230856296141528, 4198848546444402927, 1517119377864516134])),
        false,
    ),
    b: G2Affine254::new_const(
        Fq2::new_const(
            Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
            Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
        ),
        Fq2::new_const(
            Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
            Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
        ),
        false,
    ),
    c: G1Affine254::new_const(
        Fq::new(BigInteger::new([5823303549099682051, 11298647609364880259, 17539675314511186284, 556302735522023958])),
        Fq::new(BigInteger::new([2083577888616351182, 10916945937534065039, 1520021691683278293, 2748969749429754277])),
        false,
    ),
};

// const PREPARED_INPUT: G1Affine254 = G1Affine254::new_const(
//     Fq::new(BigInteger::new([9497411607956386375, 268351533763702874, 18353951159736685747, 1825167008963268151])),
//     Fq::new(BigInteger::new([5487945063526916415, 2251437326952299004, 2432273193309581731, 2595211258581520627])),
//     false
// );

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
    // let data = &mut &F[..];
    // let f = Fqk254::deserialize(data).unwrap();

    // let r = G2HomProjective254 {
    //     x: Fq2::new_const(
    //         Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
    //         Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
    //     ),
    //     y: Fq2::new_const(
    //         Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
    //         Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
    //     ),
    //     z: Fq2::new_const(
    //         Fq::new(BigInteger::new([4153767206144153341, 4757445080423304776, 7392391047398498789, 735036359864433540])),
    //         Fq::new(BigInteger::new([786726130547703630, 11930992407036731514, 3203034900645816634, 1625741866668428970])),
    //     ),
    // };

    let mut stage = PrepareInputs::default();
    stage.input_index = input[0];
    stage.bit_index = input[1];

    let public_inputs = vec![
        Fr::new(BigInteger::new([
            9497411607956386375,
            268351533763702874,
            18353951159736685747,
            1825167008963268151,
        ]));
        32
    ];

    let proof_type = OperationType::Deposit;
    let pvk = proof_type.verifying_key();

    let public_inputs_ctx = ReadOnlyContext::new(stage.public_inputs, public_inputs);
    let g_ic_ctx = UpdateContext::new(stage.g_ic, *pvk.g_ic_init);
    let tmp_ctx = UpdateContext::new(stage.tmp, G1Projective254::zero());

    stage.process(proof_type, &public_inputs_ctx, &g_ic_ctx, &tmp_ctx);

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
        
    Ok(())
}

#[cfg(test)]
mod tests {
    use solana_program::instruction::Instruction;
    use solana_sdk::{transaction::Transaction, commitment_config::{CommitmentConfig, CommitmentLevel}, signature::Keypair, signer::Signer};
    use solana_client::rpc_client::{RpcClient};

    use crate::{id, params::{Fqk254, Fq6, Fq2, Fq}, bn::BigInteger256};

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
                data: vec![0, 245, 0],
            }],
            Some(&user.pubkey()),
            &[&user],
            blockhash,
        );

        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }
}