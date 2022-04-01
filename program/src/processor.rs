use num_traits::One;
use solana_program::{pubkey::Pubkey, account_info::AccountInfo, entrypoint::ProgramResult};

use crate::{verifier::{state::Proof, params::{G1Affine254, G2Affine254, Fq, Fq2, G2HomProjective254, Fqk254, Fq6}, processor::{MillerLoopCtx, FinalExponentCtxInverse1, FinalExponentFrobiniusCtx, FinalExponentExpByNegCtx}}, OperationType, bn::Field};
use crate::bn::BigInteger256 as BigInteger;

// const PROOF: Proof = Proof {
//     a: G1Affine254::new_const(
//         Fq::new(BigInteger::new([14715620368662735844, 9563436648438579353, 9817845158629706665, 2420889558595263392])),
//         Fq::new(BigInteger::new([8640892419674201321, 14834230856296141528, 4198848546444402927, 1517119377864516134])),
//         false,
//     ),
//     b: G2Affine254::new_const(
//         Fq2::new_const(
//             Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
//             Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
//         ),
//         Fq2::new_const(
//             Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
//             Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
//         ),
//         false,
//     ),
//     c: G1Affine254::new_const(
//         Fq::new(BigInteger::new([5823303549099682051, 11298647609364880259, 17539675314511186284, 556302735522023958])),
//         Fq::new(BigInteger::new([2083577888616351182, 10916945937534065039, 1520021691683278293, 2748969749429754277])),
//         false,
//     ),
// };

// const PREPARED_INPUT: G1Affine254 = G1Affine254::new_const(
//     Fq::new(BigInteger::new([9497411607956386375, 268351533763702874, 18353951159736685747, 1825167008963268151])),
//     Fq::new(BigInteger::new([5487945063526916415, 2251437326952299004, 2432273193309581731, 2595211258581520627])),
//     false
// );

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let f = Fqk254::new_const(
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

    let mut f_inv = f.clone();
    f_inv.conjugate();
    let ctx = FinalExponentExpByNegCtx {
        index: input[0],
        found_nonzero: false,
        f,
        f_inv,
        res: Fqk254::one(),
    };
    ctx.process();
        
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
                data: vec![0],
            }],
            Some(&user.pubkey()),
            &[&user],
            blockhash,
        );

        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }
}