use crate::{params::Fr, bn::BigInteger256 as BigInteger};

pub const BIT_SIZE: usize = 124 * 2;

pub const RABIN_MODULUS: &[Fr; 12] = &[
    Fr::new(BigInteger::new([12777777600521295127, 5220067115064882724, 14362690022655613818, 2706487573154054812])),
    Fr::new(BigInteger::new([1998369480398299688, 16159721978871462194, 4396172715448382881, 1761510632796265421])),
    Fr::new(BigInteger::new([8570134951137558905, 17459132876189821037, 5505629564377348987, 1090004265756120665])),
    Fr::new(BigInteger::new([3386096054251392345, 6426368164816514150, 12704078255723802317, 554389573564471306])),
    Fr::new(BigInteger::new([11311527219562070615, 14913382653128938538, 970792649567958006, 1379826904388049708])),
    Fr::new(BigInteger::new([6947746311896286309, 16426049338515012266, 2612552927800070164, 2231407703120893569])),
    Fr::new(BigInteger::new([3810486600686980740, 16073852489525722742, 14897976663431149194, 578372123837338426])),
    Fr::new(BigInteger::new([2806725743856909609, 17782886883252955551, 16090489401577276810, 749258722818981842])),
    Fr::new(BigInteger::new([8414618439315535612, 14960847356138949448, 8273477606282110422, 2040821030238047751])),
    Fr::new(BigInteger::new([3982774839345723131, 391014855533901894, 1213711650311017124, 146818960493835217])),
    Fr::new(BigInteger::new([5791138232736921263, 10354074302837551615, 2752153283443103252, 843402108789171392])),
    Fr::new(BigInteger::new([16483669135110030546, 11823900411458084364, 13303980901346756620, 594178847673263923])),
];