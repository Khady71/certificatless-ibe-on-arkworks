use crate::util::*;
use ark_test_curves::bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Gt, Fq12 as Fq12, Fr};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::UniformRand;


use rand::{CryptoRng, Rng};
use group::Group;




#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PublicKey {
    g1: G1Affine,
    g2: G2Affine,
    p_pub: G2Affine,
    n: usize,

}

#[derive(Clone, Debug)]
pub struct MasterKey{
    s:Fr,
}

#[derive(Clone, Debug)]
pub struct UserSecretKey{
    d_a: G1Affine,
}

#[derive(Clone, Debug)]
pub struct UserPublicKey{
    n_a = G2Affine,
}

type Msg = Gt;


#[derive(Clone, Debug)]
pub struct CipherText{
    u: G2Affine,
    v: Vec<u8>,
    w: Vec<u8>

}

impl CL-IBE {
    type Pk = PublicKey;
    type Sk = MasterKey;
    type Usk = UserSecretKey;
    type Psk = UserPublicKey;
    type Ct = CipherText;
    type Msg = Msg;

    fn setup{

    }

    fn extract{

    }

    fn publish{

    }

    fn encrypt{

    }

    fn decrypt{

    }
} 