use ark_std::UniformRand;
use ark_bls12_381::{Fr, G1Projective as G1,G2Projective,G2Projective as G2, G1Affine, G2Affine, Bls12_381};
use ark_bls12_381::g2::Config as G2Config;
use rand::{CryptoRng, Rng};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve, HashToCurveError},
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use sha2::{Sha256, Digest};



pub const G1_SERIALIZED_SIZE: usize = 48;
pub const G2_SERIALIZED_SIZE: usize = 96;
pub const H1_DST : &[u8] = b"CL_PKE_CHENG_COMLEY_BLS12_381_H1";
pub const H2_DST : &[u8] = b"CL_PKE_CHENG_COMLEY_BLS12_381_H2";
pub const H3_DST : &[u8] = b"CL_PKE_CHENG_COMLEY_BLS12_381_H3";
pub const H4_DST : &[u8] = b"CL_PKE_CHENG_COMLEY_BLS12_381_H4";

pub fn rand_scalar<R: Rng+CryptoRng>(rng: &mut R) -> Fr {
    Fr::rand(rng)
}

pub fn rand_g1<R: Rng+CryptoRng>(rng: &mut R) -> G1{
    G1::rand(rng)
}

pub fn rand_g2<R: Rng+CryptoRng>(rng: &mut R) -> G2{
    G2::rand(rng)
}

pub fn rand_sigma<R: Rng+CryptoRng>(rng: &mut R) -> [u8; 32]{
    let mut sigma = [0u8; 32];
    rng.fill(&mut sigma);
    sigma
}

// Hash to curve : maps an arbitrary identity string to a point in G2
// H1 : {0, 1}* -> G2
pub fn h1_to_g2(id:&[u8]) -> Result<G2Affine, HashToCurveError>{
    let g2_mapper = MapToCurveBasedHasher::<
        G2Projective,
        DefaultFieldHasher<Sha256>,
        WBMap<G2Config>
        >::new(H1_DST)?;
    
    let q_A : G2Affine =g2_mapper.hash(id)?;
    Ok(q_A)
}

// Hash to bitstring takes a tuple (U, g^r, f) ∈ G1 x Gt x G1 and produces an n-byte mask
// H2 : G1 x Fr x G1 -> {0,1}^n
pub fn h2(
    u: &G1Affine,
    g_r: &PairingOutput<Bls12_381>,
    f:  &G1Affine
)->[u8;32]{
    let mut bytes = Vec::new();
  
    u.serialize_compressed(&mut bytes).unwrap();
    g_r.serialize_compressed(&mut bytes).unwrap();
    f.serialize_compressed(&mut bytes).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(H2_DST);
    hasher.update(&bytes);

    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out

}

// Hash to scalar maps a tuple (σ,m) ∈ {0,1}^n x {0,1}^n to a scalar r ∈ Zq
// H3 : {0,1}^n x {0,1}^n -> Zq*
pub fn h3(sigma: &[u8;32], message: &[u8;32]) -> Fr{
    let mut hasher = Sha256::new();

    hasher.update(H3_DST);
    hasher.update(sigma);
    hasher.update(message);

    let digest = hasher.finalize();

    Fr::from_le_bytes_mod_order(&digest)

}

// Hash to bitstring mask the plaintext 
// H3 : {0,1}^n -> {0,1}^n 
pub fn h4(sigma: &[u8; 32]) -> [u8; 32]{
    let mut hasher = Sha256::new();

    hasher.update(H4_DST);
    hasher.update(sigma);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out

}

