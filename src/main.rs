use crate::util::*;
use ark_bls12_381::{G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Fr, Bls12_381};
use ark_ec::{pairing::Pairing, pairing::PairingOutput, AffineRepr, CurveGroup};
use ark_std::UniformRand;
use rand::{CryptoRng, Rng};
// use group::Group;

mod util;
use util::{rand_scalar, rand_g1, rand_g2, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE, h1_to_g2, h2, h3, h4, rand_sigma};




pub const  n: usize = 256;

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PublicKey {
    p: G1Affine,
    p_pub: G1Affine,
   

}

#[derive(Clone, Debug)]
pub struct MasterSecretKey{
    s:Fr,
}

#[derive(Clone, Debug)]
pub struct UserSecretKey{  //Known by the KGC and the User
    d_a: G2Affine,
}

pub struct UserPrivateKey{  //Known only by user
    t_a:Fr,
}

#[derive(Clone, Debug)]
pub struct UserPublicKey{
    n_a:G1Affine,
}

// type Msg = Gt;


#[derive(Clone, Debug)]
pub struct CipherText{
    u: G1Affine,
    v: [u8; 32],
    w: [u8; 32]

}

#[derive(Debug)]
pub enum DecryptError {
    InvalidCiphertext,
}

pub struct CLIBE;
impl CLIBE {
    fn setup<R:Rng+CryptoRng>(rng: &mut R)->(PublicKey, MasterSecretKey){
        
        let p:G1 = rand_g1(rng);
        let s:Fr = rand_scalar(rng);
        let p_pub:G1 = p * s;

        let pk = PublicKey{
            p: p.into_affine(), 
            p_pub: p_pub.into_affine()};

        let msk = MasterSecretKey{
            s
        };

        (pk,msk)
    }

    fn extract(id: &[u8], msk:&MasterSecretKey) -> UserSecretKey{
        let q_a = h1_to_g2(id).expect("H1 failed");

        let q_a_proj: G2 = q_a.into_group();

        let d_a:G2 = q_a_proj*msk.s;

        let usk = UserSecretKey{
            d_a : d_a.into_affine()
        };
        usk
    }


    fn publish<R:Rng+CryptoRng>(rng: &mut R, pk:&PublicKey)-> (UserPublicKey, UserPrivateKey){
        let t_a:Fr = rand_scalar(rng);

        let n_a:G1 = pk.p * t_a;

        let user_private_key = UserPrivateKey{
            t_a
        };

        let user_public_key = UserPublicKey{
            n_a: n_a.into_affine()
        };
        (user_public_key,user_private_key)

    }

    fn encrypt<R:Rng+CryptoRng>(
        rng: &mut R,
        message:&[u8;32], 
        id: &[u8], 
        pk:&PublicKey, 
        upk:&UserPublicKey
    )-> CipherText{

        let sigma: [u8;32] = rand_sigma(rng);
        println!("sigma (encrypt) = {:?}", sigma);
        let r:Fr = h3(&sigma, &message);

        let q_a = h1_to_g2(id).expect("H1 failed");
        println!("q_a (encrypt) = {:?}", q_a);

        let q_a_proj: G2 = q_a.into_group();

        let g_r: PairingOutput<Bls12_381> = Bls12_381::pairing(pk.p_pub, q_a_proj) * r;
        let f:G1 = upk.n_a * r;

        let u:G1 = pk.p * r;

        let u_aff = u.into_affine();
        let f_aff = f.into_affine();
        let h2_result:[u8;32] = h2(&u_aff, &g_r, &f_aff);
        
        let mut v:[u8; 32] = [0u8; 32];
        for i in 0..32{
            v[i]= sigma[i]^h2_result[i]
        }

        let h4_result:[u8;32] = h4(&sigma);
        let mut w:[u8; 32] = [0u8; 32];
        for i in 0..32{
            w[i]= message[i]^h4_result[i];
        }

        let cipher = CipherText{
            u : u_aff,
            v : v,
            w : w
        };
        cipher

    }

    fn decrypt(
        cipher : &CipherText,
        usk : &UserSecretKey,
        user_private_key : &UserPrivateKey,
        pk : &PublicKey
    ) -> Result<[u8; 32], DecryptError>{
        let g_prime:PairingOutput<Bls12_381> = Bls12_381::pairing(cipher.u, usk.d_a);

 


        let f_prime:G1 = cipher.u.into_group() * user_private_key.t_a;
        let f_prime_affine:G1Affine = f_prime.into_affine();

        let h2_result:[u8;32] = h2(&cipher.u, &g_prime, &f_prime_affine);
        // dans decrypt, AVANT le calcul de sigma_prime
        // println!("--- DECRYPT ---");
        // println!("cipher.u        = {:?}", cipher.u);
        // println!("g_prime         = {:?}", g_prime);
        // println!("f_prime_affine  = {:?}", f_prime_affine);
        // println!("h2_result (dec) = {:?}", h2_result);
        // println!("h4_result (dec) = {:?}", h4_result);
        let mut sigma_prime:[u8;32] = [0u8; 32];
        for i in 0..32{
            sigma_prime[i]= cipher.v[i]^h2_result[i];
        }

        let h4_result:[u8;32] = h4(&sigma_prime);
        let mut message_prime:[u8;32] = [0u8; 32];
        for i in 0..32{
            message_prime[i]= cipher.w[i]^h4_result[i];
        }

        let r_prime:Fr = h3(&sigma_prime, &message_prime);

        let r_prime_p:G1 = pk.p * r_prime;
        println!("sigma_prime = {:?}", sigma_prime);
        println!("message_prime = {:?}", message_prime);
        println!("cipher.u = {:?}", cipher.u);
        println!("r_prime_p = {:?}", r_prime_p.into_affine());

       if cipher.u != r_prime_p.into_affine() {
            return Err(DecryptError::InvalidCiphertext);
        }
        // println!("--- DECRYPT ---");
        // println!("cipher.u      = {:?}", cipher.u);
        // println!("g_prime       = {:?}", g_prime);
        // println!("f_prime_affine= {:?}", f_prime_affine);
        // println!("h2_result     = {:?}", h2_result);
        // println!("h4_result     = {:?}", h4_result);
        // println!("sigma_prime   = {:?}", sigma_prime);
        // println!("message_prime = {:?}", message_prime);
        Ok(message_prime)

    }
} 

fn main(){
    use rand::thread_rng;

    let mut rng = thread_rng();
    println!("=== Tests de setup ===");
     let (pk, msk) = CLIBE::setup(&mut rng);

    println!("Public key p : {:?}",pk.p);
    println!("Public key p_pub : {:?}",pk.p_pub);
    println!("Master Secret msk : {:?}",msk.s);

    println!("\n=== Tests de H1 (hash-to-G2) ===");

  }

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup_produces_valid_keys() {
        let mut rng = thread_rng();
        let (pk, msk) = CLIBE::setup(&mut rng);
        
        // P_pub doit égaler s·P
        let recomputed = (pk.p.into_group() * msk.s).into_affine();
        assert_eq!(pk.p_pub, recomputed, "P_pub should equal s·P");
    }

    #[test]
    fn test_extract_is_deterministic() {
        let mut rng = thread_rng();
        let (_, msk) = CLIBE::setup(&mut rng);
        let id = b"alice@example.com";
        
        let usk1 = CLIBE::extract(id, &msk);
        let usk2 = CLIBE::extract(id, &msk);
        assert_eq!(usk1.d_a, usk2.d_a, "Extract should be deterministic for same ID");
    }

    #[test]
    fn test_extract_different_ids_differ() {
        let mut rng = thread_rng();
        let (_, msk) = CLIBE::setup(&mut rng);
        
        let usk_alice = CLIBE::extract(b"alice", &msk);
        let usk_bob = CLIBE::extract(b"bob", &msk);
        assert_ne!(usk_alice.d_a, usk_bob.d_a, "Different IDs should give different keys");
    }

    #[test]
    fn test_publish_randomness() {
        let mut rng = thread_rng();
        let (pk, _) = CLIBE::setup(&mut rng);
        
        let (upk1, _) = CLIBE::publish(&mut rng, &pk);
        let (upk2, _) = CLIBE::publish(&mut rng, &pk);
        assert_ne!(upk1.n_a, upk2.n_a, "Publish should produce fresh randomness");
    }

    #[test]
    fn test_h1_deterministic() {
        let id = b"alice@example.com";
        let q1 = h1_to_g2(id).expect("H1 failed");
        let q2 = h1_to_g2(id).expect("H1 failed");
        assert_eq!(q1, q2);
    }

    #[test]
    fn test_h3_deterministic() {
        let sigma = [1u8; 32];
        let m = [2u8; 32];
        assert_eq!(h3(&sigma, &m), h3(&sigma, &m));
    }

    #[test]
    fn test_h2_deterministic() {
        let mut rng = thread_rng();
        let u = G1::rand(&mut rng).into_affine();
        let f = G1::rand(&mut rng).into_affine();
        let g: PairingOutput<Bls12_381> = PairingOutput::<Bls12_381>::rand(&mut rng);
        assert_eq!(h2(&u, &g, &f), h2(&u, &g, &f));
    }

    #[test]
    fn test_h2_deterministic_same_inputs() {
        use ark_std::UniformRand;
        let mut rng = rand::thread_rng();
        
        let u = G1::rand(&mut rng).into_affine();
        let f = G1::rand(&mut rng).into_affine();
        let q = G2::rand(&mut rng).into_affine();
        let g = Bls12_381::pairing(u, q);
        
        let h1 = h2(&u, &g, &f);
        let h2_bis = h2(&u, &g, &f);
        
        assert_eq!(h1, h2_bis, "H2 must be deterministic!");
    }

    #[test]
    fn test_pairing_identity() {
        use ark_std::UniformRand;
        let mut rng = rand::thread_rng();
        let (pk, msk) = CLIBE::setup(&mut rng);
        let id = b"test";
        let usk = CLIBE::extract(id, &msk);
        
        let r = Fr::rand(&mut rng);
        let q_a = h1_to_g2(id).expect("H1 failed");
        let u: G1Affine = (pk.p.into_group() * r).into_affine();
        
        // Côté encrypt : g_r = e(P_pub, Q_A)^r
        let g_r_encrypt = Bls12_381::pairing(pk.p_pub, q_a) * r;
        // Côté decrypt : g' = e(U, d_A) où d_A = s·Q_A
        let g_prime_decrypt = Bls12_381::pairing(u, usk.d_a);
        
        assert_eq!(g_r_encrypt, g_prime_decrypt);
    }

    

    #[test]
    fn test_roundtrip() {
        let mut rng = thread_rng();
        let (pk, msk) = CLIBE::setup(&mut rng);
        let id = b"alice@example.com";
        
        let usk = CLIBE::extract(id, &msk);
        let (upk, upriv) = CLIBE::publish(&mut rng, &pk);
        
        let message: [u8; 32] = [42u8; 32];
        let ct = CLIBE::encrypt(&mut rng, &message, id, &pk, &upk);
        let decrypted = CLIBE::decrypt(&ct, &usk, &upriv, &pk).expect("decryption failed");
        
        assert_eq!(message, decrypted, "Decrypted message should match original");
    }
}