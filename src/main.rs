use crate::util::*;
use ark_bls12_381::{G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Fr};
// use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::UniformRand;
use rand::{CryptoRng, Rng};
// use group::Group;

mod util;
use util::{rand_scalar, rand_g1, rand_g2, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE,
            h1_to_g2, h2, h3, h4};




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
pub struct UserSecretKey{
    d_a: G1Affine,
}

#[derive(Clone, Debug)]
pub struct UserPublicKey{
    n_a:G2Affine,
}

// type Msg = Gt;


#[derive(Clone, Debug)]
pub struct CipherText{
    u: G2Affine,
    v: Vec<u8>,
    w: Vec<u8>

}

pub struct CLIBE;
impl CLIBE {
    fn setup<R:Rng+CryptoRng>(rng: &mut R)->(PublicKey, MasterSecretKey){
        
        let p:G1 = rand_g1(rng);
        let s:Fr = rand_scalar(rng);
        let p_pub:G1 = p * s;

        let pk = PublicKey{
            p: p.into(), 
            p_pub: p_pub.into()};

        let msk = MasterSecretKey{
            s
        };

        (pk,msk)
    }

    fn extract(){

    }

    fn publish(){

    }

    fn encrypt(){

    }

    fn decrypt(){

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


    // let id_alice = b"alice@example.com";
    // let id_bob   = b"bob@example.com";

    // let q_alice_1 = h1_to_g2(id_alice).expect("H1 ne devrait pas échouer");
    // let q_alice_2 = h1_to_g2(id_alice).expect("H1 ne devrait pas échouer");
    // let q_bob     = h1_to_g2(id_bob).expect("H1 ne devrait pas échouer");

    // // Déterminisme: même identité → même point
    // assert_eq!(q_alice_1, q_alice_2, "H1 doit être déterministe");
    // println!("✓ Déterminisme OK");

    // // Sensibilité: identités différentes → points différents
    // assert_ne!(q_alice_1, q_bob, "H1 doit distinguer des identités différentes");
    // println!("✓ Sensibilité aux inputs OK");

    // // Le point est bien dans G2 et dans le bon sous-groupe
    // assert!(q_alice_1.is_on_curve(), "Q_A doit être sur la courbe");
    // assert!(
    //     q_alice_1.is_in_correct_subgroup_assuming_on_curve(),
    //     "Q_A doit être dans le sous-groupe d'ordre premier"
    // );
    // // assert!(!q_alice_1.is_zero(), "Q_A ne doit pas être l'élément neutre");
    // println!("✓ Q_A ∈ G2* (sur la courbe, sous-groupe correct, non-zéro)");

    // println!("Q_alice = {:?}", q_alice_1);
        // ========================================================================
    println!("\n=== Tests de H4 ===");
    // ========================================================================

    let sigma = [0x42u8; 32];
    let sigma2 = [0x43u8; 32];
    let h4_out_1 = h4(&sigma);
    let h4_out_2 = h4(&sigma);
    let h4_out_different = h4(&sigma2);

    assert_eq!(h4_out_1, h4_out_2, "H4 doit être déterministe");
    assert_ne!(h4_out_1, h4_out_different, "H4 doit être sensible à σ");
    assert_eq!(h4_out_1.len(), 32, "H4 doit retourner 32 bytes");
    println!("✓ Déterminisme, sensibilité, longueur OK");

    println!("H4(σ) = {:02x?}", h4_out_1);

}