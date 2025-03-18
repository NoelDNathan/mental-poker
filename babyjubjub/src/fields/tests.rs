#![allow(unused)]


use ark_ec::{AffineCurve, MontgomeryModelParameters, ProjectiveCurve};
use ark_ff::{BigInteger, Field };//, UniformRand};
use ark_std::println;
use ark_std::str::FromStr;
// use ark_ed_on_bn254::EdwardsAffine;
// use rand::thread_rng;

use crate::{EdwardsAffine, EdwardsParameters, Fq, Fr};
use ark_ff::biginteger::BigInteger256;

#[test]
fn test_eip2494_addition() {


    let p1_x = Fq::from_str(
        "17777552123799933955779906779655732241715742912184938656739573121738514868268",
    )
    .unwrap();
    let p1_y = Fq::from_str(
        "2626589144620713026669568689430873010625803728049924121243784502389097019475",
    )
    .unwrap();

    let p2_x = Fq::from_str(
        "16540640123574156134436876038791482806971768689494387082833631921987005038935",
    )
    .unwrap();
    let p2_y = Fq::from_str(
        "20819045374670962167435360035096875258406992893633759881276124905556507972311",
    )
    .unwrap();

    let expected_x = Fq::from_str(
        "7916061937171219682591368294088513039687205273691143098332585753343424131937",
    )
    .unwrap();
    let expected_y = Fq::from_str(
        "14035240266687799601661095864649209771790948434046947201833777492504781204499",
    )
    .unwrap();

    let point1 = EdwardsAffine::new(p1_x, p1_y);
    let point2 = EdwardsAffine::new(p2_x, p2_y);
    let expected = EdwardsAffine::new(expected_x, expected_y);


    let result = point1 + point2;

    println!("result: {:?}", result.into_projective().into_affine());
    println!("expected: {:?}", expected.into_projective().into_affine());
    assert_eq!(result, expected);

    // Test addition using the curve equation
    // Note: This is a simplified test. In a real implementation, you would use proper curve point addition
}

#[test]
fn test_doubling() {
    let p1_x = Fq::from_str(
        "17777552123799933955779906779655732241715742912184938656739573121738514868268",
    )
    .unwrap();
    let p1_y = Fq::from_str(
        "2626589144620713026669568689430873010625803728049924121243784502389097019475",
    )
    .unwrap();

    let expected_x = Fq::from_str(
        "6890855772600357754907169075114257697580319025794532037257385534741338397365",
    )
    .unwrap();
    let expected_y = Fq::from_str(
        "4338620300185947561074059802482547481416142213883829469920100239455078257889",
    )
    .unwrap();

    let point1 = EdwardsAffine::new(p1_x, p1_y);
    let result = point1 + point1;
    let expected = EdwardsAffine::new(expected_x, expected_y);

    assert_eq!(result, expected);
}

#[test]
fn test_doubling_identity() {
    let identity_x = Fq::from_str("0").unwrap();
    let identity_y = Fq::from_str("1").unwrap();

    let point = EdwardsAffine::new(identity_x, identity_y);
    let result = point + point;

    assert_eq!(result, point);
}

#[test]
fn test_curve_membership() {
    let zero = Fq::from_str("0").unwrap();
    let one = Fq::from_str("1").unwrap();
    // let mut rng = thread_rng();

    let point_on_curve = EdwardsAffine::new(zero, one);

    // // let scalar = Fr::rand(&mut rng);
    // let scalar = Fr::from_str("21888242871839275222246405745257275088614511777268538073601725287587578984328").unwrap();
    // println!("scalar: {}", scalar);
    // let result = point_on_curve.into_group() * scalar;
    // println!("point: {:?}", point_on_curve.into_group());
    // println!("result: {:?}", result);
    // println!("result: {:?}", result.into_affine());

    println!("point{}", point_on_curve);

    assert!(point_on_curve.is_on_curve());

    let point_not_on_curve  = EdwardsAffine::new(one, zero);
    println!("point_not_on_curve: {:?}", point_not_on_curve);
    assert!(!point_not_on_curve.is_on_curve());
}

#[test]
fn test_base_point_choice() {
    let generator_x =
        Fq::from_str("995203441582195749578291179787384436505546430278305826713579947235728471134")
            .unwrap();
    let generator_y = Fq::from_str(
        "5472060717959818805561601436314318772137091100104008585924551046643952123905",
    )
    .unwrap();
    let base_x = Fq::from_str(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    )
    .unwrap();
    let base_y = Fq::from_str(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .unwrap();

    let generator = EdwardsAffine::new(generator_x, generator_y);
    let base = EdwardsAffine::new(base_x, base_y);
    let scalar = Fr::from_str("8").unwrap();
    let result = generator.mul(scalar);
    assert_eq!(result, base);
}

#[test]
fn test_base_point_order() {
    let zero = Fq::from_str("0").unwrap();
    let one = Fq::from_str("1").unwrap();
    
    let base_x = Fq::from_str(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    )
    .unwrap();
    let base_y = Fq::from_str(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .unwrap();
    let l = Fr::from_str(
        "2736030358979909402780800718157159386076813972158567259200215660948447373041",
    )
    .unwrap();

    let base = EdwardsAffine::new(base_x, base_y);
    let identity = EdwardsAffine::new(zero, one);

    let result = base.mul(l);
    assert_eq!(result, identity);
}
