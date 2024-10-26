#include <iostream>
#include <bicycl.hpp>
#include <gmp.h>

// Ciphertext Addition: You can add two ciphertexts homomorphically.
void ciphertext_addition(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::SecretKey& sk, BICYCL::CL_HSM2k::PublicKey& pk) {
    std::cout << "\nHomomorphic Addition:" << std::endl;
    int x = 5, y = 10;
    
    auto x_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x))), randgen);
    auto y_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y))), randgen);

    auto result_e = hsm2k.add_ciphertexts(pk, x_e, y_e, randgen);

    // Decrypt result
    BICYCL::CL_HSM2k::ClearText result_d = hsm2k.decrypt(sk, result_e);
    int result_value = (int)mpz_get_ui(result_d.operator const __mpz_struct*());

    std::cout << "x = " << x << ", y = " << y << std::endl;
    std::cout << "Homomorphic addition result: " << result_value << std::endl;
}

// Scalar Multiplication: You can scale ciphertexts by a scalar homomorphically.
void scalar_multiplication(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::SecretKey& sk, BICYCL::CL_HSM2k::PublicKey& pk) {
    std::cout << "\nScalar Multiplication:" << std::endl;
    int x = 5, scalar = 4;

    auto x_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x))), randgen);
    auto scaled_e = hsm2k.scal_ciphertexts(pk, x_e, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(scalar))), randgen);

    // Decrypt the result of scalar multiplication
    BICYCL::CL_HSM2k::ClearText scaled_d = hsm2k.decrypt(sk, scaled_e);
    int scaled_value = (int)mpz_get_ui(scaled_d.operator const __mpz_struct*());

    std::cout << "x = " << x << ", scalar = " << scalar << std::endl;
    std::cout << "Scalar multiplication result: " << scaled_value << std::endl;
}

void homomorphic_operations() {
    // 1) Setup
    std::string seed = "1157920892373161954235709850086879078528375642790749043";   // seed should be kept secret in real-world usage

    BICYCL::Mpz seed_mpz(seed);
    BICYCL::RandGen randgen;
    randgen.set_seed(seed_mpz);

    BICYCL::CL_HSM2k hsm2k(96, 64, randgen, true);

    BICYCL::CL_HSM2k::SecretKey sk = hsm2k.keygen(randgen);
    BICYCL::CL_HSM2k::PublicKey pk = hsm2k.keygen(sk);
    
    // 2) Ciphertext Addition
    ciphertext_addition(hsm2k,randgen, sk, pk);

    // 3) Scalar Multiplication
    scalar_multiplication(hsm2k, randgen, sk, pk);
}

int main() {
    homomorphic_operations();
    return 0;
}
