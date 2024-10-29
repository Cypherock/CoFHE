#include <iostream>
#include <bicycl.hpp>
#include <gmp.h>
#include <vector>

template<typename T>
using Matrix = std::vector<std::vector<T> >;

template<typename T>
using Array = std::vector<T>;

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

struct AccessStructure {
    int t;
    int n;
    AccessStructure(int t = 0, int n = 0) : t(t), n(n) {}
};

typedef struct {
    Matrix<int> M;
    Matrix<int> Sie;
    int rows;
    int cols;
} ISP;

typedef struct {
    AccessStructure A;
    Matrix<BICYCL::Mpz> secret_key_shares;
    Matrix<BICYCL::CL_HSM2k::CipherText> beaver_triplet_a_shares;
    Matrix<BICYCL::CL_HSM2k::CipherText> beaver_triplet_b_shares;
    Matrix<BICYCL::CL_HSM2k::CipherText> beaver_triplet_c_shares;
} LISSKeyGen;

// Function to compute the M_OR matrix
Matrix<int> compute_M_OR(const Matrix<int> &Ma, const Matrix<int> &Mb) {
    int da = Ma.size();
    int ea = Ma[0].size();
    int db = Mb.size();
    int eb = Mb[0].size();
    
    // Dimensions for M_OR
    int M_OR_rows = da + db;
    int M_OR_cols = ea + eb - 1;
    
    // Initialize M_OR with all zeroes
    Matrix<int> M_OR(M_OR_rows, std::vector<int>(M_OR_cols, 0));
    
    // Fill in the first column with concatenated c(a) and c(b)
    for (int i = 0; i < da; ++i) {
        M_OR[i][0] = Ma[i][0];
    }
    for (int i = 0; i < db; ++i) {
        M_OR[da + i][0] = Mb[i][0];
    }
    
    // Fill the remaining columns for Ma with db trailing zeros
    for (int i = 0; i < da; ++i) {
        for (int j = 1; j < ea; ++j) {
            M_OR[i][j] = Ma[i][j];
        }
    }
    
    // Fill the remaining columns for Mb with da leading zeros
    for (int i = 0; i < db; ++i) {
        for (int j = 1; j < eb; ++j) {
            M_OR[da + i][ea + j - 1] = Mb[i][j];
        }
    }
    
    return M_OR;
}

// Function to compute the M_AND matrix<int>
Matrix<int> compute_M_AND(const Matrix<int> &Ma, const Matrix<int> &Mb) {
    int da = Ma.size();
    int ea = Ma[0].size();
    int db = Mb.size();
    int eb = Mb[0].size();
    
    // Dimensions for M_OR
    int M_AND_rows = da + db;
    int M_AND_cols = ea + eb;
    
    // Initialize M_OR with all zeroes
    Matrix<int> M_AND(M_AND_rows, std::vector<int>(M_AND_cols, 0));
    
    // Fill in the first column with c(a) following db zeros & second column with c(a) concatenated c(b)
    for (int i = 0; i < da; ++i) {
        M_AND[i][0] = Ma[i][0];
        M_AND[i][1] = Ma[i][0];
    }
    for (int i = 0; i < db; ++i) {
        M_AND[da + i][1] = Mb[i][0];
    }
    
    // Fill the remaining columns for Ma with db trailing zeros
    for (int i = 0; i < da; ++i) {
        for (int j = 1; j < ea; ++j) {
            M_AND[i][j + 1] = Ma[i][j];
        }
    }
    
    // Fill the remaining columns for Mb with da leading zeros
    for (int i = 0; i < db; ++i) {
        for (int j = 1; j < eb; ++j) {
            M_AND[da + i][ea + j] = Mb[i][j];
        }
    }
    
    return M_AND;
}

int nCr(int n, int r) {
    double res = 1;
    for(int i = 1; i <= r; i++){
        res = res * (n - r + i) / i;
    }
    return res;
}

Matrix<int> generate_distribution_matrix_M(int n, int t, int threshold_combinations) {
    Matrix<int> Mu{{1}};
    Matrix<int> Mt = Mu;

    for (int i = 1; i < t; i++) {
        Mt = compute_M_AND(Mt, Mu);
    }
    
    Matrix<int> M = Mt;
    for (int i = 1; i < threshold_combinations; i++) {
        M = compute_M_OR(M, Mt);
    }
    return M;
}

Matrix<int> generate_Sie(int n, int t) {
    Matrix<int> Sie(n, Array<int>(n, -1));

}

// Function to generate a random matrix M (d x e) with 0s and 1s
ISP generate_isp(AccessStructure& A) {
    int n = A.n, t = A.t;

    int threshold_combinations = nCr(n, t);
    Matrix<int> M = generate_distribution_matrix_M(n, t, threshold_combinations);

    Matrix<int> Sie(threshold_combinations, Array<int>(t, 0));
    int M_row_num = 0;
    for (int i = 0; i < threshold_combinations; i++) {
        for (int j = 0; j < t; j++) {
            Sie[i][j] = M_row_num++;
        }
    }
    
    ISP isp;
    isp.M = M;
    isp.Sie = Sie;
    isp.rows = M.size();
    isp.cols = M[0].size();

    return isp;
}

Array<BICYCL::Mpz> compute_rho(BICYCL::Mpz& secret, int e) {
    std::string seed = "115792089237";   // seed should be kept secret in real-world usage
    BICYCL::Mpz seed_mpz(seed);
    BICYCL::RandGen randgen;
    randgen.set_seed(seed_mpz);
    BICYCL::CL_HSM2k hsm2k(9, 64, randgen, true);

    Array<BICYCL::Mpz> rho(e);
    rho[0] = secret;  // Set ρ(0) = s as per the algorithm
    for (int i = 1; i < e; i++) {
        rho[i] = randgen.random_mpz (hsm2k.encrypt_randomness_bound()); //BICYCL::Mpz((unsigned long)(1 + std::rand() % 100000000));   // This should be random value in range [-2^(l0+λ), 2^(l0+λ)]^(e−1)
    }
    return rho;
}

Matrix<BICYCL::Mpz> compute_shares(ISP& isp, Array<BICYCL::Mpz>& rho) {
    Matrix<int> M = isp.M;
    Matrix<int> Sie = isp.Sie;
    int rows = isp.rows, cols = isp.cols;

    std::cout << "Shares: " << std::endl;
    Matrix<BICYCL::Mpz> sharesi;
    for (auto Sp : Sie) {
        Array<BICYCL::Mpz> si;
        for (int i : Sp) {
            BICYCL::Mpz sij(BICYCL::Mpz((unsigned long)(0)));
            if ( i != -1) {
                for (int j = 0; j < cols; j++) {
                    BICYCL::Mpz mult;
                    sij.mul(mult, rho[j], BICYCL::Mpz((unsigned long)(M[i][j])));
                    sij.add(sij, sij, mult);
                }
            }
            std::cout << sij << ", ";
            si.push_back(sij);
        }
        std::cout << std::endl;
        sharesi.push_back(si);
    }
    std::cout << std::endl;
    return sharesi;
}

Matrix<BICYCL::Mpz> get_shares(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, ISP& isp, BICYCL::Mpz secret) {
    Array<BICYCL::Mpz> rho = compute_rho(secret, isp.cols);
    return compute_shares(isp, rho);
}

Matrix<BICYCL::CL_HSM2k::CipherText> encrypt_shares(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, Matrix<BICYCL::Mpz>& shares) {
    Matrix<BICYCL::CL_HSM2k::CipherText> encrypted_shares(shares.size(), std::vector<BICYCL::CL_HSM2k::CipherText>(shares[0].size()));
    for (int i = 0; i < shares.size(); i++) {
        for (int j = 0; j < shares[0].size(); j++) {
            encrypted_shares[i][j] = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, shares[i][j]), randgen);
        }
    }
    return encrypted_shares;
}

Array<BICYCL::Mpz> compute_lambda(int t) {
    Array<BICYCL::Mpz> lambda{BICYCL::Mpz((unsigned long)(1))};
    for (int i = 0; i < t; i++) {
        lambda.push_back(BICYCL::Mpz((long)(-1)));
    }

    return lambda;
}

BICYCL::QFI compute_d(BICYCL::CL_HSM2k& hsm2k, Array<BICYCL::QFI>& ds, Array<BICYCL::Mpz>& lambda, Array<int>& threshold_parties) {
    BICYCL::QFI d;
    for (int i = 0; i < ds.size(); i++) {
        BICYCL::QFI r;
        hsm2k.Cl_G().nupow(r, ds[i], lambda[i]);
        hsm2k.Cl_G().nucomp(d, d, r);
    }
    return d;
}

int get_threshold_combination_number(Array<int> threshold_parties) {
    std::sort(threshold_parties.begin(), threshold_parties.end());

    int threshold_combination_number = 0;
    int running_party_num = 0;
    for (int party_num : threshold_parties) {
        threshold_combination_number += party_num - running_party_num;
        running_party_num = party_num + 1;
    }
}

LISSKeyGen keygen(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, AccessStructure& A, BICYCL::CL_HSM2k::SecretKey& sk, BICYCL::CL_HSM2k::PublicKey& pk) {
    ISP isp = generate_isp(A);

    // Beaver's Triplet generation: 
    int a = 15, b = 35, c = a * b;
    auto a_shares = get_shares(hsm2k, randgen, isp, BICYCL::Mpz((unsigned long)(a)));
    auto b_shares = get_shares(hsm2k, randgen, isp, BICYCL::Mpz((unsigned long)(b)));
    auto c_shares = get_shares(hsm2k, randgen, isp, BICYCL::Mpz((unsigned long)(c)));

    LISSKeyGen keygen;
    keygen.A = A;
    keygen.secret_key_shares = get_shares(hsm2k, randgen, isp, sk);
    keygen.beaver_triplet_a_shares = encrypt_shares(hsm2k, randgen, pk, a_shares);
    keygen.beaver_triplet_b_shares = encrypt_shares(hsm2k, randgen, pk, b_shares);;
    keygen.beaver_triplet_c_shares = encrypt_shares(hsm2k, randgen, pk, c_shares);;

    return keygen;
}

BICYCL::QFI partDecrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, BICYCL::Mpz& ski) {
    BICYCL::QFI di;
    hsm2k.Cl_G().nupow (di, ct.c1(), ski);   // di = c1^sj
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta (di);

    return di;
}

BICYCL::CL_HSM2k::ClearText finalDecrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, Array<BICYCL::QFI>& ds, LISSKeyGen& lk, Array<int>& threshold_parties) {
    
    Array<BICYCL::Mpz> lambda = compute_lambda(lk.A.t);

    BICYCL::QFI d = compute_d(hsm2k, ds, lambda, threshold_parties);

    BICYCL::QFI r;
    hsm2k.Cl_Delta().nucompinv (r, ct.c2(), d); /* c2 . d^-1 */

    auto v = hsm2k.dlog_in_F(r);
    return BICYCL::CL_HSM2k::ClearText(hsm2k, v);
}

BICYCL::CL_HSM2k::ClearText decrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, LISSKeyGen& lk, Array<int>& threshold_parties) {
    auto sk_shares = lk.secret_key_shares;

    int threshold_combination_number = get_threshold_combination_number(threshold_parties);
    Array<BICYCL::QFI> ds(threshold_parties.size());
    for (int i = 0; i < threshold_parties.size(); i++) {
        ds[i] = partDecrypt(hsm2k, ct, sk_shares[threshold_combination_number][i]);
    }

    return finalDecrypt(hsm2k, ct, ds, lk, threshold_parties);
}

// Ciphertext Multiplication: You can multiply two ciphertexts homomorphically.
BICYCL::CL_HSM2k::CipherText ciphertext_multiplication(
    BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, LISSKeyGen& lk, Array<int>& threshold_parties,
    BICYCL::CL_HSM2k::CipherText& x1_e, BICYCL::CL_HSM2k::CipherText& y1_e, BICYCL::CL_HSM2k::CipherText& x2_e, BICYCL::CL_HSM2k::CipherText& y2_e
) {
    std::cout << "\nCiphertext Multiplication:" << std::endl;
    // Lambda values: beavers triplet shares are not additive. They are LISS shares and hence are reconstructed using lambda values
    auto lambda = compute_lambda(lk.A.t);
    int threshold_combination_number = get_threshold_combination_number(threshold_parties);

    // Beaver's triplet for given threshold parties
    auto a1_e = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_a_shares[threshold_combination_number][0], lambda[0], randgen);
    auto b1_e = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_b_shares[threshold_combination_number][0], lambda[0], randgen);
    auto c1_e = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_c_shares[threshold_combination_number][0], lambda[0], randgen);
    auto a2_e = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_a_shares[threshold_combination_number][1], lambda[1], randgen);
    auto b2_e = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_b_shares[threshold_combination_number][1], lambda[1], randgen);
    auto c2_e = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_c_shares[threshold_combination_number][1], lambda[1], randgen);


    // Calculate e and d values
    auto e1 = hsm2k.add_ciphertexts(pk, x1_e, hsm2k.scal_ciphertexts(pk, a1_e, BICYCL::Mpz((long)(-1)), randgen), randgen);
    auto d1 = hsm2k.add_ciphertexts(pk, y1_e, hsm2k.scal_ciphertexts(pk, b1_e, BICYCL::Mpz((long)(-1)), randgen), randgen);
    auto e2 = hsm2k.add_ciphertexts(pk, x2_e, hsm2k.scal_ciphertexts(pk, a2_e, BICYCL::Mpz((long)(-1)), randgen), randgen);
    auto d2 = hsm2k.add_ciphertexts(pk, y2_e, hsm2k.scal_ciphertexts(pk, b2_e, BICYCL::Mpz((long)(-1)), randgen), randgen);

    // Combine e and d values
    auto e = hsm2k.add_ciphertexts(pk, e1, e2, randgen);
    auto d = hsm2k.add_ciphertexts(pk, d1, d2, randgen);
    auto e_d = decrypt(hsm2k, e, lk, threshold_parties);
    auto d_d = decrypt(hsm2k, d, lk, threshold_parties);
    int e_d_int = (int)mpz_get_ui(e_d.operator const __mpz_struct*());
    int d_d_int = (int)mpz_get_ui(d_d.operator const __mpz_struct*());

    // Calculate r1 and r2
    auto r1_e = hsm2k.add_ciphertexts(
        pk, 
        c1_e,
        hsm2k.add_ciphertexts(
            pk,
            hsm2k.add_ciphertexts(
                pk, 
                hsm2k.scal_ciphertexts(pk, b1_e, e_d, randgen),
                hsm2k.scal_ciphertexts(pk, a1_e, d_d, randgen), 
                randgen
            ),
            hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(e_d_int * d_d_int))), randgen), 
            randgen
        ), 
        randgen
    );

    auto r2_e = hsm2k.add_ciphertexts(
        pk, 
        c2_e,
        hsm2k.add_ciphertexts(
            pk, 
            hsm2k.scal_ciphertexts(pk, b2_e, e_d, randgen),
            hsm2k.scal_ciphertexts(pk, a2_e, d_d, randgen), 
            randgen
        ), 
        randgen
    );

    // Final result of encrypted multiplication
    auto r = hsm2k.add_ciphertexts(pk, r1_e, r2_e, randgen);
    auto r_d = mpz_get_ui(decrypt(hsm2k, r, lk, threshold_parties).operator const __mpz_struct *());

    std::cout << "Final result (r): " << r_d << std::endl;

    return r;
}

// 2-degree Polynomial Evaluation: ax^2 + bx + c where a,b,c are constants and x is ciphertext
void two_degree_polynomial_evaluation(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, LISSKeyGen& lk, Array<int>& threshold_parties) {
    std::cout << "\nHomomorphic Two-Degree Polynomial Evaluation:" << std::endl;

    int a = 9, b = 10, c = 7, x1 = 3, x2 = 7;
    
    auto x1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x1))), randgen);
    auto x2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x2))), randgen);
    auto x_e = hsm2k.add_ciphertexts(pk, x1_e, x2_e, randgen);
    auto x_e_square = ciphertext_multiplication(hsm2k, randgen, pk, lk, threshold_parties, x1_e, x1_e, x2_e, x2_e);

    auto a_x_square = hsm2k.scal_ciphertexts(pk, x_e_square, BICYCL::Mpz((unsigned long)a), randgen);
    auto b_x = hsm2k.scal_ciphertexts(pk, x_e, BICYCL::Mpz((unsigned long)b), randgen);

    auto result_e = hsm2k.add_ciphertexts(
        pk, 
        a_x_square, 
        hsm2k.add_ciphertexts(
            pk, 
            b_x, 
            hsm2k.encrypt(
                pk, 
                BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)c)), 
                randgen
            ), 
            randgen
        ), 
        randgen
    );

    // Decrypt result
    BICYCL::CL_HSM2k::ClearText result_d = decrypt(hsm2k, result_e, lk, threshold_parties);
    int result_value = (int)mpz_get_ui(result_d.operator const __mpz_struct*());

    std::cout << "x = " << x1 + x2 << ", a = " << a << ", b = " << b << ", c = " << c << std::endl;
    std::cout << "Homomorphic two-degree polynomial evaluation result: " << result_value << std::endl;
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

    AccessStructure A(2, 3);
    Array<int> threshold_parties{0,2};
    LISSKeyGen lk = keygen(hsm2k, randgen, A, sk, pk);
    
    // 2) Ciphertext Addition
    ciphertext_addition(hsm2k,randgen, sk, pk);

    // 3) Scalar Multiplication
    scalar_multiplication(hsm2k, randgen, sk, pk);

    // 4) Decryption using part decrypt
    std::cout << "Decryption using Part Decrypt: " << std::endl;
    int value = 39;
    auto value_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(value))), randgen);
    auto value_d = decrypt(hsm2k, value_e, lk, threshold_parties);
    int value_d_int = (int)mpz_get_ui(value_d.operator const __mpz_struct*());
    std::cout << "Original value: " << value << std::endl;
    std::cout << "Decrypted value: " << value_d_int << std::endl;

    // 3) Ciphertext Multiplication
    // Secret shares of x = 20 and y = 30
    int x1 = 3, y1 = 10, x2 = 15, y2 = 2;
    auto x1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x1))), randgen);
    auto y1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y1))), randgen);
    auto x2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x2))), randgen);
    auto y2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y2))), randgen);
    ciphertext_multiplication(hsm2k, randgen, pk, lk, threshold_parties, x1_e, y1_e, x2_e, y2_e);

    // 4) 2-degree Polynomial Evaluation
    two_degree_polynomial_evaluation(hsm2k, randgen, pk, lk, threshold_parties);
}

int main() {
    homomorphic_operations();
    return 0;
}
