#include <iostream>
#include <bicycl.hpp>
#include <gmp.h>
#include <vector>

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
    AccessStructure(int t, int n) : t(t), n(n) {}
};

typedef struct {
    std::vector<std::vector<int> > M;
    std::vector<std::vector<int> > Sie;
    int rows;
    int cols;
} ISP;

typedef struct {
    BICYCL::CL_HSM2k::PublicKey* pk;
    std::vector<BICYCL::Mpz> shares;
    ISP isp;
} LISSKeyGen;

// Function to generate a random matrix M (d x e) with 0s and 1s
ISP generate_isp(AccessStructure& A) {
    // @TODO: Implement code for generating M and Sie for any A

    // this is temporary code
    int n = A.n, t = A.t;

    // calculated M for 2 of 3 
    std::vector<std::vector<int> > M{
        {1,1,0,0},
        {0,1,0,0},
        {1,0,1,0},
        {0,0,1,0},
        {1,0,0,1},
        {0,0,0,1}
    };
    // calculated Sie for above M
    std::vector<std::vector<int> > Sie{{0,2},{1,4},{3,5}};

    ISP isp;
    isp.M = M;
    isp.Sie = Sie;
    isp.rows = M.size();
    isp.cols = M[0].size();

    return isp;
}

std::vector<BICYCL::Mpz> compute_rho(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::SecretKey& sk, BICYCL::RandGen& randgen, int e) {
    std::vector<BICYCL::Mpz> rho(e);
    rho[0] = sk;  // Set ρ(0) = sk as per the algorithm
    for (int i = 1; i < e; i++) {
        rho[i] = BICYCL::Mpz((unsigned long)(i));   // This should be random value in range [-2^(l0+λ), 2^(l0+λ)]^(e−1)
    }

    return rho;
}

std::vector<BICYCL::Mpz> compute_shares(ISP& isp, std::vector<BICYCL::Mpz>& rho) {
    std::vector<std::vector<int> >& M = (isp.M);
    int rows = isp.rows, cols = isp.cols;

    std::vector<BICYCL::Mpz> shares;
    /*
        DOUBT:
            For 2 of 3 Access Structure, we have 6 * 4 matrix of which multiple rows belong to one party 
            i.e., one party owns multiple rows of a matrix. See Section 3.3.1 from https://cs.au.dk/fileadmin/site_files/cs/PhD/PhD_Dissertations__pdf/Thesis-RIT.pdf

            As per algorithm 8 of https://eprint.iacr.org/2022/1143.pdf, we need to calculate n shares where n is supposed to be number of parties
            As per algo, ith share, ski = (Mj . rho) where j = SieInverse(i) i.e, j is the row number which ith party owns BUT THERE CAN BE MULTIPLE ROWS
            SO THE DOUBT IS WHICH ROW TO PICK

            For now, shares are calculated as per rows, i.e., we calculate a share for each row so here multiple shares will belong to a single party
    */
    for (int i = 0; i < rows; i++) {
        BICYCL::Mpz ski(BICYCL::Mpz((unsigned long)(0)));
        for (int j = 0; j < cols; j++) {
             // ski = (Mj · rho)   Need to check what dot product here gives
             // for now, corresponding elments are multiplied and then added to get a single value final result
            BICYCL::Mpz mult;
            ski.mul(mult, rho[j], BICYCL::Mpz((unsigned long)(M[i][j])));
            ski.add(ski, ski, mult);
        }
        shares.push_back(ski);
    }
    return shares;
}

std::vector<BICYCL::Mpz> compute_lambda(BICYCL::CL_HSM2k& hsm2k, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    // @TODO: Implement code for computing lambda as per Access Structure and threshold_parties

    // calculate lambda for 2 of 3 Access Structure and [0,2] i.e., P1, P3 threshold parties 
    std::vector<BICYCL::Mpz> lamda{
        BICYCL::Mpz((long)(0)),
        BICYCL::Mpz((long)(0)),
        BICYCL::Mpz((long)(1)),
        BICYCL::Mpz((long)(-1)),
        BICYCL::Mpz((long)(0)),
        BICYCL::Mpz((long)(0))
    };
    return lamda;
}

BICYCL::QFI compute_d(BICYCL::CL_HSM2k& hsm2k, std::vector<std::vector<BICYCL::QFI> >& ds, std::vector<BICYCL::Mpz>& lambda, std::vector<std::vector<int> >& Sie) {
    /*
        Multiplied each part decrypt with the corresponsing lambda
        Not sure if this correct. This will get clear once compute_shares doubt is resolved
    */

    BICYCL::QFI d = hsm2k.Cl_G().one();     // intializing with value 1, not sure if this correct
    for (int i = 0; i < ds.size(); i++) {
        for (int j = 0; j < ds[i].size(); j++) {
            BICYCL::QFI dij = ds[i][j];
            BICYCL::QFI r;
            hsm2k.Cl_G().nupow(r, dij, lambda[Sie[i][j]]);
            if (hsm2k.compact_variant())
                hsm2k.from_Cl_DeltaK_to_Cl_Delta (r);
            hsm2k.Cl_G().nucomp(d, d, r);
        }
    }
    return d;
}

LISSKeyGen keygen(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, AccessStructure& A, BICYCL::CL_HSM2k::SecretKey& sk, BICYCL::CL_HSM2k::PublicKey& pk) {
    ISP isp = generate_isp(A);

    std::vector<BICYCL::Mpz> rho = compute_rho(hsm2k, sk, randgen, isp.cols);
    
    std::vector<BICYCL::Mpz> shares = compute_shares(isp, rho);

    LISSKeyGen keygen;
    keygen.shares = shares;
    keygen.isp = isp;

    return keygen;
}

BICYCL::QFI partDecrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, BICYCL::Mpz& ski) {
    BICYCL::QFI di;
    BICYCL::CL_HSM2k::SecretKey sj(hsm2k, ski);
    hsm2k.Cl_G().nupow (di, ct.c1(), sj);   // di = c1^sj
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta (di);

    return di;
}

BICYCL::CL_HSM2k::ClearText finalDecrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, std::vector<std::vector<BICYCL::QFI> >& ds, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    
    std::vector<BICYCL::Mpz> lambda = compute_lambda(hsm2k, lk, threshold_parties);

    BICYCL::QFI d = compute_d(hsm2k, ds, lambda, (lk.isp.Sie));

    BICYCL::QFI r;
    hsm2k.Cl_Delta().nucompinv (r, ct.c2(), d); /* c2 . d^-1 */

    auto v = hsm2k.dlog_in_F(r);    // This is giving error as invalid argument, which I think means value is not decrypted correctly
    return BICYCL::CL_HSM2k::ClearText(hsm2k, v);
}

BICYCL::CL_HSM2k::ClearText decrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    auto Sie = lk.isp.Sie;
    auto sk_shares = lk.shares;

    /*
        For each threshold party, part decrypts are calculated for each secret share they own
        This will get clear once compute_share doubt is resolved
    */
    std::vector<std::vector<BICYCL::QFI> > ds(Sie.size());
    for (int p : threshold_parties) {
        for (int rowNum : Sie[p]) {
            auto di = partDecrypt(hsm2k, ct, sk_shares[rowNum]);
            ds[p].push_back(di);
        }
    }

    return finalDecrypt(hsm2k, ct, ds, lk, threshold_parties);
}

// Ciphertext Multiplication: You can multiply two ciphertexts homomorphically.
void ciphertext_multiplication(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    std::cout << "\nCiphertext Multiplication:" << std::endl;
    
    // Secret shares of x = 20 and y = 30
    int x1 = 5, y1 = 10, x2 = 15, y2 = 20;
    auto x1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x1))), randgen);
    auto y1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y1))), randgen);
    auto x2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x2))), randgen);
    auto y2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y2))), randgen);

    // Beaver's Triplet generation
    int a1 = 5, a2 = 10, b1 = 15, b2 = 20;
    auto a1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(a1))), randgen);
    auto a2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(a2))), randgen);
    auto b1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(b1))), randgen);
    auto b2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(b2))), randgen);

    // Calculate c = (a1 + a2) * (b1 + b2)
    int c = (a1 + a2) * (b1 + b2);
    int c1 = c / 5, c2 = c - c1;
    auto c1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(c1))), randgen);
    auto c2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(c2))), randgen);

    // Calculate e and d values
    auto e1 = hsm2k.add_ciphertexts(pk, x1_e, hsm2k.scal_ciphertexts(pk, a1_e, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(-1))), randgen), randgen);
    auto d1 = hsm2k.add_ciphertexts(pk, y1_e, hsm2k.scal_ciphertexts(pk, b1_e, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(-1))), randgen), randgen);
    auto e2 = hsm2k.add_ciphertexts(pk, x2_e, hsm2k.scal_ciphertexts(pk, a2_e, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(-1))), randgen), randgen);
    auto d2 = hsm2k.add_ciphertexts(pk, y2_e, hsm2k.scal_ciphertexts(pk, b2_e, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(-1))), randgen), randgen);

    // Combine e and d values
    auto e = hsm2k.add_ciphertexts(pk, e1, e2, randgen);
    auto d = hsm2k.add_ciphertexts(pk, d1, d2, randgen);
    auto e_d = decrypt(hsm2k, e, lk, threshold_parties);
    auto d_d = decrypt(hsm2k, d, lk, threshold_parties);
    int e_d_int = (int)mpz_get_ui(e_d.operator const __mpz_struct*());
    int d_d_int = (int)mpz_get_ui(d_d.operator const __mpz_struct*());

    // Calculate r1 and r2
    auto r1_e = hsm2k.add_ciphertexts(pk, c1_e,
        hsm2k.add_ciphertexts(pk,
            hsm2k.add_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, b1_e, e_d, randgen),
            hsm2k.scal_ciphertexts(pk, a1_e, d_d, randgen), randgen),
            hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(e_d_int * d_d_int))), randgen), randgen), randgen);

    auto r2_e = hsm2k.add_ciphertexts(pk, c2_e,
        hsm2k.add_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, b2_e, e_d, randgen),
        hsm2k.scal_ciphertexts(pk, a2_e, d_d, randgen), randgen), randgen);

    // Final result of encrypted multiplication
    auto r = hsm2k.add_ciphertexts(pk, r1_e, r2_e, randgen);
    auto r_d = mpz_get_ui(decrypt(hsm2k, r, lk, threshold_parties).operator const __mpz_struct *());

    std::cout << "x = " << x1 + x2 << ", y = " << y1 + y2 << std::endl;
    std::cout << "Final result (r): " << r_d << std::endl;
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
    std::vector<int> threshold_parties{0,2};
    LISSKeyGen lk = keygen(hsm2k, randgen, A, sk, pk);
    
    // 2) Ciphertext Addition
    ciphertext_addition(hsm2k,randgen, sk, pk);

    // 3) Scalar Multiplication
    scalar_multiplication(hsm2k, randgen, sk, pk);

    // 3) Ciphertext Multiplication
    ciphertext_multiplication(hsm2k, randgen, pk, lk, threshold_parties);
}

int main() {
    homomorphic_operations();
    return 0;
}
