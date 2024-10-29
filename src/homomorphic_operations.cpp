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
    ISP isp;
    std::vector<std::vector<BICYCL::Mpz> > secret_key_shares;
    std::vector<std::vector<BICYCL::CL_HSM2k::CipherText> > beaver_triplet_a_shares;
    std::vector<std::vector<BICYCL::CL_HSM2k::CipherText> > beaver_triplet_b_shares;
    std::vector<std::vector<BICYCL::CL_HSM2k::CipherText> > beaver_triplet_c_shares;
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
    // calculated Sie for above M: -1 is dummy
    std::vector<std::vector<int> > Sie{{-1,0,2},{1,-1,4},{3,5,-1}};

    ISP isp;
    isp.M = M;
    isp.Sie = Sie;
    isp.rows = M.size();
    isp.cols = M[0].size();

    return isp;
}

std::vector<BICYCL::Mpz> compute_rho(BICYCL::CL_HSM2k& hsm2k, BICYCL::Mpz& secret, BICYCL::RandGen& randgen, int e) {
    std::vector<BICYCL::Mpz> rho(e);
    rho[0] = secret;  // Set ρ(0) = s as per the algorithm
    for (int i = 1; i < e; i++) {
        rho[i] = BICYCL::Mpz((unsigned long)(i));   // This should be random value in range [-2^(l0+λ), 2^(l0+λ)]^(e−1)
    }

    return rho;
}

std::vector<std::vector<BICYCL::Mpz> > compute_shares(ISP& isp, std::vector<BICYCL::Mpz>& rho) {
    std::vector<std::vector<int> >& M = isp.M;
    std::vector<std::vector<int> >& Sie = isp.Sie;
    int rows = isp.rows, cols = isp.cols;

    // std::vector<BICYCL::Mpz> shares;
    /*
        DOUBT:
            For 2 of 3 Access Structure, we have 6 * 4 matrix of which multiple rows belong to one party 
            i.e., one party owns multiple rows of a matrix. See Section 3.3.1 from https://cs.au.dk/fileadmin/site_files/cs/PhD/PhD_Dissertations__pdf/Thesis-RIT.pdf

            As per algorithm 8 of https://eprint.iacr.org/2022/1143.pdf, we need to calculate n shares where n is supposed to be number of parties
            As per algo, ith share, ski = (Mj . rho) where j = SieInverse(i) i.e, j is the row number which ith party owns BUT THERE CAN BE MULTIPLE ROWS
            SO THE DOUBT IS WHICH ROW TO PICK

            For now, shares are calculated as per rows, i.e., we calculate a share for each row so here multiple shares will belong to a single party
    */
    // for (int i = 0; i < rows; i++) {
    //     BICYCL::Mpz ski(BICYCL::Mpz((unsigned long)(0)));
    //     for (int j = 0; j < cols; j++) {
    //          // ski = (Mj · rho)   Need to check what dot product here gives
    //          // for now, corresponding elments are multiplied and then added to get a single value final result
    //         BICYCL::Mpz mult;
    //         ski.mul(mult, rho[j], BICYCL::Mpz((unsigned long)(M[i][j])));
    //         ski.add(ski, ski, mult);
    //     }
    //     shares.push_back(ski);
    // }

    std::cout << "Shares: " << std::endl;
    std::vector<std::vector<BICYCL::Mpz> > sharesi;
    for (auto Sp : Sie) {
        std::vector<BICYCL::Mpz> si;
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

std::vector<std::vector<BICYCL::Mpz> > get_shares(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, ISP& isp, BICYCL::Mpz secret) {
    std::vector<BICYCL::Mpz> rho = compute_rho(hsm2k, secret, randgen, isp.cols);
    return compute_shares(isp, rho);
}

std::vector<std::vector<BICYCL::CL_HSM2k::CipherText> > encrypt_shares(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, std::vector<std::vector<BICYCL::Mpz> >& shares) {
    std::vector<std::vector<BICYCL::CL_HSM2k::CipherText> > encrypted_shares(shares.size(), std::vector<BICYCL::CL_HSM2k::CipherText>(shares[0].size()));
    for (int i = 0; i < shares.size(); i++) {
        for (int j = 0; j < shares[0].size(); j++) {
            encrypted_shares[i][j] = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, shares[i][j]), randgen);
        }
    }
    return encrypted_shares;
}

std::vector<std::vector<BICYCL::Mpz> > compute_lambda(BICYCL::CL_HSM2k& hsm2k, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    // @TODO: Implement code for computing lambda as per Access Structure and threshold_parties

    // calculate lambda for 2 of 3 Access Structure and [0,2] i.e., P1, P3 threshold parties 
    std::vector<std::vector<BICYCL::Mpz> > lamda{
        {BICYCL::Mpz((unsigned long)(0)), BICYCL::Mpz((unsigned long)(0)), BICYCL::Mpz((unsigned long)(1))},
        {BICYCL::Mpz((unsigned long)(0)), BICYCL::Mpz((unsigned long)(0)), BICYCL::Mpz((unsigned long)(0))},
        {BICYCL::Mpz((long)(-1)), BICYCL::Mpz((unsigned long)(0)), BICYCL::Mpz((unsigned long)(0))}
    };
    return lamda;
}

BICYCL::QFI compute_d(BICYCL::CL_HSM2k& hsm2k, std::vector<BICYCL::QFI>& ds, std::vector<std::vector<BICYCL::Mpz> >& lambda, std::vector<int>& threshold_parties) {
    /*
        Multiplied each part decrypt with the corresponsing lambda
        Not sure if this correct. This will get clear once compute_shares doubt is resolved
    */

    BICYCL::QFI d;     // intializing with value 1, not sure if this correct
    for (int i = 0; i < ds.size(); i++) {
        BICYCL::QFI r;
        hsm2k.Cl_G().nupow(r, ds[i], lambda[threshold_parties[0]][threshold_parties[1]]);
        for (int j = 0; j < ds[i].size(); j++) {
            BICYCL::QFI dij = ds[i][j];
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

    // Beaver's Triplet generation: 
    int a = 15, b = 35, c = a * b;
    auto a_shares = get_shares(hsm2k, randgen, isp, BICYCL::Mpz((unsigned long)(a)));
    auto b_shares = get_shares(hsm2k, randgen, isp, BICYCL::Mpz((unsigned long)(b)));
    auto c_shares = get_shares(hsm2k, randgen, isp, BICYCL::Mpz((unsigned long)(c)));

    LISSKeyGen keygen;
    keygen.isp = isp;
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

BICYCL::CL_HSM2k::ClearText finalDecrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, std::vector<BICYCL::QFI>& ds, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    
    std::vector<std::vector<BICYCL::Mpz> > lambda = compute_lambda(hsm2k, lk, threshold_parties);

    // BICYCL::QFI d = compute_d(hsm2k, ds, lambda, (lk.isp.Sie));

    BICYCL::QFI d;
    hsm2k.Cl_Delta().nupow(d, ds[0], lambda[threshold_parties[0]][threshold_parties[1]]);
    // if (hsm2k.compact_variant())
    //     hsm2k.from_Cl_DeltaK_to_Cl_Delta (d);
    BICYCL::QFI temp;
    hsm2k.Cl_Delta().nupow(temp, ds[1], lambda[threshold_parties[1]][threshold_parties[0]]);
    // if (hsm2k.compact_variant())
    //     hsm2k.from_Cl_DeltaK_to_Cl_Delta (temp);

    hsm2k.Cl_Delta().nucomp(d, d, temp);
    // hsm2k.Cl_Delta().nucompinv(d, ds[0], ds[1]);

    BICYCL::QFI r;
    hsm2k.Cl_Delta().nucompinv (r, ct.c2(), d); /* c2 . d^-1 */

    auto v = hsm2k.dlog_in_F(r);    // This is giving error as invalid argument, which I think means value is not decrypted correctly
    return BICYCL::CL_HSM2k::ClearText(hsm2k, v);
}

BICYCL::CL_HSM2k::ClearText decrypt(BICYCL::CL_HSM2k& hsm2k, BICYCL::CL_HSM2k::CipherText& ct, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
    auto Sie = lk.isp.Sie;
    auto sk_shares = lk.secret_key_shares;

    /*
        For each threshold party, part decrypts are calculated for each secret share they own
        This will get clear once compute_share doubt is resolved
    */
    // std::vector<std::vector<BICYCL::QFI> > ds(Sie.size());
    // for (int p : threshold_parties) {
    //     for (int rowNum : Sie[p]) {
    //         auto di = partDecrypt(hsm2k, ct, sk_shares[rowNum]);
    //         ds[p].push_back(di);
    //     }
    // }

    std::vector<BICYCL::QFI> ds(threshold_parties.size());
    ds[0] = partDecrypt(hsm2k, ct, sk_shares[threshold_parties[0]][threshold_parties[1]]);
    ds[1] = partDecrypt(hsm2k, ct, sk_shares[threshold_parties[1]][threshold_parties[0]]);

    return finalDecrypt(hsm2k, ct, ds, lk, threshold_parties);
}

// Ciphertext Multiplication: You can multiply two ciphertexts homomorphically.
BICYCL::CL_HSM2k::CipherText ciphertext_multiplication(
    BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, LISSKeyGen& lk, std::vector<int>& threshold_parties,
    BICYCL::CL_HSM2k::CipherText& x1_e, BICYCL::CL_HSM2k::CipherText& y1_e, BICYCL::CL_HSM2k::CipherText& x2_e, BICYCL::CL_HSM2k::CipherText& y2_e
) {
    std::cout << "\nCiphertext Multiplication:" << std::endl;

    // Beaver's triplet for given threshold parties
    auto a1_e = lk.beaver_triplet_a_shares[threshold_parties[0]][threshold_parties[1]];
    auto a2_e = lk.beaver_triplet_a_shares[threshold_parties[1]][threshold_parties[0]];
    auto b1_e = lk.beaver_triplet_b_shares[threshold_parties[0]][threshold_parties[1]];
    auto b2_e = lk.beaver_triplet_b_shares[threshold_parties[1]][threshold_parties[0]];
    auto c1_e = lk.beaver_triplet_c_shares[threshold_parties[0]][threshold_parties[1]];
    auto c2_e = lk.beaver_triplet_c_shares[threshold_parties[1]][threshold_parties[0]];

    // Lambda values: beavers triplet shares are not additive. They are LISS shares and hence are reconstructed using lambda values
    auto lambda = compute_lambda(hsm2k, lk, threshold_parties);

    // Calculate e and d values
    auto e1 = hsm2k.add_ciphertexts(pk, x1_e, hsm2k.scal_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, a1_e, lambda[threshold_parties[0]][threshold_parties[1]], randgen), BICYCL::Mpz((unsigned long)(-1)), randgen), randgen);
    auto d1 = hsm2k.add_ciphertexts(pk, y1_e, hsm2k.scal_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, b1_e, lambda[threshold_parties[0]][threshold_parties[1]], randgen), BICYCL::Mpz((unsigned long)(-1)), randgen), randgen);
    auto e2 = hsm2k.add_ciphertexts(pk, x2_e, hsm2k.scal_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, a2_e, lambda[threshold_parties[1]][threshold_parties[0]], randgen), BICYCL::Mpz((unsigned long)(-1)), randgen), randgen);
    auto d2 = hsm2k.add_ciphertexts(pk, y2_e, hsm2k.scal_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, b2_e, lambda[threshold_parties[1]][threshold_parties[0]], randgen), BICYCL::Mpz((unsigned long)(-1)), randgen), randgen);

    // Combine e and d values
    auto e = hsm2k.add_ciphertexts(pk, e1, e2, randgen);
    auto d = hsm2k.add_ciphertexts(pk, d1, d2, randgen);
    auto e_d = decrypt(hsm2k, e, lk, threshold_parties);
    auto d_d = decrypt(hsm2k, d, lk, threshold_parties);
    int e_d_int = (int)mpz_get_ui(e_d.operator const __mpz_struct*());
    int d_d_int = (int)mpz_get_ui(d_d.operator const __mpz_struct*());

    // Calculate r1 and r2
    auto r1_e = hsm2k.add_ciphertexts(pk, 
        hsm2k.scal_ciphertexts(pk, c1_e, lambda[threshold_parties[0]][threshold_parties[1]], randgen),
        hsm2k.add_ciphertexts(pk,
            hsm2k.add_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, b1_e, e_d, randgen),
            hsm2k.scal_ciphertexts(pk, a1_e, d_d, randgen), randgen),
            hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(e_d_int * d_d_int))), randgen), randgen), randgen);

    auto r2_e = hsm2k.add_ciphertexts(pk, 
        hsm2k.scal_ciphertexts(pk, c2_e, lambda[threshold_parties[1]][threshold_parties[0]], randgen),
        hsm2k.add_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, b2_e, e_d, randgen),
        hsm2k.scal_ciphertexts(pk, a2_e, d_d, randgen), randgen), randgen);

    // Final result of encrypted multiplication
    auto r = hsm2k.add_ciphertexts(pk, r1_e, r2_e, randgen);
    auto r_d = mpz_get_ui(decrypt(hsm2k, r, lk, threshold_parties).operator const __mpz_struct *());

    std::cout << "Final result (r): " << r_d << std::endl;

    return r;
}

BICYCL::CL_HSM2k::CipherText ciphertext_multiplication_old(
    BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, LISSKeyGen& lk, std::vector<int>& threshold_parties, 
    BICYCL::CL_HSM2k::CipherText& x1_e, BICYCL::CL_HSM2k::CipherText& y1_e, BICYCL::CL_HSM2k::CipherText& x2_e, BICYCL::CL_HSM2k::CipherText& y2_e, bool print_result = true) {
    if (print_result)   std::cout << "\nCiphertext Multiplication:" << std::endl;
    
    // // Secret shares of x = 20 and y = 30
    // int x1 = 5, y1 = 10, x2 = 15, y2 = 20;
    // auto x1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x1))), randgen);
    // auto y1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y1))), randgen);
    // auto x2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x2))), randgen);
    // auto y2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y2))), randgen);

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

    // auto a1_e = lk.beaver_triplet_a[threshold_parties[0]][threshold_parties[1]];
    // auto a2_e = lk.beaver_triplet_a[threshold_parties[1]][threshold_parties[0]];
    // auto b1_e = lk.beaver_triplet_b[threshold_parties[0]][threshold_parties[1]];
    // auto b2_e = lk.beaver_triplet_b[threshold_parties[1]][threshold_parties[0]];
    // auto c1_e = lk.beaver_triplet_c[threshold_parties[0]][threshold_parties[1]];
    // auto c2_e = lk.beaver_triplet_c[threshold_parties[1]][threshold_parties[0]];

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

    if (print_result) {
        // std::cout << "x = " << x1 + x2 << ", y = " << y1 + y2 << std::endl;
        std::cout << "Final result (r): " << r_d << std::endl;
    }

    return r;
}

// 2-degree Polynomial Evaluation: ax^2 + bx + c where a,b,c are constants and x is ciphertext
void two_degree_polynomial_evaluation(BICYCL::CL_HSM2k& hsm2k, BICYCL::RandGen& randgen, BICYCL::CL_HSM2k::PublicKey& pk, LISSKeyGen& lk, std::vector<int>& threshold_parties) {
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
    std::vector<int> threshold_parties{0,2};
    LISSKeyGen lk = keygen(hsm2k, randgen, A, sk, pk);
    
    // 2) Ciphertext Addition
    ciphertext_addition(hsm2k,randgen, sk, pk);

    // 3) Scalar Multiplication
    scalar_multiplication(hsm2k, randgen, sk, pk);

    // encryption & decyption using part decrypt
    int temp = 23;
    auto temp_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(temp))), randgen);
    auto temp_d = decrypt(hsm2k, temp_e, lk, threshold_parties);
    int result_value = (int)mpz_get_ui(temp_d.operator const __mpz_struct*());
    std::cout << "temp dec value: " << result_value << std::endl;


    // 3) Ciphertext Multiplication
    // Secret shares of x = 20 and y = 30
    int x1 = 5, y1 = 10, x2 = 15, y2 = 20;
    auto x1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x1))), randgen);
    auto y1_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y1))), randgen);
    auto x2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x2))), randgen);
    auto y2_e = hsm2k.encrypt(pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y2))), randgen);
    ciphertext_multiplication(hsm2k, randgen, pk, lk, threshold_parties, x1_e, y1_e, x2_e, y2_e);

    // 4) 2-degree Polynomial Evaluation
    // two_degree_polynomial_evaluation(hsm2k, randgen, pk, lk, threshold_parties);

    // auto lambda = compute_lambda(hsm2k, lk, threshold_parties);
    // auto a1 = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_a_shares[0][2], lambda[0][2], randgen);
    // auto a2 = hsm2k.scal_ciphertexts(pk, lk.beaver_triplet_a_shares[2][0], lambda[2][0], randgen);
    // auto a = hsm2k.add_ciphertexts(pk, a1, a2, randgen);
    // auto a_d = decrypt(hsm2k, a, lk, threshold_parties);
    // int result_a = (int)mpz_get_ui(a_d.operator const __mpz_struct*());
    // std::cout << "a dec value: " << result_a << std::endl;
}

int main() {
    homomorphic_operations();
    return 0;
}
