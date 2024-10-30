#include <bicycl.hpp>
#include <gmp.h>
#include <iostream>
#include <vector>

template <typename T> using Matrix = std::vector<std::vector<T>>;

template <typename T> using Array = std::vector<T>;

/******************************************************************************************************************************/
/* LISS START */
/******************************************************************************************************************************/
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

  // Fill in the first column with c(a) following db zeros & second column with
  // c(a) concatenated c(b)
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
  for (int i = 1; i <= r; i++) {
    res = res * (n - r + i) / i;
  }
  return res;
}

Matrix<int> generate_distribution_matrix_M(int n, int t,
                                           int threshold_combinations) {
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
ISP generate_isp(AccessStructure &A) {
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

Array<BICYCL::Mpz> compute_rho(BICYCL::Mpz &secret, int e) {
  std::string seed =
      "115792089237"; // seed should be kept secret in real-world usage
  BICYCL::Mpz seed_mpz(seed);
  BICYCL::RandGen randgen;
  randgen.set_seed(seed_mpz);
  BICYCL::CL_HSM2k hsm2k(9, 64, randgen, true);

  Array<BICYCL::Mpz> rho(e);
  rho[0] = secret; // Set ρ(0) = s as per the algorithm
  for (int i = 1; i < e; i++) {
    rho[i] = randgen.random_mpz(
        hsm2k.encrypt_randomness_bound()); // This should be random value in
                                           // range [-2^(l0+λ), 2^(l0+λ)]^(e−1)
  }
  return rho;
}

Matrix<BICYCL::Mpz> compute_shares(ISP &isp, Array<BICYCL::Mpz> &rho) {
  Matrix<int> M = isp.M;
  Matrix<int> Sie = isp.Sie;
  int rows = isp.rows, cols = isp.cols;

  Matrix<BICYCL::Mpz> shares;
  for (auto Sp : Sie) {
    Array<BICYCL::Mpz> si;
    for (int i : Sp) {
      BICYCL::Mpz sij(BICYCL::Mpz((unsigned long)(0)));
      if (i != -1) {
        for (int j = 0; j < cols; j++) {
          BICYCL::Mpz mult;
          sij.mul(mult, rho[j], BICYCL::Mpz((unsigned long)(M[i][j])));
          sij.add(sij, sij, mult);
        }
      }
      si.push_back(sij);
    }
    shares.push_back(si);
  }
  std::cout << std::endl;
  return shares;
}

Matrix<BICYCL::Mpz> get_shares(BICYCL::CL_HSM2k &hsm2k,
                               BICYCL::RandGen &randgen, ISP &isp,
                               BICYCL::Mpz secret) {
  Array<BICYCL::Mpz> rho = compute_rho(secret, isp.cols);
  return compute_shares(isp, rho);
}

Array<BICYCL::Mpz> compute_lambda(int t) {
  Array<BICYCL::Mpz> lambda{BICYCL::Mpz((unsigned long)(1))};
  for (int i = 0; i < t; i++) {
    lambda.push_back(BICYCL::Mpz((long)(-1)));
  }
  return lambda;
}
/******************************************************************************************************************************/
/* LISS END */
/******************************************************************************************************************************/

Matrix<BICYCL::CL_HSM2k::CipherText>
encrypt_shares(BICYCL::CL_HSM2k &hsm2k, BICYCL::RandGen &randgen,
               BICYCL::CL_HSM2k::PublicKey &pk, Matrix<BICYCL::Mpz> shares) {
  Matrix<BICYCL::CL_HSM2k::CipherText> encrypted_shares(
      shares.size(),
      std::vector<BICYCL::CL_HSM2k::CipherText>(shares[0].size()));
  for (int i = 0; i < shares.size(); i++) {
    for (int j = 0; j < shares[0].size(); j++) {
      encrypted_shares[i][j] = hsm2k.encrypt(
          pk, BICYCL::CL_HSM2k::ClearText(hsm2k, shares[i][j]), randgen);
    }
  }
  return encrypted_shares;
}

/******************************************************************************************************************************/
/* Decryption using Partial Decryption Scheme START */
/******************************************************************************************************************************/
BICYCL::QFI compute_d(BICYCL::CL_HSM2k &hsm2k, Array<BICYCL::QFI> &ds,
                      Array<BICYCL::Mpz> &lambda) {
  BICYCL::QFI d;
  for (int i = 0; i < ds.size(); i++) {
    BICYCL::QFI r;
    hsm2k.Cl_G().nupow(r, ds[i], lambda[i]);
    hsm2k.Cl_G().nucomp(d, d, r);
  }
  return d;
}

int get_threshold_combination_index(Array<int> &threshold_parties,
                                    AccessStructure &A) {
  std::sort(threshold_parties.begin(), threshold_parties.end());

  // remove the extra parties as we only need threshold number of parties
  if (threshold_parties.size() > A.t) {
    threshold_parties.erase(threshold_parties.begin() + A.t,
                            threshold_parties.end());
  }
  int threshold_combination_index = 0;
  int running_party_num = 0;
  for (int party_num : threshold_parties) {
    threshold_combination_index += party_num - running_party_num;
    running_party_num = party_num + 1;
  }
  return threshold_combination_index;
}

BICYCL::QFI partDecrypt(BICYCL::CL_HSM2k &hsm2k,
                        BICYCL::CL_HSM2k::CipherText &ct, BICYCL::Mpz &ski) {
  BICYCL::QFI di;
  hsm2k.Cl_G().nupow(di, ct.c1(), ski); // di = c1^sj
  if (hsm2k.compact_variant())
    hsm2k.from_Cl_DeltaK_to_Cl_Delta(di);

  return di;
}

BICYCL::CL_HSM2k::ClearText finalDecrypt(BICYCL::CL_HSM2k &hsm2k,
                                         BICYCL::CL_HSM2k::CipherText &ct,
                                         Array<BICYCL::QFI> &ds,
                                         Matrix<BICYCL::Mpz> &sk_shares) {

  Array<BICYCL::Mpz> lambda = compute_lambda(ds.size());

  BICYCL::QFI d = compute_d(hsm2k, ds, lambda);

  BICYCL::QFI r;
  hsm2k.Cl_Delta().nucompinv(r, ct.c2(), d); /* c2 . d^-1 */

  return BICYCL::CL_HSM2k::ClearText(hsm2k, hsm2k.dlog_in_F(r));
}

BICYCL::CL_HSM2k::ClearText decrypt(BICYCL::CL_HSM2k &hsm2k,
                                    BICYCL::CL_HSM2k::CipherText &ct,
                                    Matrix<BICYCL::Mpz> &sk_shares,
                                    Array<int> &threshold_parties,
                                    AccessStructure &A) {
  int threshold_combination_index =
      get_threshold_combination_index(threshold_parties, A);

  Array<BICYCL::QFI> ds(threshold_parties.size());
  for (int i = 0; i < threshold_parties.size(); i++) {
    ds[i] = partDecrypt(hsm2k, ct, sk_shares[threshold_combination_index][i]);
  }

  return finalDecrypt(hsm2k, ct, ds, sk_shares);
}
/******************************************************************************************************************************/
/* Decryption using Partial Decryption Scheme END */
/******************************************************************************************************************************/

/******************************************************************************************************************************/
/* Multiparty Ciphertext Multiplication using Beavers Triplet START */
/******************************************************************************************************************************/
typedef struct {
  Matrix<BICYCL::CL_HSM2k::CipherText> a_shares;
  Matrix<BICYCL::CL_HSM2k::CipherText> b_shares;
  Matrix<BICYCL::CL_HSM2k::CipherText> c_shares;
} BeaversTriplet;

// Ciphertext Multiplication: You can multiply two ciphertexts homomorphically.
BICYCL::CL_HSM2k::CipherText
multiply_ciphertexts(BICYCL::CL_HSM2k &hsm2k, BICYCL::RandGen &randgen,
                     BICYCL::CL_HSM2k::PublicKey &pk,
                     Array<int> &threshold_parties, AccessStructure &A,
                     Matrix<BICYCL::Mpz> &sk_shares,
                     Matrix<BICYCL::CL_HSM2k::CipherText> &x_shares,
                     Matrix<BICYCL::CL_HSM2k::CipherText> &y_shares,
                     BeaversTriplet &beavers_triplet) {
  // Lambda values: beavers triplet shares are not additive. They are LISS
  // shares and hence are reconstructed using lambda values
  auto lambda = compute_lambda(threshold_parties.size());
  int threshold_combination_index =
      get_threshold_combination_index(threshold_parties, A);

  BICYCL::CL_HSM2k::CipherText e = hsm2k.encrypt(
      pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((long)(0))), randgen);
  BICYCL::CL_HSM2k::CipherText d = e;
  for (int i = 0; i < threshold_parties.size(); i++) {
    auto xi = hsm2k.scal_ciphertexts(
        pk, x_shares[threshold_combination_index][i], lambda[i], randgen);
    auto ai = hsm2k.scal_ciphertexts(
        pk, beavers_triplet.a_shares[threshold_combination_index][i], lambda[i],
        randgen);
    auto ei = hsm2k.add_ciphertexts(
        pk, xi,
        hsm2k.scal_ciphertexts(pk, ai, BICYCL::Mpz((long)(-1)), randgen),
        randgen);
    e = hsm2k.add_ciphertexts(pk, e, ei, randgen);

    auto yi = hsm2k.scal_ciphertexts(
        pk, y_shares[threshold_combination_index][i], lambda[i], randgen);
    auto bi = hsm2k.scal_ciphertexts(
        pk, beavers_triplet.b_shares[threshold_combination_index][i], lambda[i],
        randgen);
    auto di = hsm2k.add_ciphertexts(
        pk, yi,
        hsm2k.scal_ciphertexts(pk, bi, BICYCL::Mpz((long)(-1)), randgen),
        randgen);
    d = hsm2k.add_ciphertexts(pk, d, di, randgen);
  }

  auto e_d = decrypt(hsm2k, e, sk_shares, threshold_parties, A);
  auto d_d = decrypt(hsm2k, d, sk_shares, threshold_parties, A);
  int e_d_int = (int)mpz_get_ui(e_d.operator const __mpz_struct *());
  int d_d_int = (int)mpz_get_ui(d_d.operator const __mpz_struct *());

  BICYCL::CL_HSM2k::CipherText r = hsm2k.encrypt(
      pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((long)(0))), randgen);
  for (int i = 0; i < threshold_parties.size(); i++) {
    auto ai = hsm2k.scal_ciphertexts(
        pk, beavers_triplet.a_shares[threshold_combination_index][i], lambda[i],
        randgen);
    auto bi = hsm2k.scal_ciphertexts(
        pk, beavers_triplet.b_shares[threshold_combination_index][i], lambda[i],
        randgen);
    auto ci = hsm2k.scal_ciphertexts(
        pk, beavers_triplet.c_shares[threshold_combination_index][i], lambda[i],
        randgen);
    auto ri = hsm2k.add_ciphertexts(
        pk, ci,
        hsm2k.add_ciphertexts(pk, hsm2k.scal_ciphertexts(pk, bi, e_d, randgen),
                              hsm2k.scal_ciphertexts(pk, ai, d_d, randgen),
                              randgen),
        randgen);
    r = hsm2k.add_ciphertexts(pk, r, ri, randgen);
  }

  r = hsm2k.add_ciphertexts(
      pk, r,
      hsm2k.encrypt(pk,
                    BICYCL::CL_HSM2k::ClearText(
                        hsm2k, BICYCL::Mpz((unsigned long)(e_d_int * d_d_int))),
                    randgen),
      randgen);

  return r;
}
/******************************************************************************************************************************/
/* Multiparty Ciphertext Multiplication using Beavers Triplet END */
/******************************************************************************************************************************/

/******************************************************************************************************************************/
/* Multiparty 2-Degree Polynomial Evaluation START */
/******************************************************************************************************************************/
// 2-degree Polynomial Evaluation: ax^2 + bx + c where a,b,c are constants and x
// is ciphertext
BICYCL::CL_HSM2k::CipherText evaluate_two_degree_polynomial(
    BICYCL::CL_HSM2k &hsm2k, BICYCL::RandGen &randgen,
    BICYCL::CL_HSM2k::PublicKey &pk, Array<int> &threshold_parties,
    AccessStructure &A, Matrix<BICYCL::Mpz> &sk_shares,
    Matrix<BICYCL::CL_HSM2k::CipherText> &x_shares,
    BeaversTriplet &beavers_triplet, int a, int b, int c) {
  int threshold_combination_index =
      get_threshold_combination_index(threshold_parties, A);
  Array<BICYCL::Mpz> lambda = compute_lambda(threshold_parties.size());

  BICYCL::CL_HSM2k::CipherText x = hsm2k.encrypt(
      pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((long)(0))), randgen);
  for (int i = 0; i < threshold_parties.size(); i++) {
    auto xi = hsm2k.scal_ciphertexts(
        pk, x_shares[threshold_combination_index][i], lambda[i], randgen);
    x = hsm2k.add_ciphertexts(pk, x, xi, randgen);
  }

  auto x_square =
      multiply_ciphertexts(hsm2k, randgen, pk, threshold_parties, A, sk_shares,
                           x_shares, x_shares, beavers_triplet);

  auto a_x_square =
      hsm2k.scal_ciphertexts(pk, x_square, BICYCL::Mpz((long)a), randgen);
  auto b_x = hsm2k.scal_ciphertexts(pk, x, BICYCL::Mpz((long)b), randgen);

  auto result_e = hsm2k.add_ciphertexts(
      pk, a_x_square,
      hsm2k.add_ciphertexts(
          pk, b_x,
          hsm2k.encrypt(
              pk,
              BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)c)),
              randgen),
          randgen),
      randgen);

  return result_e;
}
/******************************************************************************************************************************/
/* Multiparty 2-Degree Polynomial Evaluation END */
/******************************************************************************************************************************/

/******************************************************************************************************************************/
/* Examples Start */
/******************************************************************************************************************************/
// Ciphertext Addition: You can add two ciphertexts homomorphically.
void ciphertext_addition(BICYCL::CL_HSM2k &hsm2k, BICYCL::RandGen &randgen,
                         BICYCL::CL_HSM2k::SecretKey &sk,
                         BICYCL::CL_HSM2k::PublicKey &pk) {
  std::cout << "\nHomomorphic Addition:" << std::endl;
  int x = 5, y = 10;

  auto x_e = hsm2k.encrypt(
      pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x))),
      randgen);
  auto y_e = hsm2k.encrypt(
      pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(y))),
      randgen);

  auto result_e = hsm2k.add_ciphertexts(pk, x_e, y_e, randgen);

  // Decrypt result
  BICYCL::CL_HSM2k::ClearText result_d = hsm2k.decrypt(sk, result_e);
  int result_value = (int)mpz_get_ui(result_d.operator const __mpz_struct *());

  std::cout << "x = " << x << ", y = " << y << std::endl;
  std::cout << "Homomorphic addition result: " << result_value << std::endl;
}

// Scalar Multiplication: You can scale ciphertexts by a scalar homomorphically.
void scalar_multiplication(BICYCL::CL_HSM2k &hsm2k, BICYCL::RandGen &randgen,
                           BICYCL::CL_HSM2k::SecretKey &sk,
                           BICYCL::CL_HSM2k::PublicKey &pk) {
  std::cout << "\nScalar Multiplication:" << std::endl;
  int x = 5, scalar = 4;

  auto x_e = hsm2k.encrypt(
      pk, BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(x))),
      randgen);
  auto scaled_e = hsm2k.scal_ciphertexts(
      pk, x_e,
      BICYCL::CL_HSM2k::ClearText(hsm2k, BICYCL::Mpz((unsigned long)(scalar))),
      randgen);

  // Decrypt the result of scalar multiplication
  BICYCL::CL_HSM2k::ClearText scaled_d = hsm2k.decrypt(sk, scaled_e);
  int scaled_value = (int)mpz_get_ui(scaled_d.operator const __mpz_struct *());

  std::cout << "x = " << x << ", scalar = " << scalar << std::endl;
  std::cout << "Scalar multiplication result: " << scaled_value << std::endl;
}

void ciphertext_multiplication(BICYCL::CL_HSM2k &hsm2k,
                               BICYCL::RandGen &randgen,
                               BICYCL::CL_HSM2k::PublicKey &pk,
                               AccessStructure &A, ISP &isp,
                               Matrix<BICYCL::Mpz> &sk_shares,
                               BeaversTriplet &beavers_triplet,
                               Array<int> &threshold_parties) {
  std::cout << "\nCiphertext Multiplication:" << std::endl;
  int x = 12, y = 21;
  auto x_shares =
      encrypt_shares(hsm2k, randgen, pk,
                     get_shares(hsm2k, randgen, isp, BICYCL::Mpz((long)(x))));
  auto y_shares =
      encrypt_shares(hsm2k, randgen, pk,
                     get_shares(hsm2k, randgen, isp, BICYCL::Mpz((long)(y))));

  auto result_mul =
      multiply_ciphertexts(hsm2k, randgen, pk, threshold_parties, A, sk_shares,
                           x_shares, y_shares, beavers_triplet);

  auto result_mul_value =
      mpz_get_ui(decrypt(hsm2k, result_mul, sk_shares, threshold_parties, A)
                     .
                     operator const __mpz_struct *());
  std::cout << "Final result (r): " << result_mul_value << std::endl;
}

void two_degree_polynomial_evaluation(BICYCL::CL_HSM2k &hsm2k,
                                      BICYCL::RandGen &randgen,
                                      BICYCL::CL_HSM2k::PublicKey &pk,
                                      AccessStructure &A, ISP &isp,
                                      Matrix<BICYCL::Mpz> &sk_shares,
                                      BeaversTriplet &beavers_triplet,
                                      Array<int> &threshold_parties) {
  std::cout << "\nHomomorphic Two-Degree Polynomial Evaluation:" << std::endl;

  int a = 15, b = 35, c = 7;
  int x = 12;
  auto x_shares =
      encrypt_shares(hsm2k, randgen, pk,
                     get_shares(hsm2k, randgen, isp, BICYCL::Mpz((long)(x))));

  auto result_2_deg = evaluate_two_degree_polynomial(
      hsm2k, randgen, pk, threshold_parties, A, sk_shares, x_shares,
      beavers_triplet, a, b, c);

  int result_2_deg_value = (int)mpz_get_ui(
      decrypt(hsm2k, result_2_deg, sk_shares, threshold_parties, A)
          .
          operator const __mpz_struct *());
  std::cout << "x = " << x << ", a = " << a << ", b = " << b << ", c = " << c
            << std::endl;
  std::cout << "Homomorphic two-degree polynomial evaluation result: "
            << result_2_deg_value << std::endl;
}
/******************************************************************************************************************************/
/* Examples END */
/******************************************************************************************************************************/

void homomorphic_operations() {
  /******************************************************************************************************************************/
  /* Setup START */
  /******************************************************************************************************************************/
  std::string seed =
      "1157920892373161954235709850086879078528375642790749043"; // seed should
                                                                 // be kept
                                                                 // secret in
                                                                 // real-world
                                                                 // usage
  BICYCL::Mpz seed_mpz(seed);
  BICYCL::RandGen randgen;
  randgen.set_seed(seed_mpz);
  BICYCL::CL_HSM2k hsm2k(96, 64, randgen, true);

  BICYCL::CL_HSM2k::SecretKey sk = hsm2k.keygen(randgen);
  BICYCL::CL_HSM2k::PublicKey pk = hsm2k.keygen(sk);

  AccessStructure A(5, 8);
  Array<int> threshold_parties{0, 2, 3, 4, 5, 7};
  auto isp = generate_isp(A);
  auto sk_shares = get_shares(hsm2k, randgen, isp, sk);

  int a = 15, b = 35, c = a * b;
  BeaversTriplet beavers_triplet;
  beavers_triplet.a_shares =
      encrypt_shares(hsm2k, randgen, pk,
                     get_shares(hsm2k, randgen, isp, BICYCL::Mpz((long)(a))));
  beavers_triplet.b_shares =
      encrypt_shares(hsm2k, randgen, pk,
                     get_shares(hsm2k, randgen, isp, BICYCL::Mpz((long)(b))));
  beavers_triplet.c_shares =
      encrypt_shares(hsm2k, randgen, pk,
                     get_shares(hsm2k, randgen, isp, BICYCL::Mpz((long)(c))));

  /******************************************************************************************************************************/
  /* Setup END */
  /******************************************************************************************************************************/

  // 1) Ciphertext Addition
  ciphertext_addition(hsm2k, randgen, sk, pk);

  // 2) Scalar Multiplication
  scalar_multiplication(hsm2k, randgen, sk, pk);

  // 3) Ciphertext Multiplication
  ciphertext_multiplication(hsm2k, randgen, pk, A, isp, sk_shares,
                            beavers_triplet, threshold_parties);

  // 3) 2-Degree Polynomial Evaluation
  two_degree_polynomial_evaluation(hsm2k, randgen, pk, A, isp, sk_shares,
                                   beavers_triplet, threshold_parties);
}

int main() {
  homomorphic_operations();
  return 0;
}
