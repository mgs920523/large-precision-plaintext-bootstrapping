#include <time.h>
#include <iostream>
#include <fstream>

#include "fhew.h"
#include "lptest.h"
#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

std::pair<double, int> TestA(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma){ 

  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  //  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<LWEPlaintext> dist(0, static_cast<LWEPlaintext>(t - 1));
  LWEPlaintext plaintext = dist(rng);

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext,sigma);
 // int err = LPfhe.Errortours(sk, ciphertext);
 // std::cout << "Init Error is " << err << std::endl;



  
  //密文自举：
  clock_t begin = clock();

  auto bootparams = std::make_shared<BootstrappingParams>( q / t, 2 * N * t / q.ConvertToInt());
  // the first group of bootstrapping procrdure:
  LWECiphertext ct_rem = ciphertext;

  LWECiphertext ct = LPfhe.CipherMod(ct_rem, 2 * N);
  LWECiphertext ctMsb = LPfhe.Bootstrapours(bootparams, ct, Msb);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);

  ct = LPfhe.CipherMod(ct_rem, 2 * N);
  LWECiphertext ctEq = LPfhe.Bootstrapours(bootparams, ct, Eq);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
  LWECiphertext ct_acc = LPfhe.HomomorphicOperator(ctEq, ctMsb, Add);

  bootparams->Revalue(bootparams->Getnextposition(), bootparams->Getblock());

  // the second group of bootstrapping procrdure:
  while (bootparams->Getnextposition() < q) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct,ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctMsb = LPfhe.Bootstrapours(bootparams, ct, Msb);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct,ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Eq);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);

    bootparams->Revalue(bootparams->Getnextposition(),
                         bootparams->Getblock());
  }

  // the third group of bootstrapping procedure:
  uint32_t block = bootparams->Getblock() * q.ConvertToInt() / bootparams->Getnextposition().ConvertToInt();
  bootparams->Revalue(bootparams->Getposition(), block);

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  ctMsb = LPfhe.Bootstrapours(bootparams, ct, Msb);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

  if (block != 2) {
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Eq);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);
  }

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  LPfhe.Decryptours(sk, ct_acc, &result);
  std::cout << "the result of bootstrapping procedure is " << result<< std::endl;
  int err2 = LPfhe.Errortours(sk, ct_acc);
  std::cout << "Error after bootstrapping procedure is " << err2  << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost << std::endl;
  return {cost, err2};
}

void TestB(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma){

  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  //  LWEPlaintext plaintext = rand() % t;
  //LWEPlaintext result;

  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<LWEPlaintext> dist(0, static_cast<LWEPlaintext>(t - 1));
  LWEPlaintext plaintext = dist(rng);

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
  int err = LPfhe.Errortours(sk, ciphertext);
  std::cout << "Init Error is " << err << std::endl;
 


  //密文自举：
  clock_t begin = clock();
  uint32_t blocki =(q / t < 2 * N) ? 2 * N* t / q.ConvertToInt() : 1 << 2;
  auto bootparams = std::make_shared<BootstrappingParams>( q / t,blocki );
  // the first group of bootstrapping procedure:
  LWECiphertext ct_rem = ciphertext;
  LWECiphertext ct;
  if (q / t < 2 * N)
    ct = LPfhe.CipherMod(ct_rem, 2 * N);
  else {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, bootparams->Getnextposition().ConvertToInt() / (2 * N));
  }
  LWECiphertext ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);

  if (q / t < 2 * N)
    ct = LPfhe.CipherMod(ct_rem, 2 * N);
  else {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, bootparams->Getnextposition().ConvertToInt() / (2 * N));
  }
  LWECiphertext ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
  LWECiphertext ct_acc = LPfhe.HomomorphicOperator(ctEq, ctMsb, Add);

  bootparams->Revalue(bootparams->Getnextposition(), 1<<5);

  // the second group of bootstrapping procrdure:
  while (bootparams->Getnextposition() < q) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);

    bootparams->Revalue(bootparams->Getnextposition(), bootparams->Getblock());
  }

  // the third group of bootstrapping procedure:
  uint32_t block = bootparams->Getblock() * q.ConvertToInt() / bootparams->Getnextposition().ConvertToInt();
  bootparams->Revalue(bootparams->Getposition(), block);

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

  if (block == 2) ct_acc = LPfhe.ScalarOperator(ct_acc, q / 4, Sub);
  else {
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);
  }

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  int err2 = LPfhe.Errortours(sk, ct_acc);
  std::cout << "Error after bootstrapping procedure is " << err2  << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost<< std::endl;
}
//Ours for tail-up.

void TestC(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma) {

  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
  LPfhe.Decryptours(sk, ciphertext, &result);
  std::cout << "Decryption result is " << result << std::endl;

  //密文自举：
  clock_t begin = clock();

  auto bootparams =
      std::make_shared<BootstrappingParams>(q / t, 2 * N * t / q.ConvertToInt());
  // the first group of bootstrapping procrdure:
  LWECiphertext ct_rem = ciphertext;

  LWECiphertext ct = LPfhe.CipherMod(ct_rem, 2 * N);
  LWECiphertext ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);

  ct = LPfhe.CipherMod(ct_rem, 2 * N);
  LWECiphertext ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
  LWECiphertext ct_acc = LPfhe.HomomorphicOperator(ctEq, ctMsb, Add);

  bootparams->Revalue(bootparams->Getnextposition(), 32 / bootparams->Getblock());

  if (bootparams->Getblock() == 2) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, 2);
    ctMsb = LPfhe.Bootstrapours(bootparams, ct, Lsb);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

    bootparams->Revalue(bootparams->Getnextposition(), 1 << 5);
  }

  // the second group of bootstrapping procrdure:
  while (bootparams->Getnextposition() < q) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);

    bootparams->Revalue(bootparams->Getnextposition(), 1 << 5);
  }

  // the third group of bootstrapping procedure:
  uint32_t block = bootparams->Getblock() * q.ConvertToInt() /bootparams->Getnextposition().ConvertToInt();
  bootparams->Revalue(bootparams->Getposition(), block);

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

  if (block == 2)
    ct_acc = LPfhe.ScalarOperator(ct_acc, q / 4, Sub);
  else {
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);
  }

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  LPfhe.Decryptours(sk, ct_acc, &result);
  std::cout << "the result of bootstrapping procedure is " << result << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost << std::endl;
}
void TestD(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma) {

  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
  LPfhe.Decryptours(sk, ciphertext, &result);
  std::cout << "Decryption result is " << result << std::endl;

  //密文自举：
  clock_t begin = clock();

  auto bootparams = std::make_shared<BootstrappingParams>(q / t, 2 );
  // the first group of bootstrapping procrdure:
  LWECiphertext ct_rem = ciphertext;
  LWECiphertext ct;
  if (q / t < 2 * N) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N / bootparams->Getnextposition().ConvertToInt(),Mul);
  }
  else {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, bootparams->Getnextposition().ConvertToInt() / (2 * N));
  }
  LWECiphertext ctMsb = LPfhe.Bootstrapours(bootparams, ct, Lsb);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
  LWECiphertext ct_acc = ctMsb;
  LWECiphertext ctEq;

  bootparams->Revalue(bootparams->Getposition() * 2, 1 << 5);

  // the second group of bootstrapping procrdure:
  while (bootparams->Getnextposition() < q) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctEq, Sub);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);

    bootparams->Revalue(bootparams->Getnextposition(), bootparams->Getblock());
  }

  // the third group of bootstrapping procedure:
  uint32_t block = bootparams->Getblock() * q.ConvertToInt() /
                   bootparams->Getnextposition().ConvertToInt();
  bootparams->Revalue(bootparams->Getposition(), block);

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  ctMsb = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctMsb, Add);

  if (block == 2)
    ct_acc = LPfhe.ScalarOperator(ct_acc, q / 4, Sub);
  else {
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ctMsb, Sub);
    ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
    ctEq = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ctEq, Add);
  }

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  LPfhe.Decryptours(sk, ct_acc, &result);
  std::cout << "the result of bootstrapping procedure is " << result << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost << std::endl;
}
// Ours for tail-up with Lsb.
std::pair<double, int> TestH(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma) {
  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  //  LWEPlaintext plaintext = rand() % t;
  //LWEPlaintext result;
  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<LWEPlaintext> dist(0, static_cast<LWEPlaintext>(t - 1));
  LWEPlaintext plaintext = dist(rng);

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
 // int err = LPfhe.Errortours(sk, ciphertext);
  //std::cout << "Init Error is " << err << std::endl;


  //密文自举：
  clock_t begin = clock();

  auto bootparams = std::make_shared<BootstrappingParams>(
      q /64, 1<<6);

  // The first group of bootstrapping procedure.
  LWECiphertext ct_rem = ciphertext;
  LWECiphertext ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  LWECiphertext ct_acc = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_acc, Sub);

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  LWECiphertext ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);

  bootparams->Revalue(bootparams->Getposition() / 16, 1 << 6);
  // The second group of bootstrapping procedure.
  while (bootparams->Getposition() > q / t) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);

    bootparams->Revalue(bootparams->Getposition() / 16, 1 << 6);
  }

  // The third group of bootstrapping procedure.
  if (bootparams->Getnextposition() > 2 * N) {
    bootparams->Revalue(q / t, bootparams->Getnextposition().ConvertToInt() * t / q.ConvertToInt());
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
  } else {
    bootparams->Revalue(q / t, 2 * N * t / q.ConvertToInt());
    ct = LPfhe.CipherMod(ct_rem, 2 * N);
  }
  ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  int err2 = LPfhe.Errortours(sk, ct_acc);
  return {cost, err2};
}
//Ours for head-on.
void TestHL(BinFHEContext LPfhe, LWEPrivateKey sk,double sigma) {
  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
  LPfhe.Decryptours(sk, ciphertext, &result);
  std::cout << "Decryption result is " << result << std::endl;

  //密文自举：
  clock_t begin = clock();

  auto bootparams = std::make_shared<BootstrappingParams>(q / t, 2 );
  //LSB precursor.

  LWECiphertext ct_rem = ciphertext;
  LWECiphertext ct;
  if (q / t < 2 * N) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N / bootparams->Getnextposition().ConvertToInt(), Mul);
  }
  else {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, bootparams->Getnextposition().ConvertToInt() / (2 * N));
  }
  LWECiphertext ct_acc = LPfhe.Bootstrapours(bootparams, ct, Lsb);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_acc, Sub);

  bootparams->Revalue(q / 64, 1 << 6);
  // The first group of bootstrapping procedure.

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  LWECiphertext ct_id = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);

  ct = LPfhe.CipherRescaling(ct_rem, q.ConvertToInt() / (2 * N));
  ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);

  bootparams->Revalue(bootparams->Getposition() / 16, 1 << 6);
  // The second group of bootstrapping procedure.
  while (bootparams->Getposition() > 2 * q / t) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);

    bootparams->Revalue(bootparams->Getposition() / 16, 1 << 6);
  }
  if (bootparams->Getposition() == 2 * q / t) {
    bootparams->Revalue(4 * q / t, 1 << 5);

    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);

    bootparams->Revalue(2 * q / t, 1 << 3);
  }

  // The third group of bootstrapping procedure.
  if (bootparams->Getnextposition() > 2 * N) {
    bootparams->Revalue(2 * q / t, bootparams->Getnextposition().ConvertToInt() * t /(2 * q.ConvertToInt()));
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
  } else {
    bootparams->Revalue(2 * q / t, 2 * N * t / (2 * q.ConvertToInt()));
    ct = LPfhe.CipherMod(ct_rem, 2 * N);
  }
  ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_acc = LPfhe.HomomorphicOperator(ct_acc, ct_id, Add);

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  LPfhe.Decryptours(sk, ct_acc, &result);
  std::cout << "the result of bootstrapping procedure is " << result
            << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost
            << std::endl;
}
//Ours for head-on with Lsb.

std::pair<double, int> TestE(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma) {
  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
//  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<LWEPlaintext> dist(0, static_cast<LWEPlaintext>(t - 1));
  LWEPlaintext plaintext = dist(rng);

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
 // int err = LPfhe.Errortours(sk, ciphertext);
 // std::cout << "Init Error is " << err << std::endl;

  //密文自举：
  clock_t begin = clock();

  auto bootparams = std::make_shared<BootstrappingParams>(q / (64*t), 1 << 6);

  // The first group of bootstrapping procedure.
  LWECiphertext ct_rem = ciphertext;
  LWECiphertext ct = LPfhe.CipherMod(ct_rem, q / t);
  if (q / t < 2 * N) {
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N * t / q.ConvertToInt(), Mul);
  } else {
    ct = LPfhe.CipherRescaling(ct, q.ConvertToInt() / (2 * t * N));
  }
  ct = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct, Sub);

  ct = LPfhe.CipherMod(ct_rem, q / t);
  if (q / t < 2 * N) {
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N * t/ q.ConvertToInt(), Mul);
  } else {
    ct = LPfhe.CipherRescaling(ct, q.ConvertToInt() / (2 * t * N));
  }
  LWECiphertext ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);

  // The second group of bootstrapping procedure.
  while (bootparams->Getposition() > N/2) {
    bootparams->Revalue(bootparams->Getposition() / 16, 1 << 6);
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling( ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  }
  // The third group of bootstrapping procedure.
  if (q / t > N) {
    bootparams->Revalue(1, 2 * N);
    ct = LPfhe.CipherMod(ct_rem, 2 * N);

    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  } else {
    bootparams->Revalue(1, q.ConvertToInt() / t);
    ct = LPfhe.CipherMod(ct_rem, q / t);

    


    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N * t / q.ConvertToInt(), Mul);



    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  }
  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  LPfhe.Decryptours(sk, ct_rem, &result);
  std::cout << "the result of bootstrapping procedure is " << result << std::endl;
  int err2 = LPfhe.Errortours(sk, ct_rem);
  return {cost, err2};
}

void TestEL(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma) {
  NativeInteger q = LPfhe.GetParams()->GetLWEParams()->Getq();
  uint64_t t = LPfhe.GetParams()->GetLWEParams()->GetT();
  uint32_t N = LPfhe.GetParams()->GetLWEParams()->GetN();

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = LPfhe.Encryptours(sk, plaintext, sigma);
  LPfhe.Decryptours(sk, ciphertext, &result);
  std::cout << "Decryption result is " << result << std::endl;

  //密文自举：
  clock_t begin = clock();

  auto bootparams = std::make_shared<BootstrappingParams>(q / t, 2);
  // LSB precursor.
  LWECiphertext ct_rem = ciphertext;
  LWECiphertext ct;
  if (q / t < 2 * N) {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N / bootparams->Getnextposition().ConvertToInt(), Mul);
  }
  else {
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, bootparams->Getnextposition().ConvertToInt() / (2 * N));
  }
  LWECiphertext ct_acc = LPfhe.Bootstrapours(bootparams, ct, Lsb);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_acc, Sub);

  bootparams->Revalue(q / (32 * t), 1 << 6);
  // The first group of bootstrapping procedure.
  ct = LPfhe.CipherMod(ct_rem, 2 * q / t);
  if (q / t < N) {
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, N * t / q.ConvertToInt(), Mul);
  } else {
    ct = LPfhe.CipherRescaling(ct, q.ConvertToInt() / (t * N));
  }
  ct = LPfhe.Bootstrapours(bootparams, ct, Sign);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct, Sub);

  ct = LPfhe.CipherMod(ct_rem, 2*q / t);
  if (q / t <  N) {
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, N * t / q.ConvertToInt(), Mul);
  } else {
    ct = LPfhe.CipherRescaling(ct, q.ConvertToInt() / (t * N));
  }
  LWECiphertext ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_acc, Add);

  // The second group of bootstrapping procedure.
  while (bootparams->Getposition() > N / 2) {
    bootparams->Revalue(bootparams->Getposition() / 16, 1 << 6);
    ct = LPfhe.CipherMod(ct_rem, bootparams->Getnextposition());
    ct = LPfhe.CipherRescaling(ct, ct->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  }

  // The third group of bootstrapping procedure.
  if (q / t > N) {
    bootparams->Revalue(1, 2 * N);
    ct = LPfhe.CipherMod(ct_rem, 2 * N);

    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  } else {
    bootparams->Revalue(1, q.ConvertToInt() / t);
    ct = LPfhe.CipherMod(ct_rem, q / t);
    ct = LPfhe.ChangeMod(ct, 2 * N);
    ct = LPfhe.ScalarOperator(ct, 2 * N * t / q.ConvertToInt(), Mul);

    ct_id = LPfhe.Bootstrapours(bootparams, ct, Id);
    ct_rem = LPfhe.HomomorphicOperator(ct_rem, ct_id, Sub);
  }

  clock_t end = clock();
  double cost = double(end - begin) / CLOCKS_PER_SEC;

  // final result verify:
  LPfhe.Decryptours(sk, ct_rem, &result);
  std::cout << "the result of bootstrapping procedure is " << result << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost << std::endl;
}

int main() {
 // auto start = std::chrono::high_resolution_clock::now();
  //ofstream fout("TestForV.txt");  //文件输出流对象
  //std::cout.rdbuf(fout.rdbuf());

  auto LPfhe = BinFHEContext();

   uint64_t t = 1 << 20;
  NativeInteger q = NativeInteger(1) <<27;
   // double sigmaT = 3.19;
      //double sigmaTL = 3.19;
   double sigmaH = 3.19;
    //double sigmaHL = 3.19;
   double sigmaE = 3.19;
    //double sigmaEL = 3.19;

  NativeInteger Q;
  Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096), 4096);
  NativeInteger qks = Q;
  LPfhe.GenerateBinFHEContext(
      1024, 2048, q, t, Q, qks, 3.19, 25, 1 << 15, 32,
      GINX);  // n,N,q,t,Q,qks,std,baseks,baseG,baseR,method;

  auto sk = LPfhe.KeyGen();
  std::cout << "Generating the bootstrapping keys..." << std::endl;
  clock_t ti1 = clock();
  LPfhe.BTKeyGen(sk);
  clock_t ti2 = clock();
  double cost = double(ti2 - ti1) / CLOCKS_PER_SEC;
  std::cout << "Completed the key generation, run time is" << cost << std::endl;

  // 2022-10-18 test.

  /* for (uint32_t i = 0; i < 100; i++) {
    std::cout << "................Test for method A. ................" << std::endl;
    TestA(LPfhe, sk, sigmaT);
    std::cout << "................Test for method B. ................" << std::endl;
    TestB(LPfhe, sk, sigmaT);
    std::cout << "................Test for method C. ................" << std::endl;
    TestC(LPfhe, sk, sigmaT);
    std::cout << "................Test for method D. ................" << std::endl;
    TestD(LPfhe, sk, sigmaTL);
  } */

  // 2022-10-31 test.
  /* for (uint32_t i = 0; i < 10; i++) {
    std::cout << "................Test for method T. ................" << std::endl;
    TestB(LPfhe, sk, sigmaT);
    std::cout << "................Test for method H. ................" << std::endl;
    TestH(LPfhe, sk, sigmaH);
    std::cout << "................Test for method TL. ................" << std::endl;
    TestD(LPfhe, sk);
    std::cout << "................Test for method HL. ................" << std::endl;
    TestHL(LPfhe, sk);
  }*/

  //2022-11-8 test.

  double totalCostA = 0.0, totalErrorA = 0.0, totalErrorSqA = 0.0;
double totalCostH = 0.0, totalErrorH = 0.0, totalErrorSqH = 0.0;
double totalCostE = 0.0, totalErrorE = 0.0, totalErrorSqE = 0.0;
const int kk=50;

for (uint32_t i = 0; i < kk; i++) {
    // Test A
    std::cout << "................Test for method Micciancio................" << std::endl;
    std::pair<double, int> resultA = TestA(LPfhe, sk, 3.19);
    double timeCostA = resultA.first;
    int errorA = resultA.second;
    totalCostA += timeCostA;
    totalErrorA += errorA;
    totalErrorSqA += errorA * errorA;

    // Test H
    std::cout << "................Test for method H................" << std::endl;
    std::pair<double, int> resultH = TestH(LPfhe, sk, sigmaH);
    double timeCostH = resultH.first;
    int errorH = resultH.second;
    totalCostH += timeCostH;
    totalErrorH += errorH;
    totalErrorSqH += errorH * errorH;

    // Test E
    std::cout << "................Test for method E................" << std::endl;
    std::pair<double, int> resultE = TestE(LPfhe, sk, sigmaE);
    double timeCostE = resultE.first;
    int errorE = resultE.second;
    totalCostE += timeCostE;
    totalErrorE += errorE;
    totalErrorSqE += errorE * errorE;

    std::cout << "\t" << std::endl;
}

// 统计结果输出
auto printStats = [kk](const std::string& name, double totalCost, double totalError, double totalErrorSq) {
    double avgCost = totalCost / kk;
    double meanError = totalError / kk;
    double varianceError = (totalErrorSq / kk) - (meanError * meanError);
    double stddevError = std::sqrt(varianceError); //

    std::cout << "===> " << name << " Average time cost = " << avgCost << " seconds" << std::endl;
    std::cout << "===> " << name << " Mean error = " << meanError << std::endl;
    std::cout << "===> " << name << " Standard deviation of error = " << stddevError << std::endl;
};

printStats("TestA (Micciancio)", totalCostA, totalErrorA, totalErrorSqA);
printStats("TestH", totalCostH, totalErrorH, totalErrorSqH);
printStats("TestE", totalCostE, totalErrorE, totalErrorSqE);
  return 0;
}