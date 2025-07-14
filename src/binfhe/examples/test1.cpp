#include <time.h>
#include <bitset>

#include "binfhecontext.h"
#include "fhew.h"

using namespace lbcrypto;
using namespace std;

int main() {
  auto cc = BinFHEContext();

  /*………………………………………………参数设置，密钥生成………………………………………………*/

  uint64_t t = 1<<20;
  NativeInteger q = NativeInteger(1) << 29;
  NativeInteger Q;
  Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096), 4096);
  NativeInteger qks = Q;
  //NativeInteger(1) << 45;
  /* auto m_lweparams = std::make_shared<LWECryptoParams>(
      512, 2048, 1 << 29, t, Q, 1 << 35, 3.19, 1 << 18);
  auto m_params =
      std::make_shared<RingGSWCryptoParams>(m_lweparams, 1 << 15, 32, GINX);*/
  //const shared_ptr<ILNativeParams> polyParams = m_params->GetPolyParams();

  //std::vector<NativeInteger> digitsR = m_params->GetDigitsR();
  cc.GenerateBinFHEContext(512, 2048, q, t, Q, qks, 3.19, 25,
                           1 << 15, 32,GINX);//n,N,q,t,Q,qks,std,baseks,baseG,baseR,method;

  auto sk = cc.KeyGen();
  uint32_t N = cc.GetParams()->GetLWEParams()->GetN();

  std::cout << "Generating the bootstrapping keys..." << std::endl;
  clock_t ti1 = clock();
  cc.BTKeyGen(sk);
  clock_t ti2 = clock();
  double cost = double(ti2 - ti1) / CLOCKS_PER_SEC;
  std::cout << "Completed the key generation, run time is" << cost << std::endl;

  /*………………………………………………………………………………………………………………………………
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext m0 = rand() % t;
  LWEPlaintext m1 = rand() % t;

  std::cout << "the first plaintext is " << m0 << std::endl;
  std::cout << "the second plaintext is " << m1 << std::endl;

  auto ct0 = cc.Encryptours(sk, m0);
  auto ct1 = cc.Encryptours(sk, m1);

  LWEPlaintext result0;
  LWEPlaintext result1;

  // std::cout << "generating ciphertext ct0=Encrypt(0) with ct1=Encrypt(1)..."
  // << std::endl;

  cc.Decryptours(sk, ct0, &result0);
  cc.Decryptours(sk, ct1, &result1);

  std::cout << "Decryption(ct0)= " << result0 << std::endl;
  std::cout << "Decryption(ct1)= " << result1 << std::endl;
  
  auto bootparams = std::make_shared<BootstrappingParams>(
      q / t, t);

  //TEST-1
  auto ctMsb0 = cc.Bootstrapours(bootparams, ct0, Sign);
  cc.Decryptours(sk, ctMsb0, &result0);
  std::cout << " /delt*Msb= " << result0 << std::endl;

  ct0 = cc.HomomorphicOperator(ct0,ctMsb0,Sub);
  auto ctEq0 = cc.Bootstrapours(bootparams, ct0, Id);
  cc.Decryptours(sk, ctEq0, &result0);
  std::cout << " x-/delt*Msb= " << result0 << std::endl;

  ct0 = cc.HomomorphicOperator(ctMsb0, ctEq0,Add);
  cc.Decryptours(sk, ct0, &result0);
  std::cout << " x= " << result0 << std::endl;

  // TEST-2
  auto ctMsb1 = cc.Bootstrapours(bootparams, ct1, Sign);
  cc.Decryptours(sk, ctMsb1, &result1);
  std::cout << " /delt*Msb= " << result1 << std::endl;

  ct1 = cc.HomomorphicOperator(ct1, ctMsb1, Sub);
  auto ctEq1 = cc.Bootstrapours(bootparams, ct1, Id);
  cc.Decryptours(sk, ctEq1, &result1);
  std::cout << " x-/delt*Msb= " << result1 << std::endl;

  ct1 = cc.HomomorphicOperator(ctMsb1, ctEq1, Add);
  cc.Decryptours(sk, ct1, &result1);
  std::cout << " x= " << result1 << std::endl;*/

  

  /*………………………………………………OLD-1st………………………………………………………………*/
  std::cout << "................................................................................" << std::endl;
  std::cout << " * large-precision homomorphic encryption according to paper written by Micciancio." << std::endl;
  std::cout << "................................................................................" << std::endl;
  std::cout << "" << std::endl;

  //明文生成：
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext plaintext1 = rand() % t;
  LWEPlaintext result1;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext1 << std::endl;
  auto ciphertext1 = cc.Encryptours(sk, plaintext1);
  cc.Decryptours(sk, ciphertext1, &result1);
  std::cout << "Decryption result is " << result1 << std::endl;

  

  //密文自举：
  clock_t begin1 = clock();

  auto bootparams1 =
      std::make_shared<BootstrappingParams>(q / t, 2 * N * t / q.ConvertToInt());
  // the first group of bootstrapping procrdure:
  LWECiphertext ct_rem1 = ciphertext1;

  LWECiphertext ct1 = cc.CipherMod(ct_rem1, 2 * N);
  LWECiphertext ct1Msb = cc.Bootstrapours(bootparams1, ct1, Msb);
  ct_rem1 = cc.HomomorphicOperator(ct_rem1, ct1Msb, Sub);

  ct1 = cc.CipherMod(ct_rem1, 2 * N);
  LWECiphertext ct1Eq = cc.Bootstrapours(bootparams1, ct1, Eq);
  ct_rem1 = cc.HomomorphicOperator(ct_rem1, ct1Eq, Sub);
  LWECiphertext ct_acc1 = cc.HomomorphicOperator(ct1Eq, ct1Msb, Add);

  bootparams1->Revalue(bootparams1->Getnextposition(), bootparams1->Getblock());

  // the second group of bootstrapping procrdure:
  while (bootparams1->Getnextposition() < q) {

    ct1 = cc.CipherMod(ct_rem1, bootparams1->Getnextposition());
    ct1 = cc.CipherRescaling(ct1, ct1->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct1Msb = cc.Bootstrapours(bootparams1, ct1, Msb);
    ct_rem1 = cc.HomomorphicOperator(ct_rem1, ct1Msb, Sub);
    ct_acc1 = cc.HomomorphicOperator(ct_acc1, ct1Msb, Add);

    ct1 = cc.CipherMod(ct_rem1, bootparams1->Getnextposition());
    ct1 = cc.CipherRescaling(ct1, ct1->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct1Eq = cc.Bootstrapours(bootparams1, ct1, Eq);
    ct_rem1 = cc.HomomorphicOperator(ct_rem1, ct1Eq, Sub);
    ct_acc1 = cc.HomomorphicOperator(ct_acc1, ct1Eq, Add);

    bootparams1->Revalue(bootparams1->Getnextposition(), bootparams1->Getblock());
  }

  // the third group of bootstrapping procedure:
  uint32_t block1 = bootparams1->Getblock() * q.ConvertToInt() /
                   bootparams1->Getnextposition().ConvertToInt();
  bootparams1->Revalue(bootparams1->Getposition(), block1);

  ct1 = cc.CipherRescaling(ct_rem1, q.ConvertToInt() / (2 * N));
  ct1Msb = cc.Bootstrapours(bootparams1, ct1, Msb);
  ct_acc1 = cc.HomomorphicOperator(ct_acc1, ct1Msb, Add);

  if (block1 != 2) {
    ct_rem1 = cc.HomomorphicOperator(ct_rem1, ct1Msb, Sub);
    ct1 = cc.CipherRescaling(ct_rem1, q.ConvertToInt() / (2 * N));
    ct1Eq = cc.Bootstrapours(bootparams1, ct1, Eq);
    ct_acc1 = cc.HomomorphicOperator(ct_acc1, ct1Eq, Add);
  }


  clock_t end1 = clock();
  cost = double(end1 - begin1) / CLOCKS_PER_SEC;

   // final result verify:
  cc.Decryptours(sk, ct_acc1, &result1);
  std::cout << "the result of bootstrapping procedure is " << result1 << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost << std::endl;
  std::cout << "" << std::endl;
  
  /*………………………………………………NEW - 1st………………………………………………………………*/
  std::cout << "................................................................................"<< std::endl;
    std::cout << " * large-precision homomorphic encryption by ours."<< std::endl;
  std::cout << "................................................................................"<< std::endl;
    std::cout << "" << std::endl;

  //明文生成：
  LWEPlaintext plaintext2 = rand() % t;
  LWEPlaintext result2;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext2 << std::endl;
  auto ciphertext2 = cc.Encryptours(sk, plaintext2);
  cc.Decryptours(sk, ciphertext2, &result2);
  std::cout << "Decryption result is " << result2 << std::endl;

  //密文自举：
  clock_t begin2 = clock();

  auto bootparams2 = std::make_shared<BootstrappingParams>(
      q / t, 2 * N * t / q.ConvertToInt());
  // the first group of bootstrapping procrdure:
  LWECiphertext ct_rem2 = ciphertext2;

  LWECiphertext ct2 = cc.CipherMod(ct_rem2, 2 * N);
  LWECiphertext ct2Msb = cc.Bootstrapours(bootparams2, ct2, Sign);
  ct_rem2 = cc.HomomorphicOperator(ct_rem2, ct2Msb, Sub);

  ct2 = cc.CipherMod(ct_rem2, 2 * N);
  LWECiphertext ct2Eq = cc.Bootstrapours(bootparams2, ct2, Id);
  ct_rem2 = cc.HomomorphicOperator(ct_rem2, ct2Eq, Sub);
  LWECiphertext ct_acc2 = cc.HomomorphicOperator(ct2Eq, ct2Msb, Add);

  bootparams2->Revalue(bootparams2->Getnextposition(), 1<<5);

  // the second group of bootstrapping procrdure:
  while (bootparams2->Getnextposition() < q) {
    ct2 = cc.CipherMod(ct_rem2, bootparams2->Getnextposition());
    ct2 = cc.CipherRescaling(ct2, ct2->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct2Msb = cc.Bootstrapours(bootparams2, ct2, Sign);
    ct_rem2 = cc.HomomorphicOperator(ct_rem2, ct2Msb, Sub);
    ct_acc2 = cc.HomomorphicOperator(ct_acc2, ct2Msb, Add);

    ct2 = cc.CipherMod(ct_rem2, bootparams2->Getnextposition());
    ct2 = cc.CipherRescaling(ct2, ct2->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct2Eq = cc.Bootstrapours(bootparams2, ct2, Id);
    ct_rem2 = cc.HomomorphicOperator(ct_rem2, ct2Eq, Sub);
    ct_acc2 = cc.HomomorphicOperator(ct_acc2, ct2Eq, Add);

    bootparams2->Revalue(bootparams2->Getnextposition(), bootparams2->Getblock());
  }

  // the third group of bootstrapping procedure:
  uint32_t block2 = bootparams2->Getblock() * q.ConvertToInt() /
                   bootparams2->Getnextposition().ConvertToInt();
  bootparams2->Revalue(bootparams2->Getposition(), block2);

  ct2 = cc.CipherRescaling(ct_rem2, q.ConvertToInt() / (2 * N));
  ct2Msb = cc.Bootstrapours(bootparams2, ct2, Sign);
  ct_acc2 = cc.HomomorphicOperator(ct_acc2, ct2Msb, Add);

  if (block2 == 2)
    ct_acc2 = cc.ScalarOperator(ct_acc2, q / 4, Sub);
  else {
    ct_rem2 = cc.HomomorphicOperator(ct_rem2, ct2Msb, Sub);
    ct2 = cc.CipherRescaling(ct_rem2, q.ConvertToInt() / (2 * N));
    ct2Eq = cc.Bootstrapours(bootparams2, ct2, Id);
    ct_acc2 = cc.HomomorphicOperator(ct_acc2, ct2Eq, Add);
  }

  clock_t end2 = clock();
  cost = double(end2 - begin2) / CLOCKS_PER_SEC;

  // final result verify:
  cc.Decryptours(sk, ct_acc2, &result2);
  std::cout << "the result of bootstrapping procedure is " << result2
            << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost
            << std::endl;
  std::cout << "" << std::endl;

  /*…………………………………………………NEW-LSB……………………………………………………………*/
  std::cout << "................................................................................." << std::endl;
  std::cout << " * LSB-variant large-precision homomorphic encryption by ours."<< std::endl;
  std::cout << "................................................................................."<< std::endl;
  std::cout << "" << std::endl;

  //明文生成：
  LWEPlaintext plaintext4 = rand() % t;
  LWEPlaintext result4;

  //明文加密与解密测试：
  std::cout << "the plaintext is " << plaintext4 << std::endl;
  auto ciphertext4 = cc.Encryptours(sk, plaintext4);
  cc.Decryptours(sk, ciphertext4, &result4);
  std::cout << "Decryption result is " << result4 << std::endl;

  //密文自举：
  clock_t begin4 = clock();

  auto bootparams4 = std::make_shared<BootstrappingParams>(
      q / t, 2 * N * t / q.ConvertToInt());
  // the first group of bootstrapping procrdure:
  LWECiphertext ct_rem4 = ciphertext4;

  LWECiphertext ct4 = cc.CipherMod(ct_rem4, bootparams4->Getnextposition());
  LWECiphertext ct4Msb = cc.Bootstrapours(bootparams4, ct4, Lsb);
  ct_rem4 = cc.HomomorphicOperator(ct_rem4, ct4Msb, Sub);
  LWECiphertext ct_acc4 = ct4Msb;
  LWECiphertext ct4Eq;

  /*
   ct4 = cc.CipherMod(ct_rem4, bootparams4->Getnextposition());
  ct4Msb = cc.Bootstrapours(bootparams4, ct4, Sign);
  ct_rem4 = cc.HomomorphicOperator(ct_rem4, ct4Msb, Sub);
  ct_acc4 = cc.HomomorphicOperator(ct_acc4, ct4Msb, Add);

  ct4 = cc.CipherMod(ct_rem4, bootparams4->Getnextposition());
  ct4Eq = cc.Bootstrapours(bootparams4, ct4, Id);
  ct_rem4 = cc.HomomorphicOperator(ct_rem4, ct4Eq, Sub);
  ct_acc4 = cc.HomomorphicOperator(ct_acc4, ct4Eq, Add);*/

  bootparams4->Revalue(bootparams4->Getposition()*2, 1<<5);

  // the second group of bootstrapping procrdure:
  while (bootparams4->Getnextposition() < q) {
    ct4 = cc.CipherMod(ct_rem4, bootparams4->Getnextposition());
    ct4 = cc.CipherRescaling(ct4, ct4->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct4Msb = cc.Bootstrapours(bootparams4, ct4, Sign);
    ct_rem4 = cc.HomomorphicOperator(ct_rem4, ct4Msb, Sub);
    ct_acc4 = cc.HomomorphicOperator(ct_acc4, ct4Msb, Add);

    ct4 = cc.CipherMod(ct_rem4, bootparams4->Getnextposition());
    ct4 = cc.CipherRescaling(ct4,
                             ct4->GetA().GetModulus().ConvertToInt() / (2 * N));
    ct4Eq = cc.Bootstrapours(bootparams4, ct4, Id);
    ct_rem4 = cc.HomomorphicOperator(ct_rem4, ct4Eq, Sub);
    ct_acc4 = cc.HomomorphicOperator(ct_acc4, ct4Eq, Add);

    bootparams4->Revalue(bootparams4->Getnextposition(),
                         bootparams4->Getblock());
  }

  // the third group of bootstrapping procedure:
  uint32_t block4 = bootparams4->Getblock() * q.ConvertToInt() /
                    bootparams4->Getnextposition().ConvertToInt();
  bootparams4->Revalue(bootparams4->Getposition(), block4);

  ct4 = cc.CipherRescaling(ct_rem4, q.ConvertToInt() / (2 * N));
  ct4Msb = cc.Bootstrapours(bootparams4, ct4, Sign);
  ct_acc4 = cc.HomomorphicOperator(ct_acc4, ct4Msb, Add);

  if (block4 == 2)
    ct_acc4 = cc.ScalarOperator(ct_acc4, q / 4, Sub);
  else {
    ct_rem4 = cc.HomomorphicOperator(ct_rem4, ct4Msb, Sub);
    ct4 = cc.CipherRescaling(ct_rem4, q.ConvertToInt() / (2 * N));
    ct4Eq = cc.Bootstrapours(bootparams4, ct4, Id);
    ct_acc4 = cc.HomomorphicOperator(ct_acc4, ct4Eq, Add);
  }

  clock_t end4 = clock();
  cost = double(end4 - begin4) / CLOCKS_PER_SEC;

  // final result verify:
  cc.Decryptours(sk, ct_acc4, &result4);
  std::cout << "the result of bootstrapping procedure is " << result4 << std::endl;
  std::cout << "run time of the bootstrapping procedure is " << cost << std::endl;

  return 0;
}