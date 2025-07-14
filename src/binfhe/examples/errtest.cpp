#include <time.h>
#include <bitset>
#include<iostream>
#include<fstream>

#include "binfhecontext.h"
#include "fhew.h"

using namespace lbcrypto;
using namespace std;

int main() {
  auto cc = BinFHEContext();

  /*�������������������������������������������ã���Կ���ɡ�����������������������������������*/

  uint64_t t = 1 << 20;
  NativeInteger q = NativeInteger(1) << 29;
  NativeInteger Q;
  Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096), 4096);
  NativeInteger qks = Q;
  // NativeInteger(1) << 45;
  /* auto m_lweparams = std::make_shared<LWECryptoParams>(
      512, 2048, 1 << 29, t, Q, 1 << 35, 3.19, 1 << 18);
  auto m_params =
      std::make_shared<RingGSWCryptoParams>(m_lweparams, 1 << 15, 32, GINX);*/
  // const shared_ptr<ILNativeParams> polyParams = m_params->GetPolyParams();

  // std::vector<NativeInteger> digitsR = m_params->GetDigitsR();
  cc.GenerateBinFHEContext(
      1024, 2048, q, t, Q, qks, 3.19, 25, 1 << 15, 32,
      GINX);  // n,N,q,t,Q,qks,std,baseks,baseG,baseR,method;

  auto sk = cc.KeyGen();
  uint32_t N = cc.GetParams()->GetLWEParams()->GetN();

  std::cout << "Generating the bootstrapping keys..." << std::endl;
  clock_t ti1 = clock();
  cc.BTKeyGen(sk);
  clock_t ti2 = clock();
  double cost = double(ti2 - ti1) / CLOCKS_PER_SEC;
  std::cout << "Completed the key generation, run time is" << cost << std::endl;
  /*������������������������������������OLD-1st������������������������������������������������*/

  ofstream fout("errtest.txt");  //�ļ����������
  std::cout.rdbuf(fout.rdbuf());


  for (int i = 0; i < 5000; i++) {
  //�������ɣ�
  unsigned seed;
  seed = time(0);
  srand(seed);
  LWEPlaintext plaintext = rand() % t;
  LWEPlaintext result;

  //���ļ�������ܲ��ԣ�
  std::cout << "the plaintext is " << plaintext << std::endl;
  auto ciphertext = cc.Encryptours(sk, plaintext);

    auto bootparams = std::make_shared<BootstrappingParams>(
        q / t, 2 * N * t / q.ConvertToInt());
    LWECiphertext ct1 = cc.CipherMod(ciphertext, 2 * N);
    LWECiphertext ct = cc.Bootstrapours(bootparams, ct1, Msb);
    cc.Decryptours(sk, ct, &result);
    cc.HomomorphicOperator(ciphertext, ct, Sub);

    ct1 = cc.CipherMod(ciphertext, 2 * N);
    ct = cc.Bootstrapours(bootparams, ct1, Eq);
    cc.Decryptours(sk, ct, &result);

  }



  return 0;
}