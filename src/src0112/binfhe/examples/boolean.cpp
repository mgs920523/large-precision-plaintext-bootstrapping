// @file boolean.cpp - Example for the FHEW scheme using the default
// bootstrapping method (GINX)
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "binfhecontext.h"
#include "time.h"
#include <bitset>
#include "fhew.h"


using namespace lbcrypto;
using namespace std;






int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // STD128 is the security level of 128 bits of security based on LWE
    // Estimator and HE standard. Other common options are TOY, MEDIUM, STD192,
    // and STD256. MEDIUM corresponds to the level of more than 100 bits for
    // both quantum and classical computer attacks.
    cc.GenerateBinFHEContext(STD128Q);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)

    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, FRESH);

    unsigned seed;
    seed = time(0);
    srand(seed);

    int bt1 = 3;  //第一次位移比特

    int bts = 4;  //每次位移比特数

    int pp = (int)(((double)rand() / RAND_MAX) * ((int)1 <<21));  //19

    //  int pp = (int)(1 << 18) - (1 << 12);
    NativeInteger q = cc.GetParams()->GetLWEParams()->Getq();

    auto ct1 = cc.Encrypt1(sk, pp, FRESH, 17);

    cout << "input message (20 bit-wise)=" << bitset<17>(pp) << endl;

    LWEPlaintext resultpp;

    cc.Decrypt1(sk, ct1, &resultpp, 29);

    cout << "message + noise (29-bit) =" << bitset<29>(resultpp) << endl;

    //削去头部
    LWEPlaintext resultpp2;

    auto ctt = cc.Bootstrap01(ct1);

    ct1 = ciphersub(ct1, ctt, q);

    cc.Decrypt1(sk, ct1, &resultpp2, 29);

    cout << "input - q/4=" << bitset<29>(resultpp2) << endl;

    //位移 bt1

    auto ct21 = cc.Bootstrap(ct1, 1);

    auto ct3n = ciphersub(ct1, ct21, q);

    LWEPlaintext resultpp3;

    cc.Decrypt1(sk, ct3n, &resultpp3, 29);

    cout << "1-st jianwan=" << bitset<29>(resultpp3) << endl;

    q = q >> bt1;
    ct1 = ciphermod(ct3n, q);

    cc.msq(bt1);

    LWECiphertext sct1;

    int yy = 4;

    clock_t start = clock();  //时间起始
    /*待测试代码*/

    for (int i = 0; i < yy; i++) {
      int btsi = bts * i + bt1;

      auto ct2 = cc.Bootstrap(ct1, 1 << btsi);

      auto ct3 = ciphersub(ct1, ct2, q);

      LWEPlaintext result31;

      // int32_t p20 = int(pow(2, 20) + 0.5);
      // int32_t p15 = int(pow(2, 15) + 0.5);

      if (i > 0) cc.mzq(btsi);

      cc.Decrypt1(sk, ct2, &result31, 29);

      cout << "ziju msq =" << bitset<29>(result31) << endl;

      if (i > 0) cc.msq(btsi);

      if (i == 0)
        sct1 = ct2;
      else
        sct1 = cipheradd(sct1, ct2, q << btsi);

      // NativeInteger cc.GetParams()->GetLWEParams()->Getq() -= 3 ;

      // Sample Program: Step 4: Evaluation

      // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
      //  auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);

      // Compute (NOT 1) = 0
      // auto ct2Not = cc.EvalNOT(ct2);

      // Compute (1 AND (NOT 1)) = 0
      // auto ctAND2 = cc.EvalBinGate(AND, ct2Not, ct1);

      // Computes OR of the results in ctAND1 and ctAND2 = 1
      //  auto ctResult = cc.EvalBinGate(OR, ctAND1, ctAND2);

      // Sample Program: Step 5: Decryption

      LWEPlaintext result;

      cc.Decrypt1(sk, ct3, &result, 17 - btsi);

      cout << "jianwan result =" << bitset<17>(result) << endl;

      if (i > 0) cc.mzq(btsi);

      LWEPlaintext resultc;

      cc.Decrypt1(sk, sct1, &resultc, 29);

      cout << "stc result = =" << bitset<29>(resultc) << endl;

      if (i > 0) cc.msq(btsi);

      // int32_t p20 = int(pow(2, 20) + 0.5);
      // int32_t p15 = int(pow(2, 15) + 0.5);

      q = q >> bts;
      ct1 = ciphermod(ct3, q);

      cc.msq(bts);
    }

    clock_t end = clock();  //时间测试结束

    cout << "running time=  " << end - start << endl;

    cc.mzq(bts * yy + bt1);

    sct1 = cipheradd(sct1, ctt, q << (bts * yy + bt1));

    sct1 = cipheradd(sct1, ct21, q << (bts * yy + bt1));

    LWEPlaintext result;

    // int32_t p20 = int(pow(2, 20) + 0.5);
    // int32_t p15 = int(pow(2, 15) + 0.5);

    cc.Decrypt1(sk, sct1, &result, 17);

    cout << "decryption result (20 bit-wise) =" << bitset<17>(result) << endl;

    cout << "input message (20 bit-wise)=" << bitset<17>(pp) << endl;

    return 0;
};

