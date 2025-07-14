// @file binfhecontext.cpp - Implementation file for Boolean Circuit FHE context
// class
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

namespace lbcrypto {

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N,
                                          const NativeInteger &q,
                                          const NativeInteger &Q, double std,
                                          uint32_t baseKS, uint32_t baseG,
                                          uint32_t baseR, BINFHEMETHOD method) {
  auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, std, baseKS);
  m_params =
      std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseR, method);
}

void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set,
                                          BINFHEMETHOD method) {
  shared_ptr<LWECryptoParams> lweparams;
  NativeInteger Q;
  switch (set) {
    case TOY:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1024),
                                       1024);
      lweparams = std::make_shared<LWECryptoParams>(64, 512, 512, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 23, method);
      break;
    case MEDIUM:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(256, 1024, 512, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 23, method);
      break;
    case STD128_AP:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 512, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 23, method);
      break;
    case STD128:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams = std::make_shared<LWECryptoParams>(
          512, 1024, 1 << 22, Q, 3.19,
          25);  // LWECryptoParams(uint32_t n LWEά��, uint32_t N
                // RGSWά��, const NativeInteger &q LWEģ��, const NativeInteger
                // &Q RSGWģ��, double std, uint32_t baseKS)
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 4, 23, method);  // lwe������baseG �ֽ����  7 , uint32_t baseR (������AP�Ծ�), method)
      break;
    case STD192:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(37, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 2048, (int) pow(2,20), Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 23, method);
      break;
    case STD256:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1 << 12),
                                       1 << 12);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1 << 25, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 32, method); // lwe������baseG �ֽ����  , uint32_t baseR (������AP�Ծ�), method)
      break;
    case STD128Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(60, 1<<12),
                                       1 << 12);
      lweparams =
          std::make_shared<LWECryptoParams>(1<<9, 1<<11, 1<< 29  , Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 <<15, 7, method);  // lwe������baseG �ֽ����  , uint32_t baseR (������AP�Ծ�), method)
      break;
    case STD192Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(35, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1<<29, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 32, method);
      break;
    case STD256Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 32, method);
      break;
    case SIGNED_MOD_TEST:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(28, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 512, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 23, method);
      break;
    default:
      std::string errMsg = "ERROR: No such parameter set exists for FHEW.";
      PALISADE_THROW(config_error, errMsg);
  }
}

LWEPrivateKey BinFHEContext::KeyGen() const {
  return m_LWEscheme->KeyGen(m_params->GetLWEParams());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
  return m_LWEscheme->KeyGenN(m_params->GetLWEParams());
}



LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey sk,
                                     const LWEPlaintext &m,
                                     BINFHEOUTPUT output) const {
  if (output == FRESH) {
    return m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m);
  } else {
    auto ct = m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m);
    return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct, m_LWEscheme,1);
  }
}







LWECiphertext BinFHEContext::Encrypt1(ConstLWEPrivateKey sk,
                                     const LWEPlaintext &m,
                                     BINFHEOUTPUT output, int32_t bin) const {
  if (output == FRESH) {
    return m_LWEscheme->Encrypt1(m_params->GetLWEParams(), sk, m ,bin);
  } else {
    auto ct = m_LWEscheme->Encrypt1(m_params->GetLWEParams(), sk, m, bin);
    return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct, m_LWEscheme,1);
  }
}






void BinFHEContext::Decrypt1(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                            LWEPlaintext *result, int32_t bin) const {
  return m_LWEscheme->Decrypt1(m_params->GetLWEParams(), sk, ct, result, bin);
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                            LWEPlaintext *result) const {
  return m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result);
}

std::shared_ptr<LWESwitchingKey> BinFHEContext::KeySwitchGen(
    ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const {
  return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey sk) {
  m_BTKey = m_RingGSWscheme->KeyGen(m_params, m_LWEscheme, sk);
  return;
}



LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate,
                                         ConstLWECiphertext ct1,
                                         ConstLWECiphertext ct2) const {
  return m_RingGSWscheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2,
                                      m_LWEscheme);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext ct1, int scale) const {
  return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct1, m_LWEscheme, scale);
}


LWECiphertext BinFHEContext::Bootstrap01(ConstLWECiphertext ct1) const {
  return m_RingGSWscheme->Bootstrap01(m_params, m_BTKey, ct1, m_LWEscheme);
}



LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext ct) const {
  return m_RingGSWscheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
  return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
}


}  // namespace lbcrypto
