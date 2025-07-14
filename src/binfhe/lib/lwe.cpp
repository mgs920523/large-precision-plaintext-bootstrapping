// @file lwe.cpp - LWE Encryption Scheme implementation as described in
// https://eprint.iacr.org/2014/816 Full reference:
// @misc{cryptoeprint:2014:816,
//   author = {Leo Ducas and Daniele Micciancio},
//   title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
//   howpublished = {Cryptology ePrint Archive, Report 2014/816},
//   year = {2014},
//   note = {\url{https://eprint.iacr.org/2014/816}},
// @author TPOC: contact@palisade-crypto.org
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

#include "lwe.h"
#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"

namespace lbcrypto {

std::shared_ptr<LWEPrivateKeyImpl> LWEEncryptionScheme::KeyGen(
    const std::shared_ptr<LWECryptoParams> params) const {
  TernaryUniformGeneratorImpl<NativeVector> tug;
  return std::make_shared<LWEPrivateKeyImpl>(
      LWEPrivateKeyImpl(tug.GenerateVector(params->Getn(), params->Getq())));
}

std::shared_ptr<LWEPrivateKeyImpl> LWEEncryptionScheme::KeyGenN(
    const std::shared_ptr<LWECryptoParams> params) const {
  TernaryUniformGeneratorImpl<NativeVector> tug;
  return std::make_shared<LWEPrivateKeyImpl>(
      LWEPrivateKeyImpl(tug.GenerateVector(params->GetN(), params->GetQ())));
}

// classical LWE encryption
// a is a randomly uniform vector of dimension n; with integers mod q
// b = a*s + e + m floor(q/4) is an integer mod q
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::Encrypt(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const LWEPlaintext &m) const {
  NativeInteger q = sk->GetElement().GetModulus();
  uint32_t n = sk->GetElement().GetLength();

  NativeInteger b = (m % 4) * (q >> 2) + params->GetDgg().GenerateInteger(q);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);
  NativeVector a = dug.GenerateVector(n);

  NativeInteger mu = q.ComputeMu();

  const NativeVector &s = sk->GetElement();
  for (uint32_t i = 0; i < n; ++i) {
    b += a[i].ModMulFast(s[i], q, mu);
  }
  b.ModEq(q);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

/*��������������������������������������Ϊ���ǵĲ��䡭����������������������������������������*/

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::Encryptours(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const LWEPlaintext &m) const {
  NativeInteger q = sk->GetElement().GetModulus();
  uint32_t n = sk->GetElement().GetLength();
  uint64_t t = params->GetT();

  NativeInteger b = (m % t);
  b = b.MultiplyAndRound(q, t) + params->GetDgg().GenerateInteger(q);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);
  NativeVector a = dug.GenerateVector(n);

  NativeInteger mu = q.ComputeMu();

  const NativeVector &s = sk->GetElement();
  for (uint32_t i = 0; i < n; ++i) {
    b += a[i].ModMulFast(s[i], q, mu);
  }
  b.ModEq(q);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::Encryptours(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const LWEPlaintext &m,double std) const {
  NativeInteger q = sk->GetElement().GetModulus();
  uint32_t n = sk->GetElement().GetLength();
  uint64_t t = params->GetT();

  NativeInteger b = (m % t);
  DiscreteGaussianGeneratorImpl<NativeVector> dgg;
  if (std < 300.0) {
    dgg.SetStd(std);
    b = b.MultiplyAndRound(q, t) + dgg.GenerateInteger(q);
  } else {
    uint32_t l = log(std) / log(32);
    uint64_t sum = 1;
    for (uint32_t i = 0; i < l; i++) sum += pow(32, 2 * i + 2);
    double std1 = std / sqrt(sum);
    dgg.SetStd(std1);
    NativeInteger err = dgg.GenerateInteger(q);
    for (uint32_t i = 0; i < l; i++) {
      err += dgg.GenerateInteger(q) * uint64_t(pow(32, i + 1));
    }
    b = b.MultiplyAndRound(q, t) + err;
  }

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);
  NativeVector a = dug.GenerateVector(n);

  NativeInteger mu = q.ComputeMu();

  const NativeVector &s = sk->GetElement();
  for (uint32_t i = 0; i < n; ++i) {
    b += a[i].ModMulFast(s[i], q, mu);
  }
  b.ModEq(q);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}


int LWEEncryptionScheme::Errortours(
  const std::shared_ptr<LWECryptoParams> params,
  const std::shared_ptr<const LWEPrivateKeyImpl> sk,
  const std::shared_ptr<const LWECiphertextImpl> ct) const {
NativeVector a = ct->GetA();
uint32_t n = sk->GetElement().GetLength();
NativeVector s = sk->GetElement();
NativeInteger q = sk->GetElement().GetModulus();
uint64_t t = params->GetT();

NativeInteger mu = q.ComputeMu();

NativeInteger inner(0);
for (uint32_t i = 0; i < n; ++i) {
  inner += a[i].ModMulFast(s[i], q, mu);
}
inner.ModEq(q);

NativeInteger r = ct->GetB();
r.ModSubFastEq(inner, q);
NativeInteger errval = r - r.MultiplyAndRound(t, q) * q / t;
//std::cout << "err= " << errval<< std::endl;
return errval.ConvertToInt();
}


void LWEEncryptionScheme::Decryptours(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const std::shared_ptr<const LWECiphertextImpl> ct,
    LWEPlaintext *result) const {
  NativeVector a = ct->GetA();
  uint32_t n = sk->GetElement().GetLength();
  NativeVector s = sk->GetElement();
  NativeInteger q = sk->GetElement().GetModulus();
  uint64_t t = params->GetT();

  NativeInteger mu = q.ComputeMu();

  NativeInteger inner(0);
  for (uint32_t i = 0; i < n; ++i) {
    inner += a[i].ModMulFast(s[i], q, mu);
  }
  inner.ModEq(q);

  NativeInteger r = ct->GetB();
  r.ModSubFastEq(inner, q);
  //auto err = r - r.MultiplyAndRound(t, q) * q / t;
  //int error = err.ConvertToInt();
  //std::cout << "err= " << error<< std::endl;
  r.MultiplyAndRoundEq(t,q);
  *result = r.Mod(t).ConvertToInt();


/* #if defined (BINFHE_DEBUG)
  double error = (4.0 * (r.ConvertToDouble() - q.ConvertToInt() / 8)) /
                     q.ConvertToDouble() -
                 static_cast<double>(*result);
  std::cerr << "error:\t" << error << std::endl;
#endif*/

  return;
}

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::HomomorphicOperator(
    const std::shared_ptr<const LWECiphertextImpl> ct1,
    const std::shared_ptr<const LWECiphertextImpl> ct2, 
    const OperatorType Operator) const {
  NativeVector a1 = ct1->GetA();
  NativeVector a2 = ct2->GetA();
  NativeInteger b1 = ct1->GetB();
  NativeInteger b2 = ct2->GetB();

  NativeInteger q = a1.GetModulus();
  NativeInteger q2 = a2.GetModulus();
  uint32_t n = a1.GetLength();
  uint32_t n2 = a2.GetLength();

  if ((q != q2) || (n != n2)) {
    std::string errMsg =
        "ERROR: It is invalid for any operatoration between ciphertexts.";
    PALISADE_THROW(config_error, errMsg);
  }
  if (Operator==Mul) {
    std::string errMsg =
        "ERROR: Multiplication between two ciphertexts has never defined.";
    PALISADE_THROW(config_error, errMsg);
  }

  if (Operator == Add) {
    for (uint32_t i = 0; i < n; i++) a1[i].ModAddEq(a2[i], q);
    b1.ModAddEq(b2, q);
  } 
  else if (Operator == Sub) {
    for (uint32_t i = 0; i < n; i++) a1[i].ModSubEq(a2[i], q);
    b1.ModSubEq(b2, q);
  }

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a1, b1));

}

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::CipherMod(
    const std::shared_ptr<const LWECiphertextImpl> ct, NativeInteger q) const {
  NativeInteger b = ct->GetB();
  NativeVector a = ct->GetA();
  uint32_t n = a.GetLength();

  if (a.GetModulus() % q.ConvertToInt() != 0) {
    std::string errMsg =
        "ERROR: New modulus is not a factor of old one.";
    PALISADE_THROW(config_error, errMsg);
  }

  for (uint32_t i = 0; i < n; i++) a[i].ModEq(q);
  b.ModEq(q);
  a.SetModulus(q);
  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
    
}

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::CipherRescaling(
    const std::shared_ptr<const LWECiphertextImpl> ct, uint32_t block) const {
  NativeInteger b = ct->GetB();
  NativeVector a = ct->GetA();
  uint32_t n = a.GetLength();
  NativeInteger q = a.GetModulus();

  if (q % block != 0) {
    std::string errMsg = "ERROR: Rescaling factor can not devide modulus.";
    PALISADE_THROW(config_error, errMsg);
  }

  q /= block;
  for (uint32_t i = 0; i < n; i++) a[i].DivideAndRoundEq(block);
  b.DivideAndRoundEq(block);
  a.SetModulus(q);
  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));

}
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::ChangeMod(
    const std::shared_ptr<const LWECiphertextImpl> ct, NativeInteger q) const {
  NativeInteger b = ct->GetB();
  NativeVector a = ct->GetA();
  a.SetModulus(q);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::ScalarOperator(
    const std::shared_ptr<const LWECiphertextImpl> ct, NativeInteger value,const OperatorType Operator) const {

  NativeVector a = ct->GetA();
  NativeInteger b = ct->GetB();
  uint32_t n = a.GetLength();
  NativeInteger q = a.GetModulus();

  if (Operator == Add)
    b += value;
  else if (Operator == Sub)
    b -= value;
  else if (Operator == Mul) {
    for (uint32_t i = 0; i < n; i++) a[i].ModMulEq(value, q);
    b.ModMulEq(value, q);
  }

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

/*��������������������������������������������������������������������������������������������*/

// classical LWE decryption
// m_result = Round(4/q * (b - a*s))
void LWEEncryptionScheme::Decrypt(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const std::shared_ptr<const LWECiphertextImpl> ct,
    LWEPlaintext *result) const {
  // TODO in the future we should add a check to make sure sk parameters match
  // the ct parameters

  // Create local variables to speed up the computations
  NativeVector a = ct->GetA();
  uint32_t n = sk->GetElement().GetLength();
  NativeVector s = sk->GetElement();
  NativeInteger q = sk->GetElement().GetModulus();

  NativeInteger mu = q.ComputeMu();

  NativeInteger inner(0);
  for (uint32_t i = 0; i < n; ++i) {
    inner += a[i].ModMulFast(s[i], q, mu);
  }
  inner.ModEq(q);

  NativeInteger r = ct->GetB();

  r.ModSubFastEq(inner, q);

  // Alternatively, rounding can be done as
  // *result = (r.MultiplyAndRound(NativeInteger(4),q)).ConvertToInt();
  // But the method below is a more efficient way of doing the rounding
  // the idea is that Round(4/q x) = q/8 + Floor(4/q x)
  r.ModAddFastEq((q >> 3), q);
  *result = ((NativeInteger(4) * r) / q).ConvertToInt();

#if defined(BINFHE_DEBUG)
  double error = (4.0 * (r.ConvertToDouble() - q.ConvertToInt() / 8)) /
                     q.ConvertToDouble() -
                 static_cast<double>(*result);
  std::cerr << "error:\t" << error << std::endl;
#endif

  return;
}

// the main rounding operation used in ModSwitch (as described in Section 3 of
// https://eprint.iacr.org/2014/816) The idea is that Round(x) = 0.5 + Floor(x)
NativeInteger RoundqQ(const NativeInteger &v, const NativeInteger &q,
                      const NativeInteger &Q) {
  return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() *
                                                      q.ConvertToDouble() /
                                                      Q.ConvertToDouble()))
      .Mod(q);
}

// Modulus switching - directly applies the scale-and-round operation RoundQ
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::ModSwitch(
    NativeInteger q, const std::shared_ptr<const LWECiphertextImpl> ctQ) const {
  auto n = ctQ->GetA().GetLength();
  auto Q = ctQ->GetA().GetModulus();

  NativeVector a(n, q);
  for (uint32_t i = 0; i < n; ++i) a[i] = RoundqQ(ctQ->GetA()[i], q, Q);
  NativeInteger b = RoundqQ(ctQ->GetB(), q, Q);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// Switching key as described in Section 3 of https://eprint.iacr.org/2014/816
std::shared_ptr<LWESwitchingKey> LWEEncryptionScheme::KeySwitchGen(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const std::shared_ptr<const LWEPrivateKeyImpl> skN) const {
  // Create local copies of main variables
  uint32_t n = params->Getn();
  uint32_t N = params->GetN();
  NativeInteger Q = params->GetqKS();
  uint32_t baseKS = params->GetBaseKS();
  std::vector<NativeInteger> digitsKS = params->GetDigitsKS();
  uint32_t expKS = digitsKS.size();

  // newSK stores negative values using modulus q
  // we need to switch to modulus Q
  NativeVector newSK = sk->GetElement();
  newSK.SwitchModulus(Q);

  NativeVector oldSKlargeQ = skN->GetElement();
  NativeVector oldSK(oldSKlargeQ.GetLength(), Q);
  for(size_t i = 0; i < oldSK.GetLength(); i++){
    if((oldSKlargeQ[i] == 0) || (oldSKlargeQ[i] == 1)){
      oldSK[i] = oldSKlargeQ[i];
    }
    else {
      oldSK[i] = Q - 1;
    }
  }

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(Q);

  NativeInteger mu = Q.ComputeMu();

  std::vector<std::vector<std::vector<LWECiphertextImpl>>> resultVec(N);

#pragma omp parallel for
  for (uint32_t i = 0; i < N; ++i) {
    std::vector<std::vector<LWECiphertextImpl>> vector1(baseKS);
    for (uint32_t j = 0; j < baseKS; ++j) {
      std::vector<LWECiphertextImpl> vector2(expKS);
      for (uint32_t k = 0; k < expKS; ++k) {
        NativeInteger b = (params->GetDgg().GenerateInteger(Q))
                              .ModAdd(oldSK[i].ModMul(j * digitsKS[k], Q), Q);

        NativeVector a = dug.GenerateVector(n);

#if NATIVEINT == 32
        for (uint32_t ii = 0; ii < n; ++ii) {
          b.ModAddFastEq(a[ii].ModMulFast(newSK[ii], Q, mu), Q);
        }
#else
        for (uint32_t ii = 0; ii < n; ++ii) {
          b += a[ii].ModMulFast(newSK[ii], Q, mu);
        }
        b.ModEq(Q);
#endif

        vector2[k] = LWECiphertextImpl(a, b);
      }
      vector1[j] = std::move(vector2);
    }
    resultVec[i] = std::move(vector1);
  }

  return std::make_shared<LWESwitchingKey>(LWESwitchingKey(resultVec));
}

// the key switching operation as described in Section 3 of
// https://eprint.iacr.org/2014/816
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::KeySwitch(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<LWESwitchingKey> K,
    const std::shared_ptr<const LWECiphertextImpl> ctQN) const {
  uint32_t n = params->Getn();
  uint32_t N = params->GetN();
  NativeInteger Q = params->GetqKS();
  uint32_t baseKS = params->GetBaseKS();
  std::vector<NativeInteger> digitsKS = params->GetDigitsKS();
  uint32_t expKS = digitsKS.size();

  // creates an empty vector
  NativeVector a(n, Q);
  NativeInteger b = ctQN->GetB();
  NativeVector aOld = ctQN->GetA();

  for (uint32_t i = 0; i < N; ++i) {
    NativeInteger atmp = aOld[i];
    for (uint32_t j = 0; j < expKS; ++j, atmp /= baseKS) {
      uint64_t a0 = (atmp % baseKS).ConvertToInt();
      for (uint32_t k = 0; k < n; ++k)
        a[k].ModSubFastEq((K->GetElements()[i][a0][j]).GetA()[k], Q);
      b.ModSubFastEq((K->GetElements()[i][a0][j]).GetB(), Q);
    }
  }

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

// noiseless LWE embedding
// a is a zero vector of dimension n; with integers mod q
// b = m floor(q/4) is an integer mod q
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::NoiselessEmbedding(
    const std::shared_ptr<LWECryptoParams> params,
    const LWEPlaintext &m) const {
  NativeInteger q = params->Getq();
  uint32_t n = params->Getn();

  NativeVector a(n, q);
  for (uint32_t i = 0; i < n; ++i) a[i] = 0;

  NativeInteger b = m * (q >> 2);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}
};  // namespace lbcrypto
