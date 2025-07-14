#ifndef BINFHE_LPSTEST_H
#define BINFHE_LPTEST_H

#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

std::pair<double,int> TestA(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);
void TestB(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);
void TestC(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);
void TestD(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);

std::pair<double,int> TestH(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);

void TestHL(BinFHEContext LPfhe, LWEPrivateKey sk,double sigma);

std::pair<double,int> TestE(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);

void TestEL(BinFHEContext LPfhe, LWEPrivateKey sk, double sigma);

int main();

#endif