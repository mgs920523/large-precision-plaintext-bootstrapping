#include <time.h>

#include "binfhecontext.h"
#include "fhew.h"
#include "booleanours.h"
#include "ringcore.h"

using namespace lbcrypto;
using namespace std;

NativeInteger Id(NativeInteger x, uint64_t t) { return x.Mod(t); }
NativeInteger f_0(NativeInteger x,uint64_t t) { 
    NativeInteger result = 1;
  NativeInteger poly = x * 3;
    result.ModSubEq(poly, t);//1-3x;
  poly = x * x;
    poly.ModMulEq(4 * x,t);
  result.ModAddEq(poly,t);//1-3x+4x^3
    return result; }





int main() {
	auto start = std::chrono::high_resolution_clock::now();
  auto cc = BinFHEContext();
  /*………………………………………………参数设置，密钥生成………………………………………………*/

  uint32_t N = 1024*2;
  //auto crt = CRTParams();
  //crt.Initialize<uint32_t,uint64_t>(N, 31,32,29);
  uint32_t r = 2;
  uint64_t t = 1 << 12;        // crt.GenerateT();
  NativeInteger q = 1 << 19;  // 128 * t;
  NativeInteger Q;
  Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 1024*4), 1024*4);

  cc.GenerateBinFHEContext(1024, N, q, t, Q, Q, 3.19, 25, 1 << 15, 32, r,
                           GINXOURS);//n,N,q,t,Q,qks,std,baseks,baseG,baseR,r,method;
  //GINX;
  auto sk = cc.KeyGen();

  std::cout << "Generating the bootstrapping keys..." << std::endl;

  cc.BTKeyGen(sk);

 


size_t totalMemoryUsage = 0;

// 获取 Refresh Key 对象
auto refreshKey = cc.GetRefreshKey();
auto elements = refreshKey->GetElements(); // 最外层元素数组

// 遍历所有层次
for (const auto& elementLevel1 : elements) {
  for (const auto& elementLevel2 : elementLevel1) {
    for (const auto& elementLevel3 : elementLevel2) {
      // 获取第三级元素的子元素
      auto subElements = elementLevel3.GetElements();

      for (const auto& subElementLevel1 : subElements) {
        for (const auto& subElementLevel2 : subElementLevel1) {
          // 获取多项式值
          for (size_t i = 0; i < subElementLevel2.GetValues().GetLength(); i++) {
            totalMemoryUsage += subElementLevel2.GetValues()[i].GetLengthForBase(2);
          }
        }
      }
    }
  }
}


  std::cout <<  "N=2^11, r=2: Our Memory (MB) " << static_cast<double>(totalMemoryUsage) / (8 * 1024 * 1024) << std::endl;
  
 auto cc1 = BinFHEContext();
  /*………………………………………………参数设置，密钥生成………………………………………………*/

  uint32_t N1 = 1 << 12;
  //auto crt = CRTParams();
  //crt.Initialize<uint32_t,uint64_t>(N, 31,32,29);
  uint32_t r1 = 1;
  uint64_t t1 = 1 << 12;        // crt.GenerateT();
  NativeInteger q1 = 1 << 19;  // 128 * t;
  NativeInteger Q1;
  Q1 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, N1*2), N1*2);

  cc1.GenerateBinFHEContext(1024, N1, q1, t1, Q1, Q1, 3.19, 25, 1 << 15, 32, r1,
                           GINX);//n,N,q,t,Q,qks,std,baseks,baseG,baseR,r,method;
  //GINX;
  auto sk1 = cc1.KeyGen();

  std::cout << "Generating the bootstrapping keys..." << std::endl;

  cc1.BTKeyGen(sk1);



size_t totalMemoryUsage2 = 0;

// 获取 Refresh Key 对象
auto refreshKey1 = cc1.GetRefreshKey();
auto elements2 = refreshKey1->GetElements(); // 最外层元素数组

// 遍历所有层次
for (const auto& elementLevel1 : elements2) {
  for (const auto& elementLevel2 : elementLevel1) {
    for (const auto& elementLevel3 : elementLevel2) {
      // 获取第三级元素的子元素
      auto subElements = elementLevel3.GetElements();

      for (const auto& subElementLevel1 : subElements) {
        for (const auto& subElementLevel2 : subElementLevel1) {
          // 获取多项式值
          for (size_t i = 0; i < subElementLevel2.GetValues().GetLength(); i++) {
            totalMemoryUsage2 += subElementLevel2.GetValues()[i].GetLengthForBase(2);
          }
        }
      }
    }
  }
}


  std::cout <<  "N=2^12: Prvious Memory (MB)" <<static_cast<double>(totalMemoryUsage2) / (8 * 1024 * 1024) << std::endl;

    auto end = std::chrono::high_resolution_clock::now();

    // 计算持续时间并转换为毫秒
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "运行时间: " << duration.count() << " 毫秒" << std::endl;

     /*………………………………………………………………………………………………………………………………
     auto result1 = Id(NativeInteger(m), t);
     std::cout << "Id " << result1.ConvertToInt() << std::endl;
     clock_t begin = clock();
     auto ct_crt = cc.CRTFunBootstrap(crt, cp, Id);
     clock_t end = clock();
     cost = double(end - begin) / CLOCKS_PER_SEC;
     cc.Decryptours(sk, ct_crt, &result);
     std::cout << "Bootstrap result " << result << std::endl;
     std::cout << "run time of Bootstrapping procedure is " << cost
               << std::endl;

     result1 = f_0(NativeInteger(m), t);
     std::cout << "f_0 " << result1.ConvertToInt() << std::endl;
     clock_t begin1 = clock();
     ct_crt = cc.CRTFunBootstrap(crt, cp, f_0);
     clock_t end1 = clock();
     cost = double(end1 - begin1) / CLOCKS_PER_SEC;
     cc.Decryptours(sk, ct_crt, &result);

     std::cout << "Bootstrap result " << result << std::endl;
     std::cout << "run time of Bootstrapping procedure is " << cost
               << std::endl;
   }
   */
}