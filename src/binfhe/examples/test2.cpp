#include <time.h>

#include "binfhecontext.h"
#include "fhew.h"

using namespace lbcrypto;
using namespace std;

int main() { 
   NativeInteger q = 1 << 29;

  uint32_t n = 1024;
  uint32_t N = 1 << 11;
  NativeInteger Q =
      PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096), 4096);
  //uint32_t BK = 25;
  double std = 3.19;
  uint32_t Bg = 1 << 15;
  uint32_t dg = 4;

  double std_acc = sqrt((double(4*dg*n*N)/6)*std*std);
  std::cout << "acc*Bg "<< 6 * std_acc << std::endl;
  double std_ks = sqrt(double(n * 12 )* std * std);
  std::cout << "ks " << 6 * std_ks << std::endl;
  double std_mds = sqrt((1 + 2 * double(n) / 3) / 12);
  std::cout << "mds "<<6 * std_mds << std::endl;
  double std_boot = sqrt((std_acc * std_acc * Bg * Bg + std_ks * std_ks) *
                         (q.ConvertToDouble() / Q.ConvertToDouble()) *
                         (q.ConvertToDouble() / Q.ConvertToDouble())+std_mds*std_mds);
  std::cout << 6 * std_boot << std::endl;
  q = 1 << 27;
  std_boot = sqrt((std_acc * std_acc * Bg * Bg + std_ks * std_ks) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) +
                         std_mds * std_mds);
  std::cout << 6 * std_boot << std::endl;
  q = 1 << 25;
  std_boot = sqrt((std_acc * std_acc * Bg * Bg + std_ks * std_ks) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) +
                         std_mds * std_mds);
  std::cout << 6 * std_boot << std::endl;
  q = 1 << 24;
  std_boot = sqrt((std_acc * std_acc * Bg * Bg + std_ks * std_ks) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) +
                         std_mds * std_mds);
  std::cout << 6 * std_boot << std::endl;
  q = 1 << 23;
  std_boot = sqrt((std_acc * std_acc * Bg * Bg + std_ks * std_ks) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) *
                             (q.ConvertToDouble() / Q.ConvertToDouble()) +
                         std_mds * std_mds);
  std::cout << 6 * std_boot << std::endl;

  int a[10] = {-3, - 5, - 6, 2 ,14 ,5 ,- 1 ,10 ,8 ,- 15};
  int sum = a[0] * a[0];
  for (uint32_t i = 1; i < 10; i++) sum += a[i] * a[i];
  double sigma = sqrt(sum) / 3;
  std::cout << sigma << std::endl;

   
}
