// #include "x25519.h"
// #include "kdf.h"
// #include "dhkem.h"
// #include "dhkem_ossl.h"
#include "x25519_bssl.h"
#include "x25519_ossl.h"

int main()
{
  info_ossl();
  info_bssl();
  // main_kdf();
  // main_dhkem();
  // main_auth_dhkem();
  // main_x25519_ossl();
  // main_x25519(&XDH_OSSL);
  // main_dhkem_ossl();

  return 0;
}
