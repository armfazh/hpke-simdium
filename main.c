#include "x25519_ossl.h"
#include "x25519_bssl.h"
#include "dhkem_ossl.h"
#include "dhkem_bssl.h"

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
  // main_dhkem_bssl();

  return 0;
}
