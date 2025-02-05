#include "x25519_ossl.h"
#include "x25519_avx2.h"
#include "kdf.h"
#include "dhkem.h"

#include <openssl/evp.h>
#include <openssl/err.h>

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // main_kdf();
  main_dhkem();
  main_auth_dhkem();
  // main_x25519_ossl();
  // main_x25519_avx2();

  return 0;
}
