#include "x25519_ossl.h"
#include "x25519_avx2.h"
#include "kdf.h"
#include "dhkem.h"
#include "dhkem_ossl.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

  // main_kdf();
  // main_dhkem();
  // main_auth_dhkem();
  // main_x25519_ossl();
  // main_x25519_avx2();
  main_dhkem_ossl();

  return 0;
}
