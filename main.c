#include "x25519.h"
#include "kdf.h"
#include "dhkem.h"

#include <openssl/evp.h>
#include <openssl/err.h>

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // main_x25519();
  // main_kdf();
  main_dhkem();

  return 0;
}
