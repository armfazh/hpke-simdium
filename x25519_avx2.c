#include "x25519_avx2.h"

#include <stdio.h>
#include <faz_ecdh_avx2.h>

void keygen_avx2(u8 *sk, u8 *pk)
{
    X25519.randKey(sk->data);
    X25519.keygen(pk->data, sk->data);
}

void shared_avx2(u8 *shared_secret, u8 *sk, u8 *pk)
{
    X25519.shared(shared_secret->data, pk->data, sk->data);
}

int main_x25519_avx2()
{
    X25519_KEY alice_private, alice_session, alice_shared;
    X25519_KEY bob_private, bob_session, bob_shared;

    printf("=== X25519 Example ===\n");

    /* Alice session key generation */
    X25519.randKey(alice_private);
    printf("Alice private key: \n");
    X25519.printKey(stdout, alice_private);
    X25519.keygen(alice_session, alice_private);
    printf("Alice session key: \n");
    X25519.printKey(stdout, alice_session);

    /* Bob session key generation */
    X25519.randKey(bob_private);
    printf("Bob private key: \n");
    X25519.printKey(stdout, bob_private);
    X25519.keygen(bob_session, bob_private);
    printf("Bob session key: \n");
    X25519.printKey(stdout, bob_session);

    /* Shared secret generation */
    X25519.shared(alice_shared, bob_session, alice_private);
    printf("Alice shared secret: \n");
    X25519.printKey(stdout, alice_shared);
    X25519.shared(bob_shared, alice_session, bob_private);
    printf("Bob shared secret: \n");
    X25519.printKey(stdout, bob_shared);

    return 0;
}
