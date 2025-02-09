#include "x25519.h"

#include <stdio.h>

int main_x25519(struct xdh *x)
{
    u8_static(aSk, 32);
    u8_static(aPk, 32);
    x->keygen(&aSk, &aPk);
    printf("sk: ");
    u8_print(&aSk);
    printf("pk: ");
    u8_print(&aPk);

    u8_static(bSk, 32);
    u8_static(bPk, 32);
    x->keygen(&bSk, &bPk);
    printf("sk: ");
    u8_print(&bSk);
    printf("pk: ");
    u8_print(&bPk);

    u8_static(aliceShared, 32);
    u8_static(bobShared, 32);

    x->shared(&aliceShared, &aSk, &bPk);
    printf("ss: ");
    u8_print(&aliceShared);

    x->shared(&bobShared, &bSk, &aPk);
    printf("ss: ");
    u8_print(&bobShared);

    return 0;
}
