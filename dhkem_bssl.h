/**
 * This file is part of hpke-simdium.
 *
 * Copyright 2025 Armando Faz Hernandez.
 *
 * Licensed under the Mozilla Public License, v. 2.0. You may not use this
 * file except in compliance with the License.
 * You can obtain a copy of the License at:
 *
 * https://www.mozilla.org/en-US/MPL/2.0/
 *
 * SPDX-License-Identifier: MPL-2.0
 */
#ifndef _DHKEM_BSSL_H_
#define _DHKEM_BSSL_H_

int main_dhkem_bssl(void);
int main_auth_dhkem_bssl(void);
void bench_dhkem_encapdecap_bssl(void);
void bench_dhkem_auth_encapdecap_bssl(void);

#endif /* _DHKEM_BSSL_H_ */
