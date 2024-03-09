/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_gpio.h"
#include "fsl_clock.h"
#include <aes_encryption.h>
#include <aes_encryption.h>
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define HASH_LEN 32
#define KEY_IN_BITS 1024
#define KEY_LEN KEY_IN_BITS/8

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

/*!
 * @brief Main function
 */
int main(void)
{
	uint8_t plaintext[111] = {"Este es el proyecto final de la materia ingenieria de software y seguridad para sistemas embebidos - Noe Ortiz"};
	uint8_t key[] = {0x03, 0x68, 0x22, 0xA9, 0x04, 0xAA, 0x41, 0x6E, 0x11, 0xFE, 0x3E, 0x5B, 0xC9, 0x8C, 0xA1, 0x33};
	uint8_t iv[]  = {0x76, 0x25, 0x11, 0x4E, 0x1E, 0xEE, 0xAA, 0x9B, 0x5A, 0x31, 0x5C, 0x15, 0xC7, 0x90, 0xAD, 0x03};
	uint8_t buff[512] = {0};
	size_t encryptedLen;
	uint8_t hash[32];
	mbedtls_rsa_context rsa;
	unsigned char publicKey[1024] = {0};
	unsigned char privateKey[1024] = {0};
	unsigned char mySign[2048] = {0};
	int8_t ret = 1;

    /* Board pin, clock, debug console init */
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    PRINTF("Option 2:\r\n");
    PRINTF("- Encryption of a message\r\n");
    PRINTF("- HASH of the encrypted message\r\n");
    PRINTF("- HASH signature of the encrypted message\r\n");
    PRINTF("----------------------------------------------------------------------------------------\r\n");

    AES_CBC_encrypt(plaintext, key, iv, buff, &encryptedLen);
    PRINTF("Encrypted message: ");
	for(int i=0; i<encryptedLen; i++) {
		PRINTF("0x%02x ", buff[i]);
	}
	PRINTF("\r\nLength: %d\r\n\n", encryptedLen);
	PRINTF("----------------------------------------------------------------------------------------\r\n");

	mbedtls_sha256_ret(buff, encryptedLen, hash, 0);
	PRINTF("HASH of the encrypted message: ");
	for(int i=0;i<HASH_LEN;i++){
		PRINTF("0x%02x ", hash[i]);
	}
	PRINTF("\r\nLength: %d\r\n\n", HASH_LEN);
	PRINTF("----------------------------------------------------------------------------------------\r\n");

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_gen_key(&rsa, myrand, NULL, KEY_IN_BITS, 17);
    mbedtls_rsa_public(&rsa, hash, publicKey);
    mbedtls_rsa_private(&rsa, myrand, NULL, hash, privateKey);
	mbedtls_rsa_pkcs1_sign(&rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, HASH_LEN, hash, mySign);
	ret = mbedtls_rsa_pkcs1_verify(&rsa, myrand, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, HASH_LEN, hash, mySign);
	mbedtls_rsa_free(&rsa);
	PRINTF("Digital signature\r\n");
	PRINTF("Public key: ");
	for(int i=0;i<KEY_LEN;i++){
		PRINTF("0x%02x ", publicKey[i]);
	}
	PRINTF("\r\n\n");
	PRINTF("Private key: ");
	for(int i=0;i<KEY_LEN;i++){
		PRINTF("0x%02x ", privateKey[i]);
	}
	PRINTF("\r\n\n");
	PRINTF("Sign: ");
	for(int i=0;i<128;i++){
		PRINTF("0x%02x ", mySign[i]);
	}
	PRINTF("\r\n\n");
	if(ret == 0){
		PRINTF("Sign verification with public key successful!");
	}
	PRINTF("\r\n\n");
	PRINTF("----------------------------------------------------------------------------------------\r\n");

	AES_CBC_decrypt(buff, &encryptedLen, key, iv);
	PRINTF("Plain text: ");
	for(int i=0; i<encryptedLen; i++) {
		PRINTF("%c", buff[i]);
	}
	PRINTF("\r\nLength: %d\r\n\n", strlen(buff));

    while (1);
}
