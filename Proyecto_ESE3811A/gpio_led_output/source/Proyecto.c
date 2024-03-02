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
#include "aes.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Main function
 */
int main(void)
{
	uint8_t plainText[111] = {"Este es el proyecto final de la materia ingenieria de software y seguridad para sistemas embebidos - Noe Ortiz"};
	uint8_t key[] = {0x03, 0x68, 0x22, 0xA9, 0x04, 0xAA, 0x41, 0x6E, 0x11, 0xFE, 0x3E, 0x5B, 0xC9, 0x8C, 0xA1, 0x33};
	uint8_t initVector[]  = {0x76, 0x25, 0x11, 0x4E, 0x1E, 0xEE, 0xAA, 0x9B, 0x5A, 0x31, 0x5C, 0x15, 0xC7, 0x90, 0xAD, 0x03};
	struct AES_ctx ctx;
	size_t plainTextLen, buffLen;
	uint8_t buff[512] = {0};
	uint8_t encryptedLen = 0;

    /* Board pin, clock, debug console init */
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    PRINTF("AES encryption\r\n");
    PRINTF("----------------------------------------------------------------------------------------\r");

    AES_init_ctx_iv(&ctx, key, initVector);
    plainTextLen = strlen(plainText);
    buffLen = plainTextLen + (16 - (plainTextLen % 16) );
	memcpy(buff, plainText, plainTextLen);

	AES_CBC_encrypt_buffer(&ctx, buff, buffLen);
	PRINTF("Encrypted data: ");
	for(int i=0; i<buffLen; i++) {
		PRINTF("0x%02x ", buff[i]);
		encryptedLen += 1;
	}
	PRINTF("\r\n");
	PRINTF("Length: %d\r\n", encryptedLen);

	PRINTF("----------------------------------------------------------------------------------------\r");

	AES_init_ctx_iv(&ctx, key, initVector);

	AES_CBC_decrypt_buffer(&ctx, buff, buffLen);
	PRINTF("Plain text: ");
	for(int i=0; i<buffLen; i++) {
		//PRINTF("0x%02x ", padded_msg[i]);
		PRINTF("%c", buff[i]);
	}
	PRINTF("\r\n");
	PRINTF("Length: %d\r\n\n", strlen(buff));

    while (1);
}
