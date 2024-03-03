/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <aes_encryption.h>

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
void AES_CBC_encrypt(uint8_t *plaintext, uint8_t *key, uint8_t *iv, uint8_t *encryptData, size_t *encryptedLen){
	size_t plainTextLen;
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	plainTextLen = strlen(plaintext);
	*encryptedLen = plainTextLen + (16 - (plainTextLen % 16) );
	memcpy(encryptData, plaintext, plainTextLen);

	AES_CBC_encrypt_buffer(&ctx, encryptData, *encryptedLen);
}

void AES_CBC_decrypt(uint8_t *encryptData, size_t *encryptedLen, uint8_t *key, uint8_t *iv){
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, encryptData, *encryptedLen);
}
