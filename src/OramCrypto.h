#pragma once

#include "OramBlock.h"
#include "sodium.h"

#define ORAM_CRYPT_KEY_LEN crypto_secretbox_KEYBYTES
#define ORAM_CRYPT_NONCE_LEN crypto_secretbox_NONCEBYTES
#define ORAM_CRYPT_OVERSIZE crypto_secretbox_MACBYTES + ORAM_CRYPT_NONCE_LEN
#define ORAM_CRYPT_OVERHEAD crypto_secretbox_MACBYTES

class OramCrypto
{
public:
	static OramCrypto *crypto;
	static OramCrypto* get_crypto();
	static void init_crypto(void *key, int key_len, 
		int s0, int s_max, int bits);
	static void init_crypto(int s0, int s_max, int bits, void *buf, size_t len, void *pvk_buf, size_t pvk_len);
	static int get_random(int range);

	unsigned char sodium_key[ORAM_CRYPT_KEY_LEN];
	damgard_jurik *ahe_sys;
	
	int s0;
	int bits;

	void* encrypt_meta(OramMeta &meta, unsigned char *buf);
	OramMeta* decrypt_meta(void *buf, int size);
	int get_chunk_size(int layer);
	OramCrypto();
	OramCrypto(int s0, int max_s, int bitmo, void *buf, size_t len, void *pvk_buf, size_t pvk_len);
	OramCrypto(void *key, int key_len, int s0, int max_s, int bitmo);
	~OramCrypto();
};

