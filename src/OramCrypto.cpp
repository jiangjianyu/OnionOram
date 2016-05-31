#include <cstring>
#include "OramCrypto.h"
#include "OramLogger.h"

OramCrypto* OramCrypto::crypto = NULL;

void OramCrypto::init_crypto(void *key, int key_len, int s0, int s_max, int bits) {
	OramCrypto::crypto = new OramCrypto(key, key_len, s0, s_max, bits);
}

void OramCrypto::init_crypto(int s0, int s_max, int bits, void *buf, size_t len, void *pvk_buf, size_t pvk_len) {
	OramCrypto::crypto = new OramCrypto(s0, s_max, bits, buf, len, pvk_buf, pvk_len);
}

OramCrypto* OramCrypto::get_crypto() {
	return OramCrypto::crypto;
}

OramCrypto::OramCrypto()
{
}


OramCrypto::~OramCrypto()
{
}

OramCrypto::OramCrypto(int s0, int max_s, int bitmo, void *buf, size_t len, void *pvk_buf, size_t pvk_len) {
	ahe_sys = new damgard_jurik(max_s, bitmo, randombytes_buf, buf, len, pvk_buf, pvk_len);
	this->s0 = s0;
	this->bits = bitmo;
}

OramCrypto::OramCrypto(void *key, int key_len, int s0, int max_s, int bitmo) {
	memset(sodium_key, 0, ORAM_CRYPT_KEY_LEN);
	memcpy(sodium_key, key, key_len);
	ahe_sys = new damgard_jurik(max_s, bitmo, randombytes_buf);
	this->s0 = s0;
	this->bits = bitmo;
}

void* OramCrypto::encrypt_meta(OramMeta &meta, unsigned char *buf) {
	if (buf == NULL)
		buf =(unsigned char*) new char[sizeof(int) * meta.size + ORAM_CRYPT_OVERSIZE];
	unsigned char nonce[ORAM_CRYPT_NONCE_LEN];
	nonce[0] = 111;
	nonce[1] = 112;
	crypto_secretbox_easy(buf + ORAM_CRYPT_NONCE_LEN, (unsigned char *)meta.address, meta.size * sizeof(int), nonce, sodium_key);
	memcpy(buf, nonce, ORAM_CRYPT_NONCE_LEN);
	return buf;
}

OramMeta* OramCrypto::decrypt_meta(void *buf, int size) {
	OramMeta *meta = new OramMeta;
	unsigned char *buf_c = (unsigned char *)buf;
	meta->size = size;
	meta->address = new int[size];
	if (crypto_secretbox_open_easy((unsigned char *)meta->address,
		buf_c + ORAM_CRYPT_NONCE_LEN,
		sizeof(int) * size + ORAM_CRYPT_OVERHEAD,
		buf_c, sodium_key) != 0) {
		log_sys << "Decrypting metadata error\n";
		return NULL;
	}
	return meta;
}

int OramCrypto::get_chunk_size(int layer) {
	return bits / 8 * (s0 + layer);
}

int OramCrypto::get_random(int range) {
	return randombytes_uniform(range);
}