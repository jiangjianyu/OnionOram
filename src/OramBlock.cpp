#include <cstring>
#include "OramBlock.h"
#include "OramCrypto.h"

static char *blank_data;

int OramBlock::chunk_size = 0;
int OramBlock::block_size = 0;
int OramBlock::chunk_count = 0;

OramBlock::OramBlock():OramBlock(blank_data){ }

OramBlock::OramBlock(int init) {
	this->block = (damgard_jurik_ciphertext_t **)malloc(sizeof(damgard_jurik_ciphertext_t*)*OramBlock::chunk_count);
}

OramBlock::~OramBlock()
{
}

void OramBlock::init_size(int chunk, int block) {
	chunk_size = chunk;
	block_size = block;
	chunk_count = block / chunk;
	blank_data = new char[block];
}

OramBlock::OramBlock(void *buf, int layer) {
	unsigned char *buf_c = (unsigned char *)buf;
	int cipher_chunk_size = OramCrypto::get_crypto()->get_chunk_size(layer);
	this->block = (damgard_jurik_ciphertext_t **)
		malloc(sizeof(damgard_jurik_ciphertext_t*) * chunk_count);
	int now_s = OramCrypto::get_crypto()->s0 + layer;
	mpz_t n_s;
	mpz_init(n_s);
	mpz_set(n_s, *OramCrypto::get_crypto()->ahe_sys->get_ns(now_s));
	for (int i = 0; i < chunk_count; i++) {
		block[i] = new damgard_jurik_ciphertext_t(buf_c + i * cipher_chunk_size, cipher_chunk_size);
		block[i]->s = now_s - 1;
		mpz_set(block[i]->n_s, n_s);
	}
	this->layer = layer;
}

OramBlock::OramBlock(void *buf) {
	unsigned char *buf_c = (unsigned char *)buf;
	damgard_jurik_plaintext_t *tem_plain;
	block = (damgard_jurik_ciphertext_t**)malloc(
		sizeof(damgard_jurik_ciphertext_t*) * chunk_count);
	int s0 = OramCrypto::get_crypto()->s0;
	damgard_jurik_plaintext_t **plain = (damgard_jurik_plaintext_t**)malloc(sizeof(damgard_jurik_plaintext_t*)*chunk_count);
	for (int i = 0; i < chunk_count; i++) {
		plain[i] = new damgard_jurik_plaintext_t(buf_c + i*chunk_size, chunk_size);
	}
	OramCrypto::get_crypto()->ahe_sys->encrypt(this->block, plain, s0, chunk_count);
	this->layer = 1;
}

OramBlock* OramBlock::encrypt() {
	OramBlock *return_block = new OramBlock(0);
	int s = this->block[0]->s;
	return_block->block = (damgard_jurik_ciphertext_t**)malloc(
			sizeof(damgard_jurik_ciphertext_t*) * chunk_count);
	damgard_jurik_plaintext_t **plain_list = (damgard_jurik_plaintext_t**)malloc(
			sizeof(damgard_jurik_plaintext_t*) * chunk_count);
	for(int i = 0;i < chunk_count;i++) {
		plain_list[i] = new damgard_jurik_plaintext_t(return_block->block[i]->text);
	}
	OramCrypto::get_crypto()->ahe_sys->encrypt(return_block->block, plain_list, s + 1, chunk_count);
	return_block->layer = this->layer + 1;
	return return_block;
}

OramBlock* OramBlock::encrypt(int add_layer) {
	if (add_layer <= 0) {
		return this;
	}
	OramBlock *return_block = new OramBlock(0);
	int s = this->block[0]->s;
	damgard_jurik_ciphertext_t **now_block = (damgard_jurik_ciphertext_t**)malloc(
		sizeof(damgard_jurik_ciphertext_t*) * chunk_count);
	damgard_jurik_plaintext_t **plain_list = (damgard_jurik_plaintext_t**)malloc(
		sizeof(damgard_jurik_plaintext_t*) * chunk_count);
	for (int i = 0; i < chunk_count; i++) {
		now_block[i] = block[i];
	}
	for (int i = 1; i <= add_layer; i++) {
		for(int j = 0;j < chunk_count;j++) {
			plain_list[j] = new damgard_jurik_plaintext_t(now_block[j]->text);
		}
		OramCrypto::get_crypto()->ahe_sys->encrypt(now_block, plain_list, s + i, chunk_count);
	}
	return_block->block = now_block;
	return_block->layer = this->layer + add_layer;
	return return_block;
}

void* OramBlock::decrypt() {
	unsigned char *buf = (unsigned char*) new char[block_size];
	int layer = this->block[0]->s - OramCrypto::get_crypto()->s0;
	damgard_jurik_ciphertext_t *list[chunk_count];
	for (int i = 0; i < chunk_count; i++) {
		list[i] = block[i];
	}
	for (int i = layer; i >= 0; i--) {
		for (int j = 0; j < chunk_count; j++) {
			list[j] = new damgard_jurik_ciphertext_t(OramCrypto::get_crypto()->ahe_sys->decrypt(list[j])->text, OramCrypto::get_crypto()->s0 + i - 1);
		}
	}
	unsigned char* tem;
	for (int i = 0; i < chunk_count; i++) {
		tem = (unsigned char *)list[i]->to_bytes(chunk_size);
		memcpy(buf + i*chunk_size, tem, chunk_size);
		delete(tem);
	}
	return buf;
}

void* OramBlock::to_bytes() {
	int chunk = OramCrypto::get_crypto()->get_chunk_size(layer);
	unsigned char *buf = (unsigned char*) new char[chunk * chunk_count];
	unsigned char *tem;
	for (int i = 0; i < chunk_count; i++) {
		tem = (unsigned char *)block[i]->to_bytes(chunk);
		memcpy(buf + i*chunk, tem, chunk);
	}
	return buf;
}

int OramBlock::size() {
	return OramCrypto::get_crypto()->get_chunk_size(layer) * chunk_count;
}