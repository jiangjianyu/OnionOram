#include <cstring>
#include "OramSelector.h"

#include "OramCrypto.h"
#include "OramBatchTask.h"

OramSelector::OramSelector()
{
}


OramSelector::~OramSelector()
{
	for (int i = 0;i < size;i++) {
		delete(this->select_vector[i]);
	}
}

OramSelector::OramSelector(int size, int select_id, int layer) {
	this->layer = layer;
	this->size = size;
	select_vector = (damgard_jurik_ciphertext_t **) new char[sizeof(damgard_jurik_ciphertext_t*)*size];
	int s = OramCrypto::get_crypto()->s0 + layer;
/*	for (int i = 0; i < size; i++) {
		if (i == select_id) {
			select_vector[i] = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t((unsigned long)1), s);
		}
		else {
			select_vector[i] = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t((unsigned long)0), s);
		}
	}*/
	OramBatchTask *task = OramBatchTask::new_task();
	OramTaskEncryptInput *input;
	for (int i = 0; i < size;i++) {
		if (i == select_id) {
			input = new OramTaskEncryptInput(new damgard_jurik_plaintext_t((unsigned long)1), s);
			task->new_job(ORAM_TASK_ENCRYPT, input);
		}
		else {
			input = new OramTaskEncryptInput(new damgard_jurik_plaintext_t((unsigned long)0), s);
			task->new_job(ORAM_TASK_ENCRYPT, input);
		}
	}
	for (int i = 0;i < size;i++) {
		select_vector[i] = (damgard_jurik_ciphertext_t*)task->get_result(i);
	}
}

void* OramSelector::to_bytes() {
	unsigned char *buf = (unsigned char *) new char[select_vector[0]->size() * size];
	unsigned char *tem;
	int per_size = select_vector[0]->size();
	for (int i = 0; i < size; i++) {
		tem = (unsigned char *)select_vector[i]->to_bytes();
		memcpy(buf + i*per_size, tem, per_size);
		delete(tem);
	}
	return buf;
}

OramSelector::OramSelector(int size, void *buf, int layer) {
	int per_size = OramCrypto::get_crypto()->get_chunk_size(layer + 1);
	select_vector = (damgard_jurik_ciphertext_t **) new char[sizeof(damgard_jurik_ciphertext_t*)*size];
	int s = OramCrypto::get_crypto()->s0 + layer;
	for (int i = 0; i < size; i++) {
		select_vector[i] = new damgard_jurik_ciphertext_t((unsigned char *)buf + i*per_size, per_size);
		select_vector[i]->s = s;
		mpz_set(select_vector[i]->n_s, *OramCrypto::get_crypto()->ahe_sys->get_ns(s + 1));
	}
	this->size = size;
	this->layer = layer;
}

OramBlock* OramSelector::select(OramBlock **select_list) {
	OramBlock *return_block = new OramBlock();

/* Old Version -- Non-Concurrency Version
 * damgard_jurik_ciphertext_t *select_result = new damgard_jurik_ciphertext_t[OramBlock::chunk_count];
	for (int i = 0; i < OramBlock::chunk_count; i++) {
		select_result[i] = (*select_vector[0]) ^ (*select_list[0]->block[i]);
		for (int j = 1; j < size; j++) {
			select_result[i] = select_result[i] * ((*select_vector[j]) ^ (*select_list[j]->block[i]));
		}
		*return_block->block[i] = select_result[i];
	}
 */
	OramTaskSelectInput *input;
	OramBatchTask *task = OramBatchTask::new_task();
	for (int i = 0; i < OramBlock::chunk_count;i++) {
		input = new OramTaskSelectInput(size, i, select_vector, select_list);
		task->new_job(ORAM_TASK_SELECT, input);
	}
	for (int i = 0;i < OramBlock::chunk_count;i++) {
		return_block->block[i] = (damgard_jurik_ciphertext_t*)task->get_result(i);
	}

	return_block->layer = layer + 1;
	return return_block;
}