#pragma once

#include "OramBlock.h"
#include "OramBucket.h"
#include "OramCrypto.h"

class OramSelector
{
public:
	int size;
	int layer;
	damgard_jurik_ciphertext_t **select_vector;

	OramSelector();

	//Layer here is only referred to encryption layer of the selecting list
	OramSelector(int size, void *buf, int layer);
	OramSelector(int size, int select_id, int layer);
	~OramSelector();

	OramBlock* select(OramBlock **select_list);

	void* to_bytes();
	int get_size() {
		return OramCrypto::get_crypto()->get_chunk_size(layer + 1) * size;
	}
};

