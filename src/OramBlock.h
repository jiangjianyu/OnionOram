#pragma once

#include "damgard_jurik.h"
#include "vector"

typedef struct OramMeta {
	int size;
	int *address;
} OramMeta;

class OramBlock
{
public:
	//Chunk number is block_size / chunk_size
	static int chunk_size;
	static int block_size;
	static int chunk_count;
	static void init_size(int chunk, int block);

	damgard_jurik_ciphertext_t **block;
	int layer;
	
	/*Construct by serilized ciphertext
	  Should make sure that len is block_size 
	*/
	OramBlock(void *buf, int layer);

	//Construct by plaintext, encrypt plaintext
	OramBlock(void *buf);
	OramBlock(int);
	OramBlock();
	~OramBlock();

	/* convert to encrypted bytes */
	void* to_bytes();

	/* onion encrypt */
	OramBlock* encrypt();

	OramBlock* encrypt(int add_layer);

	/* onion decrypt and converted to bytes */
	void* decrypt();

	int size();
};

