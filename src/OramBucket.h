#pragma once
#include "OramBlock.h"
#include "oram.hpp"
class OramBucket
{
public:
	/* Block size for a bucket*/
	static int bucket_size;

	static void init_size(int bucket_size);

	int layer;
	OramBlock **bucket;
	unsigned char *encrypt_matadata;

	OramBucket();
	/* Construct bucket from serilized data */
	OramBucket(void *buf, int layer);
	~OramBucket();

	//Serilized all data of this bucket
	void* to_bytes();
	void* get_meta() { return encrypt_matadata; }
	void to_file(int file_id);
	void set_meta(int int_arr[]);
	int size();
};

