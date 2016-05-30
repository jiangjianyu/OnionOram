#pragma once
#include "OramSocket.h"
#include "oram.hpp"
class OramClient
{
public:
	int *position_map;
	int eviction_g;
	int reshuffling_rate;
	int cnt;

	int tree_depth;
	int tree_leaf_count;
	int tree_leaf_start;
	int bucket_count;
	int block_per_bucket;
	int chunk_size;
	int block_size;

	OramSocket *sock;
	OramClient();
	OramClient(char *host, int port, int bucket_count, int block_per_bucket, int block_size, int chunk_size,
	           char *key, int key_len, int s0, int bits);
	~OramClient();

	OramMeta** get_metadata(int pos, int[], bool);

	int access(int address, OramAccessOp op, unsigned char data[]);

	int read_path(int pos, int address, unsigned char data[]);

	int evict();

	int evict_along_path(int pos);

	int write_back(OramBlock *block);

	int init();
};

