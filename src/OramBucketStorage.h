#pragma once
#include "OramBucket.h"
class OramBucketStorage
{
public:

	int bucket_count;
	int mem_count;
	int mem_max;
	int cnt_0;
	OramBucket **bucket_list;

	OramBucketStorage();
	OramBucketStorage(int bucket, int mem_max);

	~OramBucketStorage();
	OramBucket* get_bucket(int pos) { return bucket_list[pos]; }
	void set_bucket(int id, OramBucket *bkt) { bucket_list[id] = bkt; }
};

