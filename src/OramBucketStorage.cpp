#include "OramBucketStorage.h"

OramBucketStorage::OramBucketStorage()
{
}


OramBucketStorage::~OramBucketStorage()
{
}


OramBucketStorage::OramBucketStorage(int bucket, int mem_max) {
	bucket_list = (OramBucket**) new char[sizeof(OramBucket*)*bucket];
	this->bucket_count = bucket;
	for (int i = 0; i < bucket; i++) {
		bucket_list[i] = new OramBucket();
	}
	mem_count = 0;
	this->mem_max = mem_max;
	this->cnt_0 = 0;
}
