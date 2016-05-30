#include "OramBucket.h"
#include "OramCrypto.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

int OramBucket::bucket_size = 0;

void OramBucket::init_size(int bucket_size) {
	OramBucket::bucket_size = bucket_size;
}

OramBucket::OramBucket(){
	bucket = (OramBlock **) new char[sizeof(OramBucket*)*bucket_size];
	for (int i = 0; i < bucket_size; i++) {
		bucket[i] = new OramBlock();
	}
	this->encrypt_matadata = (unsigned char *) new char[sizeof(int) * bucket_size + ORAM_CRYPT_OVERSIZE];
	this->layer = 1;
}


OramBucket::~OramBucket()
{
}


void* OramBucket::to_bytes() {
	int per_size = bucket[0]->size();
	unsigned char *buf = (unsigned char *)new char[per_size*bucket_size +
		sizeof(int)*bucket_size + ORAM_CRYPT_OVERSIZE];
	unsigned char *tem;
	for (int i = 0; i < bucket_size; i++) {
		tem = (unsigned char *)bucket[i]->to_bytes();
		memcpy(buf + per_size*i, tem, per_size);
		delete(tem);
	}
	memcpy(buf + per_size*bucket_size, encrypt_matadata, sizeof(int)*bucket_size + ORAM_CRYPT_OVERSIZE);
	return buf;
}

OramBucket::OramBucket(void *buf, int layer) {
	int per_bucket = OramCrypto::get_crypto()->get_chunk_size(layer) * OramBlock::chunk_count;
	bucket = (OramBlock**) new char[sizeof(OramBlock*)*bucket_size];
	for (int i = 0; i < bucket_size; i++) {
		bucket[i] = new OramBlock((unsigned char *)buf + per_bucket*i, layer);
	}
	this->encrypt_matadata = (unsigned char*)new char[sizeof(int)*bucket_size + ORAM_CRYPT_OVERSIZE];
	memcpy(this->encrypt_matadata, (unsigned char *)buf + per_bucket * bucket_size, sizeof(int)*bucket_size + ORAM_CRYPT_OVERSIZE);
	this->layer = layer;
}

void OramBucket::to_file(int file_id) {
	char filename[100];
	sprintf(filename, ORAM_BUCKET_FILEFORMAT, file_id);
	int fd = open(filename, O_RDONLY);
	unsigned char *tem = (unsigned char *)this->to_bytes();
	write(fd, tem, this->size());
}

int OramBucket::size() {
	return bucket[0]->size()*bucket_size + sizeof(int)*bucket_size + ORAM_CRYPT_OVERSIZE;
}

void OramBucket::set_meta(int int_array[]) {
	for (int i = 0;i<bucket_size;i++) {
		OramMeta meta;
		meta.address = int_array;
		meta.size = bucket_size;
		OramCrypto::get_crypto()->encrypt_meta(meta, encrypt_matadata);
	}
}