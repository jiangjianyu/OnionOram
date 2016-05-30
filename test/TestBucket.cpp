//
// Created by maxxie on 16-5-28.
//

#include <cassert>
#include "../src/OramCrypto.h"
#include "../src/OramBucket.h"

int main(int argc, char **args) {
    char *key = "ORAM";
    OramCrypto::init_crypto(key, 4, 8, 100, 1024);
    OramBlock::init_size(1024, 10240);
    OramBucket::init_size(10);
    OramBucket *bucket = new OramBucket();
    int arr[10];
    arr[1] = 2;
    bucket->set_meta(arr);
    unsigned char *nothing = (unsigned char *)bucket->bucket[0]->decrypt();
    void *by = bucket->to_bytes();
    OramBucket *bucket_2 = new OramBucket(by, bucket->layer);
    for (int i = 0;i<bucket->bucket_size;i++) {
        for (int j = 0;j<OramBlock::chunk_count;j++) {
            assert(mpz_cmp(bucket->bucket[i]->block[j]->text, bucket_2->bucket[i]->block[j]->text) == 0);
        }
    }
}