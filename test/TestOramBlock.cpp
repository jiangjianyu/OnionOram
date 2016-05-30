//
// Created by maxxie on 16-5-26.
//

#include <cassert>
#include "../src/OramBlock.h"
#include "../src/OramCrypto.h"

int main (int argc, char **args) {

    char *key = "ORAM";
    unsigned char buf[40960];
    buf[0] = 2;
    buf[1] = 1;
    OramCrypto::init_crypto(key, 4, 8, 100, 1024);
    OramBlock::init_size(1024, 10240);

    //Test for encryption
    OramBlock *block = new OramBlock(buf);
    unsigned char *de = (unsigned char *)block->decrypt();

    //Test for Serialization
    unsigned char *ser = (unsigned char *)block->to_bytes();
    OramBlock *block_2 = new OramBlock(ser, 1);
    for (int i = 0;i < OramBlock::chunk_count;i++) {
        assert(mpz_cmp(block->block[i]->text, block_2->block[i]->text) == 0);
    }
    unsigned char *de_2 = (unsigned char *)block_2->decrypt();

    //Test for Onion Decryption
    int si = block->block[0]->size();
    OramBlock *block_3 = block->encrypt(2);
    unsigned char *de_3 = (unsigned char *)block_3->decrypt();
    int si_2 = block_3->block[0]->size();
    return 0;
}