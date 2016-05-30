//
// Created by maxxie on 16-5-21.
//

#ifndef ONIONORAM_ORAM_H
#define ONIONORAM_ORAM_H

#define ORAM_BLOCK_SIZE 128
#define ORAM_TREE_DEPTH 20

#define ORAM_BUCKET_FILEFORMAT "BUCKET.%d.data"
#define ORAM_CHUNK_NUMBER
#define ORAM_SOCKET_BACKLOG 5

typedef enum {
	ORAM_ACCESS_READ = 0,
	ORAM_ACCESS_WRITE = 1
}OramAccessOp;
#endif //ONIONORAM_ORAM_H
