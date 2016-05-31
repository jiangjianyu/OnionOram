#pragma once
#include "OramCrypto.h"
#define ORAM_SOCKET_TIMEOUT_SECOND 5
#define ORAM_SOCKET_TIMEOUT_USECOND 0
typedef enum oram_socket_type {
	ORAM_SOCKET_READBLOCK = 0,
	ORAM_SOCKET_GETMETA = 1,
	ORAM_SOCKET_EVICT = 2,
	ORAM_SOCKET_READBUCKET = 3,
	ORAM_SOCKET_WRITEBUCKET = 4,
	ORAM_SOCKET_WRITEBLOCK = 5,
	ORAM_SOCKET_INIT = 6
} oram_socket_type;

#define sizeof_read_block(size) 
#define sizeof_read_bucket(size)
#define sizeof_write_bucket(size)
#define sizeof_evict(size)
#define sizeof_read_meta(size) (sizeof(int) * size + ORAM_CRYPT_OVERSIZE)
#define ORAM_SOCKET_BUFFER_SIZE 102400
typedef struct OramSocketHeader {
	oram_socket_type socket_type;
	/* Suggest a path or a bucket id*/
	int pos_id;
	int len;
	int layer;
	int msg_len;
} OramSocketHeader;

typedef struct OramSocketInit{
	int bucket_count; /* total bucket */
	int block_per_bucket; /* block per bucket */
	int chunk_size; /* chunk len */
	int block_size; /* block len */
	int mem_max; /* max of memory */
	/* CryptoSystem */
	int s0;
	int s_max;
	int bits;
	size_t key_len;
	size_t pvk_len;
} OramSocketInit;

#define ORAM_SOCKET_HEADER_SIZE sizeof(OramSocketHeader)
#define ORAM_SOCKET_INIT_SIZE(size) sizeof(OramSocketInit) + size

class OramSocket
{
public:
	int sock;
	char *host;
	int port;
	int if_bind;
	size_t last;
	unsigned char *buf_r;
	unsigned char *buf_s;
	/* buffer for send and recv */

	OramSocket();
	OramSocket(char* host, int port, int bind);
	OramSocket(int sock);
	~OramSocket();

	int standard_send(size_t len);
	int standard_recv(size_t len);
	int recv_continue(size_t len);
	int init();
	OramSocket* accept_connection();
	void* get_recv_buf() { return buf_r + ORAM_SOCKET_HEADER_SIZE; }
	void* get_send_buf() { return buf_s + ORAM_SOCKET_HEADER_SIZE; }
	OramSocketHeader* get_recv_header() { return (OramSocketHeader*)buf_r; }
	OramSocketHeader* get_send_header() { return (OramSocketHeader*)buf_s; }
};

