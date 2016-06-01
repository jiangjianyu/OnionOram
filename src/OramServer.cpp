
#include "OramServer.h"
#include "OramSelector.h"
#include "OramLogger.h"
#include "OramBatchTask.h"
#include <cstring>

#define max(a,b) ((a > b) ? a:b)

OramServer::OramServer()
{
}

OramServer::OramServer(char *host, int port) {
	this->host = host;
	this->port = port;
	sock = new OramSocket(host, port, 1);
	this->storage = NULL;
	OramBatchTask::init(4);
}

OramServer::~OramServer()
{
}

void OramServer::run() {
	sock->init();
	running = 1;
	while(running) {
		OramSocket *sock_client = sock->accept_connection();
		while (running) {
			if (sock_client->standard_recv(ORAM_SOCKET_HEADER_SIZE) < 0)
				break;
			log_sys << "New Request"<< std::endl;
			sock_client->recv_continue(sock_client->get_recv_header()->msg_len);
			switch (sock_client->get_recv_header()->socket_type) {
				case ORAM_SOCKET_GETMETA:
					r_get_metadata(sock_client);
					break;
				case ORAM_SOCKET_READBLOCK:
					r_read_block(sock_client);
					break;
				case ORAM_SOCKET_READBUCKET:
					r_read_block(sock_client);
					break;
				case ORAM_SOCKET_WRITEBUCKET:
					r_write_bucket(sock_client);
					break;
				case ORAM_SOCKET_EVICT:
					r_evict_path(sock_client);
					break;
				case ORAM_SOCKET_INIT:
					r_init(sock_client);
					break;
				case ORAM_SOCKET_WRITEBLOCK:
					r_write_block(sock);
					break;
				default:
					break;
			}
		}
	}
}

void OramServer::r_get_metadata(OramSocket *sock) {
	OramBucket *bkt;
	int pos = sock->get_recv_header()->pos_id;
	log_detail << "REQUEST >> GET METADATA " << pos << std::endl;
	bool layer_l = sock->get_recv_header()->len == -1;
	int layer_list[100];
	int max_layer = 0;
	int len;
	int extra_layer = 0;
	int size = sizeof_read_meta(OramBucket::bucket_size);
	for (int pos_run = pos, i = 0;; pos_run = (pos_run - 1) >> 1, ++i) {
		bkt = storage->get_bucket(pos_run);
		layer_list[i] = bkt->layer;
		if (bkt->layer > max_layer) {
			max_layer = bkt->layer;
		}
		memcpy((unsigned char *)sock->get_send_buf() + i * size, bkt->encrypt_matadata, size);
		if (pos_run == 0) {
			len = i + 1;
			break;
		}
	}
	if (layer_l) {
		extra_layer = sizeof(int) * len;
		memcpy(sock->get_send_buf() + len * size, layer_list, extra_layer);
	}
	sock->get_send_header()->len = len;
	sock->get_send_header()->layer = max_layer;
	sock->get_send_header()->pos_id = pos;
	sock->get_send_header()->socket_type = ORAM_SOCKET_GETMETA;
	sock->get_send_header()->msg_len = size * len + extra_layer;
	sock->standard_send(size * len + ORAM_SOCKET_HEADER_SIZE + extra_layer);
}

void OramServer::r_read_bucket(OramSocket *sock) {
	OramBucket *bkt;
	int bucket_id = sock->get_recv_header()->pos_id;
	bkt = storage->get_bucket(bucket_id);
	OramSocketHeader *header = sock->get_send_header();
	header->len = 1;
	header->layer = bkt->layer;
	header->socket_type = ORAM_SOCKET_READBUCKET;
	sock->standard_send(bkt->size() + ORAM_SOCKET_HEADER_SIZE);
	unsigned char *buf = (unsigned char *)bkt->to_bytes();
	memcpy((unsigned char *)sock->get_send_buf(), buf, bkt->size());
	delete(buf);
}

void OramServer::r_write_bucket(OramSocket *sock) {
	OramBucket *bkt;
	int bucket_id = sock->get_recv_header()->pos_id;
	size_t total_size = OramCrypto::get_crypto()->get_chunk_size(sock->get_recv_header()->layer) *
			OramBlock::chunk_count * OramBucket::bucket_size + sizeof_read_meta(OramBucket::bucket_size);
	sock->standard_recv(total_size);
	OramBucket *new_bucket = new OramBucket(
		sock->get_recv_buf(), sock->get_recv_header()->layer);
	storage->set_bucket(bucket_id, new_bucket);
}

void OramServer::r_init(OramSocket *sock) {
	log_sys << "Init Server" << std::endl;
	OramSocketInit *init = (OramSocketInit *)sock->get_recv_buf();
	OramBucket::init_size(init->block_per_bucket);
	OramBlock::init_size(init->chunk_size, init->block_size);
	OramCrypto::init_crypto(init->s0, init->s_max, init->bits,
							sock->get_recv_buf() + sizeof(OramSocketInit),
							init->key_len, sock->get_recv_buf() + ORAM_SOCKET_INIT_SIZE(init->key_len),
							init->pvk_len);
	int pos_start = ORAM_SOCKET_INIT_SIZE(init->key_len + init->pvk_len);
	storage = new OramBucketStorage(init->bucket_count, init->mem_max);
	//Init Meta
	for (int i = 0;i < init->bucket_count;i++) {
		memcpy(storage->get_bucket(i)->encrypt_matadata,
			   sock->get_recv_buf() + pos_start + i*sizeof_read_meta(OramBucket::bucket_size),
			   sizeof_read_meta(OramBucket::bucket_size));
	}
	log_sys << "Server Init Finished\n";
}

void OramServer::r_read_block(OramSocket *sock) {
	OramBucket *bkt;
	//Block count
	int size = sock->get_recv_header()->len * OramBucket::bucket_size;
	OramBlock **block_list = (OramBlock**) new char[sizeof(OramBlock*)*size];
	int pos = sock->get_recv_header()->pos_id;
	int layer = sock->get_recv_header()->layer;
	log_detail << "REQUEST >> GET BLOCK " << pos << std::endl;
	for (int pos_run = pos, i = 0;; pos_run = (pos_run - 1) >> 1) {
		bkt = storage->get_bucket(pos_run);
		for (int j = 0; j < OramBucket::bucket_size; j++) {
			block_list[i++] = bkt->bucket[j]->encrypt(layer - bkt->layer);
		}
		if (pos_run == 0)
			break;
	}
	OramSelector *selector = new OramSelector(size, sock->get_recv_buf(), sock->get_recv_header()->layer);
	//Select from data
	OramBlock *return_block = selector->select(block_list);
	unsigned char *tem = (unsigned char *)return_block->to_bytes();
	memcpy(sock->get_send_buf(), tem, return_block->size());
	sock->get_send_header()->layer = sock->get_recv_header()->layer + 1;
	sock->get_send_header()->len = 1;
	sock->get_send_header()->pos_id = pos;
	sock->get_send_header()->socket_type = ORAM_SOCKET_READBLOCK;
	sock->standard_send(return_block->size() + ORAM_SOCKET_HEADER_SIZE);
	delete(tem);
	delete(return_block);
}

void OramServer::r_evict_path(OramSocket* sock) {
	int pos = sock->get_recv_header()->pos_id;
	int *pos_array = new int[sock->get_recv_header()->len];
	log_detail << "REQUEST >> EVICT " << pos << std::endl;
	int size = 2*OramBucket::bucket_size;
	OramBlock **block_list = (OramBlock**) new char[sizeof(OramBlock*)*size];
	OramBucket *bkt, *bkt_left, *bkt_right, *bkt_next;
	OramSelector *selector;
	int last = 0;
	int selector_size = 0;
	int sibing_list[sock->get_recv_header()->len];
	for (int pos_run = pos, i = sock->get_recv_header()->len - 1;; (pos_run - 1) >> 1, i--) {
		pos_array[i] = pos_run;
		if (pos_run == 0)
			break;
	}
	for (int i = 0, k = 0, s = 0; i < sock->get_recv_header()->len - 1; i++) {
		bkt = storage->get_bucket(pos_array[i]);
		bkt_left = storage->get_bucket(pos_array[i] >> 1 + 1);
		bkt_right = storage->get_bucket(pos_array[i] >> 1 + 2);
		bkt_next = storage->get_bucket(pos_array[i + 1]);
		if (pos_array[i] >> 1 + 1 == pos_array[i + 1]) {
			sibing_list[s++] = pos_array[i] >> 1 + 2;
		} else {
			sibing_list[s++] = pos_array[i] >> 1 + 1;
		}
		for (int j = 0; i < OramBucket::bucket_size; j++) {
			block_list[k++] = bkt->bucket[j];
			block_list[k++] = bkt_next->bucket[j];
		}
		selector_size = OramCrypto::get_crypto()->get_chunk_size(max(bkt->layer, bkt_next->layer) + 1) * size;
		for (int j = 0; j < OramBucket::bucket_size; j++, last += selector_size) {
			selector = new OramSelector(size, (unsigned char *)sock->get_recv_buf() + last, sock->get_recv_header()->layer);
			bkt_left->bucket[j] = selector->select(block_list);
		}
		for (int j = 0; j < OramBucket::bucket_size; j++, last += selector_size) {
			selector = new OramSelector(size, (unsigned char *)sock->get_recv_buf() + last, sock->get_recv_header()->layer);
			bkt_right->bucket[j] = selector->select(block_list);
		}
	}
	//Rewrite metadata
	sibing_list[sock->get_recv_header()->len - 1] = pos_array[sock->get_recv_header()->len - 1];
	for (int i = 0;i < sock->get_recv_header()->len;i++) {
		memcpy(storage->get_bucket(sibing_list[i])->encrypt_matadata,
			   sock->get_recv_buf() + last + i * sizeof_read_meta(OramBucket::bucket_size),
			   OramBucket::bucket_size);
	}
	storage->cnt_0 = 0;
}

void OramServer::r_write_block(OramSocket* sock) {
	log_detail << "REQUEST >> WRITEBACK" << std::endl;
	OramBlock *new_block = new OramBlock(sock->get_recv_buf(), 1);
	storage->get_bucket(0)->bucket[storage->cnt_0++] = new_block;
	memcpy(storage->get_bucket(0)->encrypt_matadata,
		   sock->get_recv_buf() + new_block->size(),
		   sizeof(int) * OramBucket::bucket_size);
}