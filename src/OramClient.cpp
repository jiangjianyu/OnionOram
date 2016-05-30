#include <cstring>
#include <cmath>
#include "OramClient.h"
#include "OramBucket.h"
#include "OramSelector.h"
#include "OramLogger.h"

#define max(a,b) ((a > b)?a:b)

int gen_reverse_lexicographic(int g, int oram_size, int tree_height) {
	int i, pos = 0;
	for (i = 0;i < tree_height - 1;i++) {
		pos = pos * 2 + (g & 0x01) + 1;
		g >>= 1;
	}
	if (pos > oram_size)
		pos >>= 1;
	return pos;
}

int pos_to_len(int pos) {
	for (int pos_run = pos, i = 0;;(pos_run - 1) >> 1, i++) {
		if (pos_run == 0)
			return i + 1;
	}
}

int address_in_path(int address_pos, int node_pos) {
	for (int pos_run = address_pos;;pos_run = (pos_run - 1) >> 1 ) {
		if (pos_run == node_pos)
			return 1;
		if (pos_run < node_pos)
			break;
	}
	return 0;
}


OramClient::OramClient()
{
}

OramClient::OramClient(char *host, int port ,int bucket_count, int block_per_bucket, int block_size, int chunk_size,
					   char *key, int key_len, int s0, int bits){
	sock = new OramSocket(host, port, 0);
	sock->init();
	OramBucket::init_size(block_per_bucket);
	OramBlock::init_size(chunk_size, block_size);
	OramCrypto::init_crypto(key, key_len, s0, 50, bits);
	this->bucket_count = bucket_count;
	this->block_per_bucket = block_per_bucket;
	this->block_size = block_size;
	this->chunk_size = chunk_size;
	this->position_map = new int[bucket_count];
	this->cnt = 0;
	this->eviction_g = 0;
	this->reshuffling_rate = block_per_bucket;
	this->tree_depth = log(bucket_count)/log(2) + 1;
	this->tree_leaf_count = (bucket_count + 1) / 2;
	this->tree_leaf_start = bucket_count - tree_leaf_count;
}

OramClient::~OramClient(){

}

int OramClient::access(int address, OramAccessOp op, unsigned char data[]) {
	int pos = position_map[address];
	int pos_new = OramCrypto::get_random(tree_leaf_count) + tree_leaf_start;
	position_map[address] = pos_new;
	unsigned char data_read[OramBlock::block_size];
	if (read_path(pos, address, data_read) < 0)
		return -1;
	if (op == ORAM_ACCESS_READ)
		memcpy(data, data_read, OramBlock::block_size);
	else if (op == ORAM_ACCESS_WRITE)
		memcpy(data_read, data, OramBlock::block_size);
	OramBlock *return_block = new OramBlock(data_read);
	write_back(return_block);
	evict();
	return 1;
}

int OramClient::write_back(OramBlock *block) {
	memcpy(sock->get_send_buf(), block->to_bytes(), block->size());
	sock->get_send_header()->socket_type = ORAM_SOCKET_WRITEBLOCK;
	sock->get_send_header()->pos_id = cnt;
	sock->get_send_header()->len = 1;
	sock->get_send_header()->layer = 1;
	sock->get_send_header()->msg_len = block->size();
	sock->standard_send(ORAM_SOCKET_HEADER_SIZE + block->size());
	return 1;
}

int OramClient::evict() {
	cnt = (cnt + 1) % reshuffling_rate;
	if (cnt == 0) {
		evict_along_path(gen_reverse_lexicographic(eviction_g, bucket_count, tree_depth));
		eviction_g = (eviction_g + 1) % ((bucket_count + 1) >> 1 + 1);
	}
	return 1;
}

OramMeta** OramClient::get_metadata(int pos, int layer_list[], bool layer_all) {
	sock->get_send_header()->pos_id = pos;
	sock->get_send_header()->socket_type = ORAM_SOCKET_GETMETA;
	sock->get_send_header()->msg_len = 0;
	if (!layer_all)
		sock->get_send_header()->len = 0;
	else
		sock->get_send_header()->len = -1;
	sock->standard_send(ORAM_SOCKET_HEADER_SIZE);

	sock->standard_recv(ORAM_SOCKET_HEADER_SIZE);
	int len = sock->get_recv_header()->len;
	int layer = sock->get_recv_header()->layer;
	int layer_extra = (!layer_all) ? 0 : sizeof(int);
	sock->recv_continue(sock->get_recv_header()->msg_len);
	OramMeta **meta = (OramMeta**) malloc(sizeof(OramMeta*) * len);
	for (int i = 0;i < len;i++) {
		meta[i] = OramCrypto::get_crypto()->decrypt_meta(
				sock->get_recv_buf() + sizeof_read_meta(OramBucket::bucket_size) * i,
				OramBucket::bucket_size);
	}
	if (layer_all) {
		memcpy(layer_list, sock->get_recv_buf() +
				len * sizeof_read_meta(OramBucket::bucket_size),
			    layer_extra * len);
	} else {
		*layer_list = layer;
	}

	return meta;
}

int OramClient::evict_along_path(int pos) {
	int len = pos_to_len(pos);
	int layer_list[len];
	int pos_list[len];
	int left_list[OramBucket::bucket_size];
	int right_list[OramBucket::bucket_size];
	int left_detail[OramBucket::bucket_size];
	int right_detail[OramBucket::bucket_size];
	OramMeta *meta_list = new OramMeta[len];
	OramMeta **meta = get_metadata(pos, layer_list, true);
	for (int pos_run = pos, i = len - 1;; (pos_run - 1) >> 1, i--) {
		pos_list[i] = pos_run;
		if (pos_run == 0)
			break;
	}
	int addr, last_pos;
	//m was used to count total selector
	for (int i = 0, m = 0;i < len;i++) {
		int pos_run = pos_list[i];
		int g_left = 0, g_right = 0;
		int select_id = 0;
		memset(left_list, 0, sizeof(int) * OramBucket::bucket_size);
		memset(left_detail, 0, sizeof(int) * OramBucket::bucket_size);
		memset(right_list, 0, sizeof(int) * OramBucket::bucket_size);
		memset(right_detail, 0, sizeof(int) * OramBucket::bucket_size);
		for (int j = 0;j < OramBucket::bucket_size;j++) {
			addr = meta[len - i - 1]->address[j];
			if (address_in_path(position_map[addr], pos_run >> 1 + 1)) {
				left_list[g_left++] = select_id++;
				left_detail[g_left - 1] = addr;
			}
			else {
				right_list[g_right++] = select_id++;
				right_detail[g_right - 1] = addr;
			}
			addr = meta[len - i - 2]->address[j];
			if (address_in_path(position_map[addr], pos_run >> 1 + 1)) {
				left_list[g_left++] = select_id++;
				left_detail[g_left - 1] = addr;
			} else {
				right_list[g_right++] = select_id++;
				right_detail[g_right - 1] = addr;
			}
		}
		//copy them to original
		if (pos_list[i + 1] == pos_run >> 1 + 1) {
			memcpy(meta[len - i - 2]->address, left_detail, sizeof(int) * OramBucket::bucket_size);
			meta_list[i].address = new int[OramBucket::bucket_size];
			memcpy(meta_list[i].address, right_detail, sizeof(int) * OramBucket::bucket_size);
		} else {
			memcpy(meta[len - i - 2]->address, right_detail, sizeof(int) * OramBucket::bucket_size);
			meta_list[i].address = new int[OramBucket::bucket_size];
			memcpy(meta_list[i].address, left_detail, sizeof(int) * OramBucket::bucket_size);
		}
		int max_layer = max(layer_list[len - i - 1], layer_list[len - i - 2]);
		for (int j = 0;j < OramBucket::bucket_size;j++) {
			OramSelector *selector = new OramSelector(OramBucket::bucket_size*2, left_list[j], max_layer);
			memcpy(sock->get_send_buf() + last_pos, selector->to_bytes(), selector->get_size());
			last_pos += selector->get_size();
		}
		for (int j = 0;j < OramBucket::bucket_size;j++) {
			OramSelector *selector = new OramSelector(OramBucket::bucket_size*2, right_list[j], max_layer);
			memcpy(sock->get_send_buf() + last_pos, selector->to_bytes(), selector->get_size());
			last_pos += selector->get_size();
		}
	}
	meta_list[len - 1].address = new int[OramBucket::bucket_size];
	memcpy(meta_list[len - 1].address, meta[len - 1]->address, OramBucket::bucket_size);
	for (int i = 0;i < len;i++) {
		OramCrypto::get_crypto()->encrypt_meta(meta_list[i], (unsigned char *)sock->get_send_buf() + last_pos);
		last_pos += sizeof_read_meta(OramBucket::bucket_size);
	}
	sock->get_send_header()->pos_id = pos;
	sock->get_send_header()->len = len;
	sock->get_send_header()->socket_type = ORAM_SOCKET_EVICT;
	sock->get_send_header()->msg_len = last_pos;
	sock->standard_send(ORAM_SOCKET_HEADER_SIZE + last_pos);
	return 1;
}

int OramClient::read_path(int pos, int address, unsigned char data[]) {
	int select_id = -1;
	int len;
	int max_layer;
	OramMeta **meta = get_metadata(pos, &max_layer, false);
	for (int pos_run = pos, i = 0;;pos_run = (pos_run - 1) >> 1, i++) {
		for (int j = 0; j < OramBucket::bucket_size; j++) {
			if (meta[i]->address[j] == address)
				select_id = i * OramBucket::bucket_size + j;
		}
		if (pos_run == 0) {
			len = i + 1;
			break;
		}
	}
	OramSelector *selector;
	if (select_id == -1)
		selector = new OramSelector(len * OramBucket::bucket_size, 0, max_layer);
	else
		selector = new OramSelector(len * OramBucket::bucket_size, select_id, max_layer);
	int selector_size = selector->get_size();
	memcpy(sock->get_send_buf(), selector->to_bytes(), selector_size);
	sock->get_send_header()->pos_id = pos;
	sock->get_send_header()->socket_type = ORAM_SOCKET_READBLOCK;
	sock->get_send_header()->layer = max_layer;
	sock->get_send_header()->len = len;
	sock->get_send_header()->msg_len = selector_size;
	sock->standard_send(selector_size + ORAM_SOCKET_HEADER_SIZE);

	int block_cipher_size = OramCrypto::get_crypto()->get_chunk_size(max_layer + 1)*OramBlock::chunk_count;
	sock->standard_recv(ORAM_SOCKET_HEADER_SIZE + block_cipher_size);
	OramBlock *recv_block = new OramBlock(sock->get_recv_buf(), max_layer + 1);
	unsigned char *recv_data = (unsigned char *)recv_block->decrypt();
	if (select_id != -1) {

		memcpy(data, recv_data, OramBlock::block_size);
	} else {
		memset(data, 0, OramBlock::block_size);
	}
	return 0;
}

int OramClient::init() {
	sock->get_send_header()->socket_type = ORAM_SOCKET_INIT;
	OramSocketInit *init_header = (OramSocketInit*)sock->get_send_buf();
	int last_pos;
	init_header->bucket_count = this->bucket_count;
	init_header->block_per_bucket = this->block_per_bucket;
	init_header->block_size = this->block_size;
	init_header->chunk_size = this->chunk_size;
	init_header->mem_max = 1000;
	init_header->bits = OramCrypto::get_crypto()->bits;
	init_header->s0 = OramCrypto::get_crypto()->s0;
	init_header->s_max = 50;
	void *tem = OramCrypto::get_crypto()->ahe_sys->export_pubkey(&init_header->key_len);
	memcpy(sock->get_send_buf() + sizeof(OramSocketInit), tem, init_header->key_len);
	last_pos = ORAM_SOCKET_INIT_SIZE(init_header->key_len);

	OramMeta meta_blank;
	meta_blank.address = new int[OramBucket::bucket_size];
	for (int i = 0;i < OramBucket::bucket_size;i++) {
		meta_blank.address[i] = -1;
		meta_blank.size = OramBucket::bucket_size;
	}
	for (int i = 0;i < this->bucket_count;i++) {
		position_map[i] = OramCrypto::get_crypto()->get_random(tree_leaf_count) + tree_leaf_start;
		OramCrypto::get_crypto()->encrypt_meta(meta_blank,
		    (unsigned char *)sock->get_send_buf() + last_pos +
			i*sizeof_read_meta(OramBucket::bucket_size));
	}
	last_pos += bucket_count*sizeof_read_meta(OramBucket::bucket_size);
	sock->get_send_header()->msg_len = last_pos;
	log_detail << "Init Request Sent" << std::endl;
	sock->standard_send(ORAM_SOCKET_HEADER_SIZE + last_pos);
	return 1;
}