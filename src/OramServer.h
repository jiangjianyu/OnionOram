#pragma once
#include "OramSocket.h"
#include "OramBucketStorage.h"
class OramServer
{
public:
	char* host;
	int port;
	int running;
	OramSocket *sock;
	OramBucketStorage *storage;
	void r_read_block(OramSocket*);
	void r_get_metadata(OramSocket*);
	void r_evict_path(OramSocket*);
	void r_read_bucket(OramSocket*);
	void r_write_bucket(OramSocket*);
	void r_init(OramSocket*);
	void r_write_block(OramSocket*);
	void run();

	OramServer();
	OramServer(char *host, int port);
	~OramServer();
};

