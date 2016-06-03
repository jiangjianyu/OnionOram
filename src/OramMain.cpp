//
// Created by maxxie on 16-5-28.
//

#include <cstring>
#include "OramLogger.h"
#include "OramServer.h"
#include "OramClient.h"

int main(int argc, char **args) {
    if (argc <= 1)
        return -1;
    else if (!strcmp(args[1], "server")) {
        log_sys << "Server Starting" << std::endl;
        OramServer server = OramServer("10.0.1.30", 30000);
        server.run();
    } else if (!strcmp(args[1], "client")) {
        log_sys << "Client Starting" << std::endl;
        OramClient client = OramClient("127.0.0.1", 30000, 32, 5, 10240, 1024, "ORAM", 4, 9, 1024);
        client.init();
        unsigned char data[10240];
        data[0] = 12;
        client.access(1, ORAM_ACCESS_WRITE, data);
        client.access(2, ORAM_ACCESS_WRITE, data);
        client.access(3, ORAM_ACCESS_WRITE, data);
        client.access(4, ORAM_ACCESS_WRITE, data);
        client.access(5, ORAM_ACCESS_WRITE, data);
        client.access(6, ORAM_ACCESS_READ, data);
        printf("%d\n", data[0]);
    }
}