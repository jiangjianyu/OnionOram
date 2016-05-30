cmake_minimum_required(VERSION 3.0)
project(OnionOram)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(SOURCE_FILES src/damgard_jurik.cpp src/OramBlock.cpp src/OramBucket.cpp src/OramClient.cpp src/OramCrypto.cpp
                 src/OramSelector.cpp src/OramServer.cpp src/OramSocket.cpp src/OramBucketStorage.cpp src/OramMain.cpp src/OramLogger.h)
add_executable(OnionOram ${SOURCE_FILES})
add_executable(TestBlock src/OramBlock.cpp src/damgard_jurik.cpp src/OramCrypto.cpp test/TestOramBlock.cpp)
add_executable(TestEncrypt src/damgard_jurik.cpp test/TestEncrypt.cpp src/OramCrypto.cpp)
add_executable(TestBucket src/damgard_jurik.cpp src/OramBlock.cpp src/OramBucket.cpp src/OramCrypto.cpp test/TestBucket.cpp)
add_executable(TestSelector src/damgard_jurik.cpp src/OramBlock.cpp src/OramBucket.cpp src/OramCrypto.cpp src/OramSelector.cpp test/TestOramSelector.cpp)
target_link_libraries(OnionOram sodium gmp)
target_link_libraries(TestBlock sodium gmp)
target_link_libraries(TestEncrypt sodium gmp)
target_link_libraries(TestBucket sodium gmp)
target_link_libraries(TestSelector sodium gmp)

set(LIBRARY_OUTPUT_PATH build/bin)