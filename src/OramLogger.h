//
// Created by maxxie on 16-5-29.
//

#ifndef ONIONORAM_ORAMLOGGER_H
#define ONIONORAM_ORAMLOGGER_H
#include <iostream>
#include <fstream>

#define ORAM_DEBUG_LEVEL 3
//std::fstream fs("/dev/null");
#if ORAM_DEBUG_LEVEL >= 1
#define log_sys std::cout
#else
#define log_sys fs
#endif

#if ORAM_DEBUG_LEVEL >= 2
#define log_detail std::cout
#else
#define log_detail fs
#endif

#if ORAM_DEBUG_LEVEL >= 3
#define log_all std::cout
#else
#define log_all fs
#endif


#endif //ONIONORAM_ORAMLOGGER_H
