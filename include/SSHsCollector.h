//
// Created by 佘崧林 on 2020/2/4.
//

#ifndef PUBLICKEYCOLLECTOR_SSHSCOLLECTOR_H
#define PUBLICKEYCOLLECTOR_SSHSCOLLECTOR_H

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

class SSHsCollector {
private:
    static std::shared_ptr<spdlog::logger> fileLogger;

    const unsigned int threadNumber = 32;

    size_t failCount = 0;
    size_t rsaServerCount = 0;
    size_t dssServerCount = 0;
    size_t ecdsaServerCount = 0;
    size_t eddsaServerCount = 0;
    void scanServer(const std::vector<uint8_t> &ipv);

public:
    void scanServers(const std::vector<uint8_t> &from, const std::vector<int> &to);
};


#endif //PUBLICKEYCOLLECTOR_SSHSCOLLECTOR_H
