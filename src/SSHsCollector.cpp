//
// Created by 佘崧林 on 2020/2/4.
//
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>

#include "../include/SSHCollector.h"
#include "../include/SSHsCollector.h"
#include "PathConst.h"
#include "MessageConst.h"

auto SSHsCollector::fileLogger = spdlog::basic_logger_mt("SUMMARY", SUMMAYLOGPATH.string());

void SSHsCollector::scanServers(const std::vector<uint8_t> &from, const std::vector<int> &to) {
    assert(from.size() == 4 && to.size() == 4);
    std::vector<uint8_t> ipv = from;
    boost::asio::thread_pool threadPool(this->threadNumber);
    for (int i0 = ipv[0]; i0 < to[0]; ipv[0] = ++i0) {
        for (int i1 = ipv[1]; i1 < to[1]; ipv[1] = ++i1) {
            size_t cache[4] = {rsaServerCount, dssServerCount, ecdsaServerCount, eddsaServerCount};
            for (int i2 = ipv[2]; i2 < to[2]; ipv[2] = ++i2) {
                for (int i3 = ipv[3]; i3 < to[3]; ipv[3] = ++i3) {
                    boost::asio::post(threadPool, [this, ipv] {
                        this->scanServer(ipv);
                    });
                }
            }
            if (cache[0] != rsaServerCount || cache[1] != dssServerCount ||
                cache[2] != ecdsaServerCount || cache[3] != eddsaServerCount) {
                fileLogger->info("[0.0.0.0]-[{0}.{1}.255.255]", i0, i1);
                fileLogger->info(SSHSLOGMSG_RSACOUNT, rsaServerCount);
                fileLogger->info(SSHSLOGMSG_DSSCOUNT, dssServerCount);
                fileLogger->info(SSHSLOGMSG_ECDSACOUNT, ecdsaServerCount);
                fileLogger->info(SSHSLOGMSG_EDDSACOUNT, eddsaServerCount);
                spdlog::flush_on(spdlog::level::info);
            }
        }
    }
    threadPool.join();
    fileLogger->info(SSHSLOGMSG_RSACOUNT, rsaServerCount);
    fileLogger->info(SSHSLOGMSG_DSSCOUNT, dssServerCount);
    fileLogger->info(SSHSLOGMSG_ECDSACOUNT, ecdsaServerCount);
    fileLogger->info(SSHSLOGMSG_EDDSACOUNT, eddsaServerCount);
}

void SSHsCollector::scanServer(const std::vector<uint8_t> &ipv) {
    if (!AbstractCollector::isValidInternetIP(ipv)) return;;

    SSHCollector sshCollector(ipv);
    if (!sshCollector.scanServer()) this->failCount++;
    switch (ssh_key_type(sshCollector.serverKey)) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
        case SSH_KEYTYPE_RSA_CERT01: this->rsaServerCount++; break;
        case SSH_KEYTYPE_DSS:
        case SSH_KEYTYPE_DSS_CERT01: this->dssServerCount++; break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_ECDSA_P256:
        case SSH_KEYTYPE_ECDSA_P384:
        case SSH_KEYTYPE_ECDSA_P521:
        case SSH_KEYTYPE_ECDSA_P256_CERT01:
        case SSH_KEYTYPE_ECDSA_P384_CERT01:
        case SSH_KEYTYPE_ECDSA_P521_CERT01: this->ecdsaServerCount++; break;
        case SSH_KEYTYPE_ED25519_CERT01:
        case SSH_KEYTYPE_ED25519: this->eddsaServerCount++; break;
        case SSH_KEYTYPE_UNKNOWN:
        default: break;
    }
}
