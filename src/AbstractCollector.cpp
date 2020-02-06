//
// Created by 佘崧林 on 2020/1/26.
//
#include <filesystem>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>

#include "AbstractCollector.h"
#include "PathConst.h"
#include "MessageConst.h"

auto AbstractCollector::consoleLogger = spdlog::stdout_color_mt("collector-console");
auto AbstractCollector::sharedSink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(SCANLOGPATH.string());

std::shared_ptr<spdlog::logger> AbstractCollector::getFileLogger() {
    if (fileLogger == nullptr) {
        fileLogger = std::make_shared<spdlog::logger>(this->getIP4StringAddress(), sharedSink);
    }
    return this->fileLogger;
}

bool AbstractCollector::isPortOpening(const std::vector<uint8_t> &ipv, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) throw AbstractException(ABSTRACTLOGMSG_SOCKETINITFAIL);

    in_addr_t inAddr = *((const uint32_t *) (&ipv[0]));
    struct sockaddr_in servAddr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = {.s_addr = inAddr},
    };
    return connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) >= 0;
}

bool AbstractCollector::isValidInternetIP(const std::vector<uint8_t> &ipv) {
    // https://zh.wikipedia.org/wiki/%E4%BF%9D%E7%95%99IP%E5%9C%B0%E5%9D%80
    if (ipv.size() != 4) throw AbstractException(ABSTRACTLOGMSG_IPAMOUNTWRONG);
    return !((ipv[0] == 10) ||
             (ipv[0] == 172 && ipv[1] >= 16 && ipv[1] <= 31) ||
             (ipv[0] == 192 && ipv[1] == 168) ||
             (ipv[0] == 0) ||
             (ipv[0] == 127) ||
             (ipv[0] == 169 && ipv[1] == 254) ||
             (ipv[0] == 192 && ipv[1] == 0 && ipv[2] == 0) ||
             (ipv[0] == 192 && ipv[1] == 0 && ipv[2] == 2) ||
             (ipv[0] == 198 && ipv[1] == 18) ||
             (ipv[0] == 198 && ipv[1] == 51 && ipv[2] == 100) ||
             (ipv[0] == 203 && ipv[1] == 0 && ipv[2] == 113) ||
             (ipv[0] >= 224 && ipv[0] <= 239) ||
             (ipv[0] == 255 && ipv[1] == 255 && ipv[2] == 255 && ipv[3] == 255));
}

void AbstractCollector::setIPAddress(const std::string &ip) {
    std::vector<uint8_t> tvec;
    tvec.reserve(4);
    for (auto c = ip.begin(), prev = c; c++ != ip.end();) {
        if (*c == '.' || *c == ':' || c == ip.end()) {
            auto i = std::stoi(std::string(prev, c));
            if (i > 0xff || i < 0) throw AbstractException(ABSTRACTLOGMSG_IPNUMBEROUTRANGE);
            tvec.emplace_back(uint8_t(i));
            prev = c, prev++;
        } else if (*c < '0' || *c > '9') throw AbstractException(ABSTRACTLOGMSG_IPCHAROUTRANGE);
    }
    if (tvec.size() != 4) throw AbstractException(ABSTRACTLOGMSG_IPAMOUNTWRONG);
    this->ipVector = tvec;
    this->ipStrCache = ip;
}

void AbstractCollector::setIPAddress(const std::vector<uint8_t> &tvec) {
    if (tvec.size() != 4) throw AbstractException(ABSTRACTLOGMSG_IPAMOUNTWRONG);
    if (!ipStrCache.empty()) this->ipStrCache.clear();
    this->ipVector = tvec;
}

std::string AbstractCollector::getIP4StringAddress() {
    if (!ipStrCache.empty()) return ipStrCache;

    std::stringstream sstream;
    sstream << int(ipVector[0]) << "." << int(ipVector[1]) << "." << int(ipVector[2]) << "." << int(ipVector[3]);
    return ipStrCache = sstream.str();
}

std::string AbstractCollector::getDataFilename() const {
    if (ipVector.empty()) return "";

    fs::path ipFilepath = DATAPATH;
    for (auto ipv4 : ipVector) {
        ipFilepath /= std::to_string(ipv4);
        fs::create_directories(ipFilepath);
    }
    return ipFilepath.string();
}
