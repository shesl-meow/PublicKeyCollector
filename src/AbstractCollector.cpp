//
// Created by 佘崧林 on 2020/1/26.
//
#include <filesystem>
#include <sstream>

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

bool AbstractCollector::checkIPVector() const {
    // https://zh.wikipedia.org/wiki/%E4%BF%9D%E7%95%99IP%E5%9C%B0%E5%9D%80
    return !((ipVector[0] == 10) ||
             (ipVector[0] == 172 && ipVector[1] >= 16 && ipVector[1] <= 31) ||
             (ipVector[0] == 192 && ipVector[1] == 168) ||
             (ipVector[0] == 0) ||
             (ipVector[0] == 127) ||
             (ipVector[0] == 169 && ipVector[1] == 254) ||
             (ipVector[0] == 192 && ipVector[1] == 0 && ipVector[2] == 0) ||
             (ipVector[0] == 192 && ipVector[1] == 0 && ipVector[2] == 2) ||
             (ipVector[0] == 198 && ipVector[1] == 18) ||
             (ipVector[0] == 198 && ipVector[1] == 51 && ipVector[2] == 100) ||
             (ipVector[0] == 203 && ipVector[1] == 0 && ipVector[2] == 113) ||
             (ipVector[0] >= 224 && ipVector[0] <= 239) ||
             (ipVector[0] == 255 && ipVector[1] == 255 && ipVector[2] == 255 && ipVector[3] == 255));
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
