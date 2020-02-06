//
// Created by 佘崧林 on 2020/1/26.
//

#ifndef PUBLICKEYCOLLECTOR_ABSTRACTCOLLECTOR_H
#define PUBLICKEYCOLLECTOR_ABSTRACTCOLLECTOR_H

#include <gmpxx.h>
#include <vector>
#include <string>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

class AbstractCollector {
protected:
    static std::shared_ptr<spdlog::logger> consoleLogger;
    static std::shared_ptr<spdlog::sinks::basic_file_sink_mt> sharedSink;
    std::shared_ptr<spdlog::logger> fileLogger = nullptr;
    std::shared_ptr<spdlog::logger> getFileLogger();

public:
    static bool isValidInternetIP(const std::vector<uint8_t> &ipv);
    bool isValidInternetIP() { return AbstractCollector::isValidInternetIP(ipVector); }
    static bool isPortOpening(const std::vector<uint8_t> &ipv, uint16_t port);
    bool isPortOpening() { return AbstractCollector::isPortOpening(ipVector, port); }

private:
    std::string ipStrCache = "";
    std::vector<uint8_t> ipVector = {};

protected:
    uint16_t port = 0;
    AbstractCollector(const std::string &ipAddr, uint16_t p): port(p) { this->setIPAddress(ipAddr); }
    AbstractCollector(const std::vector<uint8_t> &ipAddr, uint16_t p): port(p) { this->setIPAddress(ipAddr); }
    ~AbstractCollector() { spdlog::drop(this->getIP4StringAddress()); }

    virtual std::string getDataFilename() const;
    virtual bool getServerPublicKey() = 0;
    virtual bool parseServerPublicKey() = 0;
    virtual bool exportServerPublicKey() = 0;

public:
    std::string getIP4StringAddress();
    void setIPAddress(const std::string &ip);
    void setIPAddress(const std::vector<uint8_t> &tvec);
};

#include <exception>

class AbstractException : public std::exception {
protected:
    std::string message;
public:
    explicit AbstractException(const char* msg): message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }
};
#endif //PUBLICKEYCOLLECTOR_ABSTRACTCOLLECTOR_H
