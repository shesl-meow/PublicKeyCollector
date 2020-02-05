//
// Created by 佘崧林 on 2020/1/28.
//
#define BOOST_TEST_MODULE "SSHCollectorTestCases"
#include <boost/test/included/unit_test.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "../include/SSHCollector.h"
#include "../include/SSHsCollector.h"
#include "../src/PathConst.h"

std::shared_ptr<spdlog::logger> initLog()
{
    auto console = spdlog::stdout_color_mt("test-console");
    spdlog::set_default_logger(console);
    spdlog::set_level(spdlog::level::debug);
    return console;
}

struct {
    std::string ip;
    bool success;
} singleServerTestCases[] = {
    {"mm", false},
    {"256.1.1.1", false},
    {"1.2.3.4.5", false},
    {"127.0.0.1", false},
    {"39.105.214.245", true},
    {"47.94.141.55", true},
};

BOOST_AUTO_TEST_CASE ( single_server_test ) {
    auto logger = initLog();
    for (const auto& sstc: singleServerTestCases) {
        try {
            SSHCollector sshCollector(sstc.ip);
            BOOST_CHECK_MESSAGE(sshCollector.scanServer() == sstc.success, "Scan should success.");
        } catch (std::exception const& ae) {
            logger->error(ae.what());
            BOOST_CHECK_MESSAGE(!sstc.success, "Scan should fail.");
        }
    }
}

BOOST_AUTO_TEST_CASE ( local_server_test ) {
    auto *sshCollector = new SSHCollector("127.0.0.1");
    BOOST_CHECK_MESSAGE(sshCollector->scanServer(), "Scan Properly");
    delete sshCollector;
}

BOOST_AUTO_TEST_CASE ( all_server_test ) {
    auto logger = initLog();
    auto *sshsCollector = new SSHsCollector();
    sshsCollector->scanServers();
    delete sshsCollector;
}
