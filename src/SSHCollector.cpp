//
// Created by 佘崧林 on 2020/1/26.
//
#include <gmpxx.h>
#include <filesystem>
#include <boost/beast/core/detail/base64.hpp>

#include "../include/SSHCollector.h"
#include "MessageConst.h"
//
//SSHCollector::SSHCollector(const std::string& ipAddr, uint16_t sshPort) : AbstractCollector(ipAddr, sshPort) {
//    fileLogger = spdlog::basic_logger_mt(this->getIP4StringAddress(), SCANLOGPATH.string());
//    consoleLogger = spdlog::stdout_color_mt(this->getIP4StringAddress());
//    spdlog::set_level(spdlog::level::info);
//    consoleLogger->info(SSHLOGMSG_INITSUCCESS);
//}
//
//SSHCollector::SSHCollector(const std::vector<uint8_t> &ipAddr, uint16_t sshPort) : AbstractCollector(ipAddr, sshPort) {
//    fileLogger = spdlog::basic_logger_mt(this->getIP4StringAddress(), SCANLOGPATH.string());
//    consoleLogger = spdlog::stdout_color_mt(this->getIP4StringAddress());
//    spdlog::set_level(spdlog::level::info);
//    consoleLogger->info(SSHLOGMSG_INITSUCCESS);
//}

std::string SSHCollector::getDataFilename() const {
    std::__fs::filesystem::path parentPath = AbstractCollector::getDataFilename();
    parentPath /= "ssh" + std::to_string(this->port) + "." +
            ssh_key_type_to_char(ssh_key_type(serverKey)) + ".cert";
    return parentPath.string();
}

bool SSHCollector::exportServerPublicKey() {
    FILE *outf = fopen(this->getDataFilename().c_str(), "w");
    if (outf == nullptr) goto storeToFile_ERROR;
    if (publicMessage != mpz_class(0))
        if (mpz_out_raw(outf, publicMessage.get_mpz_t()) <= 0)
            goto storeToFile_ERROR;

    fclose(outf);
    return true;
storeToFile_ERROR:
    fclose(outf);
    getFileLogger()->error(SSHLOGMSG_EXPORTFAILED);
    return false;
}

bool SSHCollector::getServerPublicKey() {
    ssh_session session = ssh_new();
    if (session == nullptr) {
        getFileLogger()->error(SSHLOGMSG_SSHLIBERROR);
        return false;
    }
    ssh_options_set(session, SSH_OPTIONS_HOST, this->getIP4StringAddress().c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_connect(session);

    if (ssh_get_server_publickey(session, &serverKey) < 0) {
        consoleLogger->warn(SSHLOGMSG_SERVERERROR, this->getIP4StringAddress());
        return false;
    }

    ssh_disconnect(session);
    ssh_free(session);
    return true;
}

bool SSHCollector::scanServer() {
    const std::string ip = this->getIP4StringAddress();
    if (!this->getServerPublicKey()) return false;
    consoleLogger->info(SSHLOGMSG_GETKEYSUCCESS, ip);

    if (!this->parseServerPublicKey()) return false;
    consoleLogger->info(SSHLOGMSG_PARSEKEYSUCCESS, ip);

    if (!this->exportServerPublicKey()) return false;
    consoleLogger->info(SSHLOGMSG_EXPORTSUCCESS, ip);

    return true;
}

bool SSHCollector::parseServerPublicKey() {
    namespace bbdb64 = boost::beast::detail::base64;
    char *b64cipher = nullptr, *b64plain = nullptr;
    size_t clen = 0, plen = 0;
    mpz_t mpint; mpz_init(mpint);
    std::pair<size_t, size_t> pairFlag;
    publicMessage = mpz_class(0);

    if (ssh_pki_export_pubkey_base64(serverKey, &b64cipher) != SSH_OK)
        goto getPrimeProduct_ERROR;
    clen = strlen(b64cipher);
    plen = bbdb64::decoded_size(clen);
    b64plain = new char[plen + 1];
    pairFlag = bbdb64::decode(b64plain, b64cipher, clen);
    if (pairFlag.first > plen || pairFlag.second > clen)
        goto getPrimeProduct_ERROR;


    switch (ssh_key_type(serverKey)) {
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
        case SSH_KEYTYPE_RSA_CERT01:
        {
            mpz_import(mpint, 4, 1, sizeof(char), 0, 0, b64plain);
            auto mpsizeT = mpz_class(mpint).get_ui(); // sizeof type description
            mpz_import(mpint, 4, 1, sizeof(char), 0, 0, b64plain + 4 + mpsizeT);
            auto mpsizeE = mpz_class(mpint).get_ui(); // sizeof e
            mpz_import(mpint, 4, 1, sizeof(char), 0, 0, b64plain + 4 + mpsizeT + 4 + mpsizeE);
            auto mpsizeN = mpz_class(mpint).get_ui(); // sizeof N
            mpz_import(mpint, mpsizeN, 1, sizeof(char), 0, 0, b64plain + 4 + mpsizeT + 4 + mpsizeE + 4);
            publicMessage = mpz_class(mpint);
        }
            break;
        case SSH_KEYTYPE_DSS:
        case SSH_KEYTYPE_DSS_CERT01:
        {
            // https://notes.shesl.top/an-quan-ji-shu/mi-ma-xue/gong-yue-mi-ma-ti-zhi/elgamal
            mpz_import(mpint, 4, 1, sizeof(char), 0, 0, b64plain);
            auto mpsizeT = mpz_class(mpint).get_ui(); // sizeof type description
            mpz_import(mpint, 4, 1, sizeof(char), 0, 0, b64plain + 4 + mpsizeT);
            auto mpsizeP = mpz_class(mpint).get_ui(); // sizeof p
            mpz_import(mpint, mpsizeP, 1, sizeof(char), 0, 0, b64plain + 4 + mpsizeT + 4);
            publicMessage = mpz_class(mpint);
        }
            break;
        default:
            getFileLogger()->warn(SSHLOGMSG_ALGORITHMNOTSUPPORT,
                    ssh_key_type_to_char(ssh_key_type(serverKey)));
            publicMessage = mpz_class(0);
            break;
    }

    delete []b64cipher;
    delete []b64plain;
    mpz_clear(mpint);
    return true;
getPrimeProduct_ERROR:
    delete []b64cipher;
    delete []b64plain;
    mpz_clear(mpint);
    getFileLogger()->error(SSHLOGMSG_DECODEPFAILED);
    return false;
}

