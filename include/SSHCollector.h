//
// Created by 佘崧林 on 2020/1/26.
//

#ifndef PUBLICKEYCOLLECTOR_SSHCOLLECTOR_H
#define PUBLICKEYCOLLECTOR_SSHCOLLECTOR_H

#include <libssh/libssh.h>
#include <string>

#include "../src/PathConst.h"
#include "../src/AbstractCollector.h"

class SSHCollector : public AbstractCollector {
public:
    explicit SSHCollector(const std::string& ipAddr, uint16_t sshPort = 22) : AbstractCollector(ipAddr, sshPort) {}
    explicit SSHCollector(const std::vector<uint8_t>& ipAddr, uint16_t sshPort = 22) : AbstractCollector(ipAddr, sshPort) {}
    bool scanServer();

private:
    ssh_key serverKey = nullptr;
    mpz_class publicMessage = mpz_class(0);
    friend class SSHsCollector;

protected:
    std::string getDataFilename() const override;
    bool getServerPublicKey() override;
    bool parseServerPublicKey() override;
    bool exportServerPublicKey() override;
};


#endif //PUBLICKEYCOLLECTOR_SSHCOLLECTOR_H
