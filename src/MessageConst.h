//
// Created by 佘崧林 on 2020/1/29.
//

#ifndef PUBLICKEYCOLLECTOR_MESSAGECONST_H
#define PUBLICKEYCOLLECTOR_MESSAGECONST_H

#define ABSTRACTLOGMSG_IPNUMBEROUTRANGE "Invalid ipv4 address (Constituent number should within 0-255)"
#define ABSTRACTLOGMSG_IPCHAROUTRANGE "Invalid ipv4 address (Please provide characters of decimal representation)"
#define ABSTRACTLOGMSG_IPAMOUNTWRONG "Invalid ipv4 address (Required exactly four numbe)"
#define ABSTRACTLOGMSG_NOTINTERNETIP "Invalid ipv4 address '{0}', it's a reserved address"

#define SSHLOGMSG_IPV4SETSUCCESS "Server '{0}' has been set successfully."
#define SSHLOGMSG_INITSUCCESS "SSHCollector has been init successfully."
#define SSHLOGMSG_GETKEYSUCCESS "[{0}] Server's public key has been got successfully."
#define SSHLOGMSG_PARSEKEYSUCCESS "[{0}] Public number message has been extract from public key."
#define SSHLOGMSG_EXPORTSUCCESS "[{0}] Server's public message has been export."

#define SSHLOGMSG_ALGORITHMNOTSUPPORT "Server config public algorithm '{0}' that isn't support."
#define SSHLOGMSG_DECODEPFAILED "Depart public message from signature failed."
#define SSHLOGMSG_EXPORTFAILED "Failed to export public message into filesystem."
#define SSHLOGMSG_SSHLIBERROR "An error of sshlib has occur."
#define SSHLOGMSG_SERVERERROR "[{0}] Can't grab public key throw Internet."

#define SSHSLOGMSG_RSACOUNT "'{0}' of ssh-rsa server has been discovered."
#define SSHSLOGMSG_DSSCOUNT "'{0}' of ssh-dss server has been discovered."
#define SSHSLOGMSG_ECDSACOUNT "'{0}' of ssh-ecdsa server has been discovered."
#define SSHSLOGMSG_EDDSACOUNT "'{0}' of ssh-eddsa server has been discovered."
#endif //PUBLICKEYCOLLECTOR_MESSAGECONST_H
