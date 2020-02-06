//
// Created by 佘崧林 on 2020/1/28.
//

#ifndef PUBLICKEYCOLLECTOR_PATHCONST_H
#define PUBLICKEYCOLLECTOR_PATHCONST_H
#include <filesystem>

namespace fs = std::__fs::filesystem;

const fs::path DATAPATH = std::__fs::filesystem::current_path() / "data";
const fs::path LOGPATH = std::__fs::filesystem::current_path() / "logs";
const fs::path SUMMAYLOGPATH = LOGPATH / "summary.log";
const fs::path SCANLOGPATH = LOGPATH / "scan.log";

#endif //PUBLICKEYCOLLECTOR_PATHCONST_H
