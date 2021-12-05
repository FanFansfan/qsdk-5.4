/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "dppManager.h"

#include <memory>

int main(int argc, char* argv[]) {
    std::shared_ptr<DppConfig>  dpp_config_p = std::make_shared<DppConfig> ();
    std::unique_ptr<DPPManager> dm_p =
        std::make_unique<DPPManager>(dpp_config_p);

    std::string cmd = argv[0];
    for (int idx = 1; idx < argc; idx++) {
        cmd += " " + std::string(argv[idx]);
    }

    int ret = dm_p->ProcessCommand(cmd);
    if (ret < 0) {
        dpp_daemon_print(dpp_config_p.get(), DPPDAEMON_MSG_ERROR,
                         "[%s] Failed to start DppDaemon with config:"
                         " %s", __func__, cmd.c_str());
    }
    return 0;
}


