/*
 * Copyright (c) 2015-2016,2018-2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary
*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<ctype.h>
#include<string.h>
#include <libgen.h>
#include<stdint.h>
#include<sys/types.h>

#include <acfg_types.h>
#include<acfg_api.h>
#include <acfg_config_file.h>

extern struct socket_context g_sock_ctx;
extern uint8_t g_acfg_standard;
/*
 * Prototypes
 */
void usage(void);

int wrap_set_profile(char *params[])
{
    int status = QDF_STATUS_SUCCESS;
    acfg_wlan_profile_t *new_profile;
    int i = 0;

    /* Get New Profile */
    new_profile = acfg_get_profile(params[0]);
    if( NULL == new_profile )
        return QDF_STATUS_E_INVAL;
    /* Read New profile from user & populate new_profile */
    status = acfg_read_file(params[1], new_profile);
    if(status < 0 ) {
        printf("New profile could not be read \n\r");
        /* Free cur_profile & new_profile */
        acfg_free_profile(new_profile);
        return QDF_STATUS_E_FAILURE;
    }
    for (i = 0; i < new_profile->num_vaps; i++) {
        strlcpy((char *)new_profile->vap_params[i].radio_name,
                (char *)new_profile->radio_params.radio_name, sizeof(new_profile->vap_params[i].radio_name));
    }
    strlcpy(ctrl_hapd, new_profile->ctrl_hapd, sizeof(ctrl_hapd));
    strlcpy(ctrl_wpasupp, new_profile->ctrl_wpasupp, sizeof(ctrl_wpasupp));

    g_acfg_standard = new_profile->acfg_standard;

    /* Apply the new profile */
    status = acfg_apply_profile(new_profile);

    if(status == QDF_STATUS_SUCCESS)
        printf("Configuration Completed \n\r");

    /* Free cur_profile & new_profile */
    acfg_free_profile(new_profile);

    return status;
}

void usage(void)
{
    printf("\nInvalid input to acfg_set_profile\n");
    printf("Usage: acfg_set_profile <radio_iface_name> <config_file>");
}


int main(int argc , char *argv[])
{
    int ret = 0 ;
    acfg_dl_init();

    if (argc != 3) {
        usage();
        return -1;
    }

    g_sock_ctx.cfg80211 = get_config_mode_type();
    init_socket_context(&g_sock_ctx, DEFAULT_NL80211_CMD_SOCK_ID,
                                   DEFAULT_NL80211_EVENT_SOCK_ID);

    ret = wrap_set_profile(&argv[1]);

    if(ret != 0)
    {
        printf("\n<<<<<<<<<< Dumping LOG >>>>>>>>>>>>>\n");
        printf("Error %d , try again. \n", ret);
        printf("%s", acfg_get_errstr());
        printf("\n<<<<<<<<<<<<<< End >>>>>>>>>>>>>>>>>\n");
    }

    destroy_socket_context(&g_sock_ctx);
    return ret;
}
