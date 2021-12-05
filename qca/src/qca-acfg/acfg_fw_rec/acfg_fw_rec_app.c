/*
 * Copyright (c) 2015-2016,2018-2021 Qualcomm Technologies, Inc.
 *
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

#include<acfg_tool.h>
#include<acfg_event.h>

#define BUFF_INIT_SIZE      500
#define NULLCHAR            '\0'


#define MAX_NUM_CHAINS   8
#define MAX_RXG_CAL_CHANS 8

/*
 * Prototypes
 */

uint32_t
cb_wdt_event(uint8_t * ifname, acfg_wdt_event_t * wdt_event);

void usage(void);
int recv_events(char *ifname, int nonblock) ;
void acfg_set_tftp_server_addr(const char *tftp_addr);

/* Globals */
extern int acfg_event_log;

/* Options acepted by this tool
 *
 * p - Print description of command line parameters for acfg api
 * e - Wait for events
 */
static char *option_args = "ne::p::w::st:" ;
char *appname;

int main(int argc , char *argv[])
{

    int c;
    int ret = 0 ;
    int opt_events = 0 ;
    int opt_events_nonblock = 0 ;
    char *opt_event_arg = NULL;
    acfg_dl_init();

    appname = basename(argv[0]);


    while( (c = getopt(argc , argv , option_args)) != -1 )
    {
        switch (c)
        {
            case 'e':
                opt_events = 1 ;
                opt_event_arg = optarg ;
                break;

            case 'n':
                opt_events_nonblock = 1 ;
                break;

            case 's':
                acfg_event_log = 0 ;
                break;
            case 't':
                acfg_set_tftp_server_addr(optarg);
                break;
            case '?':
                /* getopt returns error */
                usage();
                return 0;

            default:
                usage();
                return 0;
        } //end switch
    }//end while

    if(opt_events)
    {
        ret = recv_events(opt_event_arg,opt_events_nonblock);
    }

    if(ret != 0)
    {
        printf("\n<<<<<<<<<< Dumping LOG >>>>>>>>>>>>>\n");
        printf("Error %d , try again. \n", ret);
        printf("%s", acfg_get_errstr());
        printf("\n<<<<<<<<<<<<<< End >>>>>>>>>>>>>>>>>\n");
    }

    return ret ;
}

void usage(void)
{
    printf("\n");
    printf("\t%s <acfg api name> <api arguments> \n",appname);
    printf("\t%s -p \n\t\tPrint help for "\
            "all acfg apis\n\n",appname);

    printf("\t%s -p<acfg api name> \n\t\tPrint help for "\
            "one acfg api\n\n",appname);

    printf("\t%s -e <interface name> [-n]"\
            "\n\t\tWait for events on interface. "
            " -n issues a nonblocking call to acfg library\n\n",appname);
}


acfg_event_t ev ;

/**
 * @brief Receive events
 *
 * @param ifname
 * @param nonblock - 1 for nonblocking call
 *                   0 for blocking call
 * @return
 */
int recv_events(char *ifname, int nonblock)
{
    uint32_t status ;
    acfg_event_mode_t evmode ;

    if(nonblock == 1)
        evmode = ACFG_EVENT_NOBLOCK ;
    else
        evmode = ACFG_EVENT_BLOCK ;

    ev.wdt_event = cb_wdt_event;
    status = acfg_recv_events(&ev, evmode);
    if(status != QDF_STATUS_SUCCESS && status != QDF_STATUS_E_SIG)
    {
        printf("Acfg lib returned error...");
        goto errout;
    }

    if(evmode == ACFG_EVENT_NOBLOCK)
    {
        printf("Returned from acfg lib call. Going to sleep...");
        while(1)
            sleep(1000);
    }

errout: ;
        return acfg_to_os_status(status) ;
}
