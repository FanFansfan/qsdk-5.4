/*
 * Copyright (c) 2019,2021 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008-2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdint.h>

#include <linux/un.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <acfg_types.h>
#include <acfg_api.h>
#include <acfg_api_pvt.h>
#include <acfg_event.h>
#include <acfg_security.h>
#include <acfg_api_event.h>
#include <acfg_misc.h>
#include<appbr_types.h>
#include <acfg_tool.h>

/*
 * Fields required to maintain netlink socket.
 */
struct acfg_rtnl_hdl
{
    int acfg_fd;
    struct sockaddr_nl acfg_local;
    struct sockaddr_nl      acfg_peer;
    __u32 acfg_seq;
    __u32 acfg_dump;
};



#define FW_DUMP_TFTP_CMD_PREFIX "cd /dev && tftp -l "
#define FW_DUMP_DEFAULT_FILE "q6mem "
#define FW_DUMP_TFTP_DEFAULT_SERVER_IP "192.168.1.100"
#define FW_DUMP_TFTP_CMD_SUFFIX " 2>&1"
#define FW_DUMP_HOTPLUG_DEFAULT_APP "/etc/hotplug.d/dump_q6v5/00-q6dump"



#if ACFG_DEBUG_ERROR
#define acfg_log_errstr(fmt, ...) _acfg_print(fmt, ##__VA_ARGS__)
#else
#define acfg_log_errstr(fmt, ...) _acfg_log_errstr(fmt, ##__VA_ARGS__)
#endif

int acfg_event_log = 1;
static int loop_for_events ;
char tftp_server[IP_ADDR_LEN +1] = FW_DUMP_TFTP_DEFAULT_SERVER_IP;

appbr_status_t appbr_if_open_dl_conn(uint32_t app_id);
appbr_status_t appbr_if_open_ul_conn(uint32_t app_id);


/**
 * @brief signal handler
 *
 * @param int
 */
static void
sig_handler(int sig)
{
    if(sig == SIGINT) {
        loop_for_events = 0;
    }
    else
        acfg_log_errstr("%s:Unknown signal(%d) received\n\r", __func__, sig);

    return;
}


uint32_t
acfg_logger(uint8_t *buf)
{
    FILE *ev_fp;

    if (!acfg_event_log)
        return QDF_STATUS_SUCCESS;

    ev_fp = fopen(ACFG_EVENT_LOG_FILE, "a+");
    if (ev_fp == NULL) {
        printf("unable to open event log file\n");
        return QDF_STATUS_E_FAILURE;
    }
    fprintf(ev_fp, "%s\n", buf);
    fclose(ev_fp);

    return QDF_STATUS_SUCCESS;
}



/*
 * Open a RtNetlink socket
 * Return: 0 on Success
 *         -ve on Error
 */
static inline
int acfg_rt_nl_open(struct acfg_rtnl_hdl *acfg_rth, unsigned sub)
{
    int acfg_addr_len;

    memset(acfg_rth, 0, sizeof(struct acfg_rtnl_hdl));

#ifdef ACFG_PARTIAL_OFFLOAD
    acfg_rth->acfg_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ACFG_EVENT);
#else
    acfg_rth->acfg_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
#endif

    if (acfg_rth->acfg_fd < 0) {
        return -1;
    }

    memset(&acfg_rth->acfg_local, 0, sizeof(acfg_rth->acfg_local));
    acfg_rth->acfg_local.nl_family = AF_NETLINK;
    acfg_rth->acfg_local.nl_groups = sub;

    if (bind(acfg_rth->acfg_fd, \
                (struct sockaddr*)&acfg_rth->acfg_local, sizeof(acfg_rth->acfg_local)) < 0) {
        acfg_log_errstr("bind failed: %s\n", strerror(errno));
        goto error;
    }

    acfg_addr_len = sizeof(acfg_rth->acfg_local);
    if (getsockname(acfg_rth->acfg_fd, (struct sockaddr*)&acfg_rth->acfg_local,
                (socklen_t *) &acfg_addr_len) < 0) {
        goto error;
    }

    if (acfg_addr_len != sizeof(acfg_rth->acfg_local)) {
        goto error;
    }

    if (acfg_rth->acfg_local.nl_family != AF_NETLINK) {
        goto error;
    }
    acfg_rth->acfg_seq = time(NULL);
    return 0;

error:
      close(acfg_rth->acfg_fd);
      return -1;
}

/**
 * @brief  Initialize interface for device-less configurations
 *
 * @return
 */
uint32_t acfg_dl_init()
{

    uint32_t ret_status = QDF_STATUS_E_FAILURE;

    ret_status = appbr_if_open_dl_conn(APPBR_ACFG);
    if(ret_status != QDF_STATUS_SUCCESS)
        goto out;

    ret_status = appbr_if_open_ul_conn(APPBR_ACFG);
    if(ret_status != QDF_STATUS_SUCCESS)
        goto out;

out:
    return  ret_status;
}


static inline
void acfg_rt_nl_close(struct acfg_rtnl_hdl *acfg_rth)
{
    close(acfg_rth->acfg_fd);
}



uint32_t acfg_recover_profile(char *radioname)
{
    char cmd[32];
    int ret = 0;

    acfg_reset_errstr();
    memset(&cmd, '\0', sizeof(cmd));

    snprintf(cmd, sizeof(cmd)-1, "/sbin/wifi recover %s", radioname);
    ret = system(cmd);
    return ret;
}

void acfg_set_tftp_server_addr(const char *tftp_addr)
{
   strlcpy(tftp_server, optarg, sizeof(tftp_server));
}

uint32_t
cb_wdt_event(uint8_t * ifname, acfg_wdt_event_t * wdt_event)
{
    uint8_t buf[256];
    uint8_t fw_dump_file_name[128];

    if(wdt_event->reason==ACFG_WDT_TARGET_ASSERT){
        snprintf((char *)buf, sizeof(buf), "%s: Watchdog event: target assert!\n", ifname);
        acfg_logger(buf);
    }else if(wdt_event->reason==ACFG_WDT_FWDUMP_READY){
        /* If hotplug file doesn't exists, collect the dump here */
        if(access(FW_DUMP_HOTPLUG_DEFAULT_APP, F_OK) == -1) {
            memset(fw_dump_file_name, '\0', 128);
            if (wdt_event->dump_file[0] != '\0')
                snprintf((char *)fw_dump_file_name, "%s%s",
                         "/dev/", wdt_event->dump_file);

            /* If file with the filename from the driver exists, use that,
             * else use the default file name
             */
            if (fw_dump_file_name[0] != '\0' &&
                (access(fw_dump_file_name, F_OK) != -1)) {
               snprintf((char *)buf, sizeof(buf),
                        FW_DUMP_TFTP_CMD_PREFIX "%s -p %s" FW_DUMP_TFTP_CMD_SUFFIX,
                        wdt_event->dump_file, tftp_server);
            } else {
               snprintf((char *)buf, sizeof(buf),
                        FW_DUMP_TFTP_CMD_PREFIX FW_DUMP_DEFAULT_FILE "-p %s" FW_DUMP_TFTP_CMD_SUFFIX,
                        tftp_server);
            }
            system((char *)buf);
        }
        snprintf((char *)buf, sizeof(buf), "%s: Watchdog event: FW Dump Ready!\n", ifname);
        acfg_logger(buf);
    }else if(wdt_event->reason==ACFG_WDT_REINIT_DONE){
        snprintf((char *)buf, sizeof(buf), "%s: Watchdog event: re-init done!\n", ifname);
        acfg_logger(buf);
        if (acfg_recover_profile((char *)ifname) == QDF_STATUS_SUCCESS) {
            snprintf((char *)buf, sizeof(buf), "%s: Profile recovered.\n", ifname);
            acfg_logger(buf);
        }
    }

    return QDF_STATUS_SUCCESS ;
}


static uint32_t
notify_event(uint8_t *ifname, acfg_os_event_t *msg, \
        acfg_event_t *event, uint8_t *userif)

{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_ev_data_t *pdata = &msg->data ;

    if (userif != NULL) {
        if(strncmp(ifname, userif, ACFG_MAX_IFNAME) != 0)
            return QDF_STATUS_SUCCESS ;
    }

    if ((msg->id == ACFG_EV_WDT_EVENT) && event->wdt_event)
        status = event->wdt_event(ifname, &pdata->wdt);
    return status;
}

/*
 * Respond to a single RTM_NEWLINK event from the rtnetlink socket.
 * Return: 0 On Success ;
 *
 */
static int
parse_event(struct nlmsghdr *nlh, acfg_event_t *event, uint8_t *userif)
{
    struct ifinfomsg* ifi;

    ifi = NLMSG_DATA(nlh);

    if(nlh->nlmsg_type != RTM_NEWLINK)
        return 0;

    /* Check for attributes */
    if (nlh->nlmsg_len > NLMSG_ALIGN(sizeof(struct ifinfomsg)))
    {
        int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct ifinfomsg));
        struct rtattr *attr = (void *) ((char *) ifi +
                NLMSG_ALIGN(sizeof(struct ifinfomsg)));
        char *ifname = NULL;

        while (RTA_OK(attr, attrlen))
        {

            /* Check if the Wireless kind */
            if(attr->rta_type == IFLA_IFNAME)
            {
                ifname = (char *) attr + RTA_ALIGN(sizeof(struct rtattr)) ;
                /*
                   fprintf(stderr,"%s: attr type is IFLA_IFNAME - %s\n",\
                   __FUNCTION__,ifname);
                 */
            }

            if(attr->rta_type == IFLA_WIRELESS)
            {
                /*fprintf(stderr,"%s: wireless event \n",__FUNCTION__);*/

                acfg_os_event_t *msg = (acfg_os_event_t *) ((char *) attr + \
                        RTA_ALIGN(sizeof(struct rtattr))) ;

                if(ifname)
                    notify_event((uint8_t *)ifname, msg, event, userif);
            }

            attr = RTA_NEXT(attr, attrlen);
        }
    }//endif

    return 0;
}


/*
 * This routine handles events (i.e., call this when rth.acfg_fd
 * is ready to read).
 */
static inline void
handle_netlink_events(struct acfg_rtnl_hdl *rth, \
        acfg_event_t *event, uint8_t *ifname)
{

    /*fprintf(stderr, "acfg_lib: %s \n",__FUNCTION__);*/
    while(1)
    {
        struct sockaddr_nl sanl;
        socklen_t sanllen = sizeof(struct sockaddr_nl);
        struct nlmsghdr *h;
        int amt;
        char buf[2048];

        amt = recvfrom(rth->acfg_fd, buf, sizeof(buf), MSG_DONTWAIT, \
                (struct sockaddr*)&sanl, &sanllen);
        if(amt < 0)
        {
            /*fprintf(stderr, "acfg_lib: error reading netlink\n");*/
            return ;
        }

        if(amt == 0)
        {
            /*fprintf(stderr, "acfg_lib: EOF on netlink\n");*/
            return ;
        }

        h = (struct nlmsghdr*)buf;
        while(amt >= (int)sizeof(*h))
        {
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if(l < 0 || len > amt)
            {
                /*fprintf(stderr, "%s: malformed netlink message: len=%d\n",\
                  __FUNCTION__, len);*/
                break;
            }

            switch(h->nlmsg_type)
            {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                    /*fprintf(stderr,"RTM_NEW/DEL LINK in %s\n",__FUNCTION__);*/
                    parse_event(h,event,ifname);
                    break;

                default:
                    /*fprintf(stderr,"default in %s \n",__FUNCTION__);*/
                    break;
            }

            len = NLMSG_ALIGN(len);
            amt -= len;
            h = (struct nlmsghdr*)((char*)h + len);
        }//end while

    }//end while
}


/**
 * Wait until we get an event
 *
 * Return: 0 - Success
 *         1 - Exit due to received SIGINT
 *         -ve - Error
 */
static inline int
wait_for_event(struct acfg_rtnl_hdl * rth, \
        acfg_event_t *event, uint8_t *ifname)
{
    void (*old_handler)(int sig) ;
    int status = 0;

    /*printf("%s() \n",__FUNCTION__);*/

    /* Register new signal handler */
    old_handler = signal(SIGINT, sig_handler) ;
    if(old_handler == SIG_ERR)
    {
        acfg_log_errstr("%s(): unable to register signal handler \n",__FUNCTION__);
        return -1;
    }

    loop_for_events = 1;
    while(1)
    {
        fd_set rfds;        /* File descriptors for select */
        int last_fd;        /* Last fd */
        int ret;

        /* Guess what ? We must re-generate rfds each time */
        FD_ZERO(&rfds);
        FD_SET(rth->acfg_fd, &rfds);
        last_fd = rth->acfg_fd;

        /* Wait until something happens */
        ret = select(last_fd + 1, &rfds, NULL, NULL, NULL);

        /* Check if there was an error */
        if(ret < 0)
        {
            if(errno == EINTR)
            {
                if(loop_for_events == 0)
                {
                    /*printf("%s(): Exit due to signal \n",__FUNCTION__);*/
                    status = 1;
                    break ;
                }
                else
                    continue ;
            }
            else if(errno == EAGAIN)
                continue;
            else
            {
                /* Unhandled signal */
                status = -1;
                break;
            }
        }

        /* Check for interface discovery events. */
        if(FD_ISSET(rth->acfg_fd, &rfds))
            handle_netlink_events(rth, event,ifname);
    }//end while

    /* Restore original signal handler for SIGINT */
    signal(SIGINT, old_handler) ;
    return status ;
}


uint32_t
acfg_recv_events(acfg_event_t *event, \
        acfg_event_mode_t  mode)
{
    struct acfg_rtnl_hdl    rth;
    uint32_t status = QDF_STATUS_SUCCESS;
    int ret = 0 ;
    void (*old_handler)(int sig) ;

    if(mode == ACFG_EVENT_NOBLOCK)
        return QDF_STATUS_E_NOSUPPORT ;
    /* Open netlink channel */
    if(acfg_rt_nl_open(&rth, RTMGRP_NOTIFY) < 0) {
        return QDF_STATUS_E_FAILURE ;
    }


    old_handler = signal(SIGINT, sig_handler) ;
    if(old_handler == SIG_ERR)
    {
        acfg_log_errstr("%s(): unable to register signal handler \n",__FUNCTION__);
        acfg_rt_nl_close(&rth);
        return -1;
    }

    loop_for_events = 1;
    while (1) {
        ret = wait_for_event(&rth, event, NULL);
        if (ret == 2) {
            break;
        }
    }
    signal(SIGINT, old_handler) ;
    acfg_rt_nl_close(&rth);
    if(ret == 2)
        status = QDF_STATUS_E_SIG ;
    return status;
}
