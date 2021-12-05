/*
 * Copyright (c) 2012,2017,2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2012 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  icm_socket.c
 *
 *    Description:  Socket Interface
 *
 *        Version:  1.0
 *        Created:  04/23/2012 11:58:08 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *
 * =====================================================================================
 */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <net/if.h>
#include <fcntl.h>
#include <limits.h>

#ifdef WLAN_SPECTRAL_ENABLE
#include "spectral_data.h"
#endif /* WLAN_SPECTRAL_ENABLE */
#include "icm.h"

/*
 * Function     : icm_init_streaminet_socket
 * Description  : initialize TCP server socket interface
 * Input params : pointer to icm info structure
 * Return       : pointer to icm info structure
 *
 */
int icm_init_streaminet_socket(ICM_DEV_INFO_T* pdev)
{
    ICM_INET_T *pinet = ICM_GET_ADDR_OF_INETINFO(pdev);

    /* init socket interface */
    pinet->listener = socket(PF_INET, SOCK_STREAM, 0);

    /* validate */
    if (pinet->listener < 0) {
        perror("icm : unable to open socket\n");
        return FAILURE;
    }

    /* set socket option : Reuse */
    if (setsockopt(pinet->listener, SOL_SOCKET, SO_REUSEADDR, &pinet->on, sizeof(pinet->on)) < 0) {
        perror("icm : bind error\n");
        close(pinet->listener);
        return FAILURE;
    }

    /* initialize.... */
    memset(&pinet->server_addr, 0, sizeof(pinet->server_addr));
    pinet->server_addr.sin_family = AF_INET;
    pinet->server_addr.sin_port   = htons(ATHPORT);
    pinet->server_addr.sin_addr.s_addr = INADDR_ANY;
    pinet->type = SOCK_TYPE_TCP;

    /* bind the listener socket */
    if (bind(pinet->listener, (struct sockaddr*)&pinet->server_addr, sizeof(pinet->server_addr)) < 0) {
        perror("icm : bind error\n");
        close(pinet->listener);
        return FAILURE;
    }

    /* start listening */
    if (listen(pinet->listener, BACKLOG) == -1) {
        perror("icm : listen error\n");
        close(pinet->listener);
        return FAILURE;
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET, "tcp socket init done\n");

    return SUCCESS;
}

/*
 * Function     : icm_init_dgraminet_socket
 * Description  : initialize UDP socket interface
 * Input params : pointer to icm info structure
 * Return       : SUCCESS : 1
 *                FAILURE : -1
 *
 */
int icm_init_dgraminet_socket(ICM_DEV_INFO_T* pdev)
{
    int status = SUCCESS;
    ICM_INET_T  *pinet = ICM_GET_ADDR_OF_INETINFO(pdev);

    /* init socket interface */
    pinet->listener = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (pinet->listener < 0) {
        perror("icm : unable to open socket\n");
        status = FAILURE;
    }

    /* initialize..... */
    memset(&pinet->server_addr, 0, sizeof(pinet->server_addr));
    pinet->server_addr.sin_family   = AF_INET;
    pinet->server_addr.sin_port     = htons(ATHPORT);
    pinet->server_addr.sin_addr.s_addr = INADDR_ANY;

    pinet->type = SOCK_TYPE_UDP;
    pinet->client_fd = INVALID_FD;

    /* bind the listener socket */
    if (bind(pinet->listener, (struct sockaddr*)&pinet->server_addr, sizeof(pinet->server_addr)) < 0) {
        perror("icm : bind error\n");
        close(pinet->listener);
        status = FAILURE;
    }

    if (status) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET, "udp socket init done\n");
    } else {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET, "udp socket init fail\n");
    }

    return status;
}


/*
 * Function     : icm_init_nl80211_socket
 * Description  : initialize nl80211 socket interface
 * Input params : pointer to icm info structure
 * Return       : SUCCESS : 1
 *                FAILURE : -1
 *
 */
int icm_init_nl80211_socket(ICM_DEV_INFO_T* pdev)
{
    if (init_driver_netlink(pdev)) {
        perror("icm : err : unable to open nl80211 socket\n");
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_init_netlink_socket
 * Description  : initialize netlink socket interface
 * Input params : pointer to icm info structure
 * Return       : SUCCESS : 1
 *                FAILURE : -1
 *
 */
int icm_init_netlink_socket(ICM_DEV_INFO_T* pdev)
{

    int err = FAILURE;
    ICM_NLSOCK_T *pnlinfo = ICM_GET_ADDR_OF_NLSOCK_INFO(pdev);
    void *spectral_samp_msg = NULL;

    /* Avoid reinitialization */
    if (pnlinfo->sock_fd)
        return SUCCESS;

    pnlinfo->sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ATHEROS);

    if (pnlinfo->sock_fd < 0) {
        perror("icm : err : unable to open netlink_atheros socket\n");
        return err;
    }

    memset(&pnlinfo->src_addr, 0, sizeof(pnlinfo->src_addr));
    pnlinfo->src_addr.nl_family    = PF_NETLINK;
    pnlinfo->src_addr.nl_pid       = getpid();
    pnlinfo->src_addr.nl_groups    = 1;

    if ((err = bind(pnlinfo->sock_fd, (struct sockaddr*)&pnlinfo->src_addr, sizeof(pnlinfo->src_addr))) < 0) {
        perror("icm : err : unable to bind (netlink)");
        close(pnlinfo->sock_fd);
        return err;
    }

    /* init message related params */
    spectral_samp_msg = malloc(NLMSG_SPACE(sizeof(struct spectral_samp_msg)));
    if (spectral_samp_msg == NULL) {
        perror("icm : err : malloc failed\n");
        close(pnlinfo->sock_fd);
        return err;
    }

    pdev->nlh = (struct nlmsghdr*)spectral_samp_msg;
    pdev->nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct spectral_samp_msg));
    pdev->nlh->nlmsg_pid = getpid();
    pdev->nlh->nlmsg_flags = 0;

    pdev->iov.iov_base = (void*)pdev->nlh;
    pdev->iov.iov_len  = pdev->nlh->nlmsg_len;

    memset(&pnlinfo->dst_addr, 0, sizeof(pnlinfo->dst_addr));

    pnlinfo->dst_addr.nl_family = PF_NETLINK;
    pnlinfo->dst_addr.nl_pid    = 0;
    pnlinfo->dst_addr.nl_groups = 1;

    memset(&pdev->msg, 0, sizeof(pdev->msg));
    pdev->msg.msg_name = (void *)&pnlinfo->dst_addr;
    pdev->msg.msg_namelen = sizeof(pnlinfo->dst_addr);
    pdev->msg.msg_iov = &pdev->iov;
    pdev->msg.msg_iovlen = 1;

    return (err = SUCCESS);
}

#ifdef WLAN_SPECTRAL_ENABLE
/*
 * Function     : icm_init_spectral_nlsock_operation
 * Description  : Initialize Spectral operation on netlink socket. On some
 *                platforms and under some circumstances, our netlink message
 *                receive rate may not be able to keep up with the driver's send
 *                rate. This can result in receive buffer errors. To mitigate
 *                this, we try to increase the socket receive buffer size from
 *                its default. We maintain a reference count so that the socket
 *                receive buffer size is increased only for the first init
 *                request.
 * Input params : Pointer to ICM_DEV_INFO_T structure
 * Return       : SUCCESS/FAILURE
 */
int icm_init_spectral_nlsock_operation(ICM_DEV_INFO_T *pdev)
{
    ICM_NLSOCK_T *pnlinfo = NULL;
    int ret = FAILURE;
    unsigned long long limit_temp = 0;
    unsigned long long req_temp = 0;

    /* Note: SO_RCVBUF/SO_RCVBUFFORCE expect receive buffer sizes as integer
     * values. Hence the corresponding variables below are integers.
     */

    /* Receive buffer size to be requested */
    int rbuff_sz_req = 0;

    /* Upper limit on receive buffer size to be requested */
    int rbuff_sz_req_limit = 0;

    /* Current receive buffer size */
    int rbuff_sz_curr = 0;

    /* Length of current receive buffer size datatype */
    socklen_t rbuff_sz_curr_len = 0;

    /* Free physical memory */
    size_t free_mem = 0;

    ICM_ASSERT(pdev != NULL);

    if (pthread_mutex_lock(&pdev->spectral_nlsockop_ref_lock) != 0) {
        perror("pthread_mutex_lock\n");
        /* This would be unexpected and should be investigated separately
         * instead of giving the caller the option of deciding on handling.
         */
        ICM_ASSERT(0);
    }

    if (pdev->spectral_nlsockop_ref > 0)
        goto ignore;

    pnlinfo = ICM_GET_ADDR_OF_NLSOCK_INFO(pdev);
    ICM_ASSERT(pnlinfo != NULL);

    /* Get current receive buffer size */
    rbuff_sz_curr_len = sizeof(rbuff_sz_curr);
    if (getsockopt(pnlinfo->sock_fd, SOL_SOCKET, SO_RCVBUF,
                   (void *)&rbuff_sz_curr,
                   &rbuff_sz_curr_len) < 0) {
        perror("getsockopt\n");
        goto fail;
    }

    /* The value returned is double the actual size, for book-keeping reasons.
     * So divide by 2.
     */
    rbuff_sz_curr /= 2;

    pnlinfo->rbuff_sz_def = rbuff_sz_curr;
    if (0 == pnlinfo->rbuff_sz_def) {
        fprintf(stderr, "Default effective receive buffer size is unexpectedly zero\n");
        goto fail;
    }

    /* Calculate upper limit on receive buffer size we'd like to request */
    if (icm_get_free_mem(&free_mem) < 0) {
        fprintf(stderr, "Could not determine amount of free physical memory\n");
        goto fail;
    }

    ICM_ASSERT(ICM_MAX_FREEMEM_UTIL_PERCENT <= 100);

    limit_temp = ((unsigned long long)free_mem *
                        ICM_MAX_FREEMEM_UTIL_PERCENT)/100;

    /* Since the kernel will double the size for book-keeping reasons, keep the
     * limit at half of INT_MAX.
     */
    if (limit_temp > INT_MAX/2)
        limit_temp = INT_MAX/2;

    rbuff_sz_req_limit = limit_temp;

    /* Determine the receive buffer size to be requested */
    req_temp = NLMSG_SPACE(sizeof(struct spectral_samp_msg)) *
                                            ICM_SPECTRALSAMP_MAX_BUFF;

    if (req_temp > INT_MAX/2)
        req_temp = INT_MAX/2;

    rbuff_sz_req = req_temp;

    if (rbuff_sz_req > rbuff_sz_req_limit)
        rbuff_sz_req = rbuff_sz_req_limit;

    if (rbuff_sz_req > rbuff_sz_curr) {
        /* We first try SO_RCVBUFFORCE. This is available since Linux 2.6.14,
         * and if we have CAP_NET_ADMIN privileges.
         *
         * In case we are not entitled to use it, then an error will be returned
         * and we can fall back to SO_RCVBUF. If we use SO_RCVBUF, the kernel
         * will cap our requested value as per rmem_max. We will have to survive
         * with the possibility of a few netlink messages being lost under some
         * circumstances.
         */
        if (setsockopt(pnlinfo->sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                            (void *)&rbuff_sz_req, sizeof(rbuff_sz_req)) < 0) {
            if (setsockopt(pnlinfo->sock_fd, SOL_SOCKET, SO_RCVBUF,
                             (void *)&rbuff_sz_req, sizeof(rbuff_sz_req)) < 0) {
                perror("setsockopt\n");
                goto fail;
            }
        }
    }
    /* Else if rbuff_sz_req < rbuff_sz_curr, we go with the default configured
     * into the kernel. We will have to survive with the possibility of a few
     * netlink messages being lost under some circumstances in case rbuff_sz_req
     * has been capped to below what we would ideally have desired.
     */

ignore:
    pdev->spectral_nlsockop_ref++;

    ret = SUCCESS;

fail:
    if (pthread_mutex_unlock(&pdev->spectral_nlsockop_ref_lock) != 0) {
        perror("pthread_mutex_lock\n");
        /* This would be unexpected and should be investigated separately
         * instead of giving the caller the option of deciding on handling */
        ICM_ASSERT(0);
    }

    return ret;
}

/*
 * Function     : icm_deinit_spectral_nlsock_operation
 * Description  : De-initialize Spectral operation on netlink socket. Restore
 *                default socket receive buffer size for Spectral netlink
 *                socket. We maintain a reference count so that this restoration
 *                is done only for the last deinit request we would see.
 * Input params : Pointer to ICM_DEV_INFO_T structure
 * Return       : SUCCESS/FAILURE
 */
int icm_deinit_spectral_nlsock_operation(ICM_DEV_INFO_T *pdev)
{
    ICM_NLSOCK_T *pnlinfo = NULL;
    int ret = FAILURE;

    ICM_ASSERT(pdev != NULL);

    if (pthread_mutex_lock(&pdev->spectral_nlsockop_ref_lock) != 0) {
        perror("pthread_mutex_lock\n");
        /* This would be unexpected and should be investigated separately
         * instead of giving the caller the option of deciding on handling.
         */
        ICM_ASSERT(0);
    }

   /* If the reference count is not greater than 0, we have been called in an
    * improper sequence. Assert for investigation.
    */
    ICM_ASSERT(pdev->spectral_nlsockop_ref > 0);

    if (pdev->spectral_nlsockop_ref > 1)
        goto ignore;

    pnlinfo = ICM_GET_ADDR_OF_NLSOCK_INFO(pdev);
    ICM_ASSERT(pnlinfo != NULL);

    if (0 == pnlinfo->rbuff_sz_def) {
        goto fail;
    }

    /* We first try SO_RCVBUFFORCE so that we have a better chance of restoring
     * the default, even for corner cases if any. This is available since Linux
     * 2.6.14, and if we have CAP_NET_ADMIN privileges.
     *
     * In case we are not entitled to use it, then an error will be returned
     * and we can fall back to SO_RCVBUF.
     */
    if (setsockopt(pnlinfo->sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                        (void *)&pnlinfo->rbuff_sz_def,
                        sizeof(pnlinfo->rbuff_sz_def)) < 0) {
        if (setsockopt(pnlinfo->sock_fd, SOL_SOCKET, SO_RCVBUF,
                         (void *)&pnlinfo->rbuff_sz_def,
                         sizeof(pnlinfo->rbuff_sz_def)) < 0) {
            perror("setsockopt\n");
            goto fail;
        }
    }

ignore:
    ret = SUCCESS;

fail:
    /* We decrement the reference count inspite of failure, since the attempt to
     * restore default would happen for the last remaining reference and there
     * may or may not be further opportunities to retry. The consequence is that
     * we would be stuck with a potentially higher socket receive buffer size,
     * but this might be survivable (though not optimal) in many circumstances.
     */
    pdev->spectral_nlsockop_ref--;
    if (pthread_mutex_unlock(&pdev->spectral_nlsockop_ref_lock) != 0) {
        perror("pthread_mutex_lock\n");
        /* This would be unexpected and should be investigated separately
         * instead of giving the caller the option of deciding on handling */
        ICM_ASSERT(0);
    }

    return ret;
}
#endif /* WLAN_SPECTRAL_ENABLE */

/*
 * Function     : icm_init_ioctl_socket
 * Description  : initialize socket interface used for some of the ioctls
 * Input params : pointer to dev info structure
 * Return       : success/failure
 *
 */
int icm_init_ioctl_socket(ICM_DEV_INFO_T* pdev)
{
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);

    iocinfo->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (iocinfo->sock_fd < 0) {
        perror("icm : socket() for ioctls\n");
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_cleanup_socket
 * Description  : cleanup socket interface, free memory
 * Input params : pointer to icm info structure
 * Return       : success/failure
 *
 */
int icm_cleanup_socket(ICM_DEV_INFO_T* pdev)
{

    int err = SUCCESS;
    ICM_INET_T* pinet = ICM_GET_ADDR_OF_INETINFO(pdev);
    ICM_NLSOCK_T* pnlinfo = NULL;
    ICM_NLSOCK_T* prtnlinfo = NULL;
    ICM_CONFIG_T* conf = &pdev->conf;
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);

    pnlinfo = ICM_GET_ADDR_OF_NLSOCK_INFO(pdev);
    prtnlinfo = ICM_GET_ADDR_OF_RTNLSOCK_INFO(pdev);

    if (pnlinfo->sock_fd) {
        err = deinit_driver_netlink(pdev);
        pnlinfo->sock_fd = 0;
    }

    if (iocinfo->sock_fd) {
        err = close(iocinfo->sock_fd);
        iocinfo->sock_fd = 0;
    }

    if (prtnlinfo->sock_fd) {
        err = close(prtnlinfo->sock_fd);
        prtnlinfo->sock_fd = 0;
    }

    if (pdev->nlh != NULL) {
        free(pdev->nlh);
        pdev->nlh = NULL;
    }

    if (conf->server_mode == TRUE) {
        close(pinet->listener);
        close(pinet->client_fd);
    }

    return err;
}

/*
 * Function     : icm_accept_new_connection
 * Description  : accepts new client connection
 * Input params : pointer to icm info structure
 * Return       : SUCCESS or FAILURE
 *
 */
int icm_accept_new_connection(ICM_DEV_INFO_T* pdev)
{
    int status = SUCCESS;
    ICM_INET_T* pinet = ICM_GET_ADDR_OF_INETINFO(pdev);

    pinet->addrlen = sizeof(pinet->client_addr);

    if ((pinet->client_fd = accept(pinet->listener, (struct sockaddr*)&pinet->client_addr, &pinet->addrlen)) == -1) {
        perror("icm : unable to accept connection\n");
        status = FAILURE;
    }

    if (status) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,
                "new connection from %s on socket %d\n", inet_ntoa(pinet->client_addr.sin_addr), pinet->client_fd);
    }

    return status;
}

/*
 * Function     : icm_handle_client_data
 * Description  : receives data from socket
 * Input params : pointer to icm info structure
 * Return       : SUCCESS or FAILURE
 *
 */
int icm_handle_client_data(ICM_DEV_INFO_T* pdev, int fd)
{
    int recvd_bytes = 0;
    int err = 0;

    ICM_INET_T* pinet = ICM_GET_ADDR_OF_INETINFO(pdev);

    char buf[MAX_PAYLOAD] = {'\0'};

    if (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_UDP) {
        char host[NI_MAXHOST];
        char service[NI_MAXSERV];

        pinet->peer_addr_len = sizeof(pinet->peer_addr);
        recvd_bytes = recvfrom(fd, buf, sizeof(buf), 0,
                (struct sockaddr*)&pinet->peer_addr, &pinet->peer_addr_len);

        getnameinfo((struct sockaddr*)&pinet->peer_addr,
                pinet->peer_addr_len, host, NI_MAXHOST, service,
                NI_MAXSERV, NI_NUMERICSERV);

        if (recvd_bytes == -1) {
            return 0;
        }
    } else if (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_TCP) {
        if ((recvd_bytes = recv(fd, buf, sizeof(buf), 0)) <= 0) {
            perror("icm : recv error\n");
            err = -1;
        }
    }

    icm_parse_client_cmd(pdev, (void*)buf, recvd_bytes);

    return err;
}

/*
 * Function     : icm_init_event_mechanism
 * Description  : initialize ICM application internal event mechanism
 * Input params : pointer to dev info structure
 * Return       : SUCCESS or FAILURE
 */
int icm_init_event_mechanism(ICM_DEV_INFO_T* pdev)
{
    ICM_PIPE_T *pmnpipeinfo = ICM_GET_ADDR_OF_MNPIPE_INFO(pdev);
    ICM_PIPE_T *psrpipeinfo = ICM_GET_ADDR_OF_SRPIPE_INFO(pdev);

    pmnpipeinfo->pfds[0] = -1;
    pmnpipeinfo->pfds[1] = -1;
    psrpipeinfo->pfds[0] = -1;
    psrpipeinfo->pfds[1] = -1;

    return SUCCESS;
}

/*
 * Function     : icm_deinit_event_mechanism
 * Description  : de-initialize ICM application internal event mechanism
 * Input params : pointer to dev info structure
 */
void icm_deinit_event_mechanism(ICM_DEV_INFO_T* pdev)
{
    ICM_PIPE_T *pmnpipeinfo = ICM_GET_ADDR_OF_MNPIPE_INFO(pdev);
    ICM_PIPE_T *psrpipeinfo = ICM_GET_ADDR_OF_SRPIPE_INFO(pdev);

    if (pmnpipeinfo->pfds[0] != -1) {
        close(pmnpipeinfo->pfds[0]);
        pmnpipeinfo->pfds[0] = -1;
    }

    if (pmnpipeinfo->pfds[1] != -1) {
        close(pmnpipeinfo->pfds[1]);
        pmnpipeinfo->pfds[1] = -1;
    }

    if (psrpipeinfo->pfds[0] != -1) {
        close(psrpipeinfo->pfds[0]);
        psrpipeinfo->pfds[0] = -1;
    }

    if (psrpipeinfo->pfds[1] != -1) {
        close(psrpipeinfo->pfds[1]);
        psrpipeinfo->pfds[1] = -1;
    }
}

/*
 * Function     : icm_register_event_recipient
 * Description  : register an ICM application internal event recipient
 * Input params : pointer to dev info structure, recipient ID
 * Return       : -1 on error, file descriptor to listen on, on success.
 */
int icm_register_event_recipient(ICM_DEV_INFO_T* pdev,
        ICM_EVENT_RECIPIENT_T recipient)
{
    ICM_PIPE_T *ppipeinfo = NULL;
    int flags;
    int ret;

    if (pdev == NULL ||
            recipient >= ICM_EVENT_RECIPIENT_INVALID) {
        return -1;
    }

    switch(recipient)
    {
        case ICM_EVENT_RECIPIENT_MAIN:
            ppipeinfo = ICM_GET_ADDR_OF_MNPIPE_INFO(pdev);
            break;

        case ICM_EVENT_RECIPIENT_SPECTRAL_LOOP:
            ppipeinfo = ICM_GET_ADDR_OF_SRPIPE_INFO(pdev);
            break;

        default:
            return -1;
            break;
    }

    if (pipe(ppipeinfo->pfds) == -1) {
        perror("icm : pipe");
        ppipeinfo->pfds[0] = -1;
        ppipeinfo->pfds[1] = -1;
        return -1;
    }

    flags = fcntl(ppipeinfo->pfds[0], F_GETFL, 0);
    if (flags == -1) {
        perror("icm : fcntl");
        close(ppipeinfo->pfds[0]);
        ppipeinfo->pfds[0] = -1;
        close(ppipeinfo->pfds[1]);
        ppipeinfo->pfds[1] = -1;
        return -1;
    }

    ret = fcntl(ppipeinfo->pfds[0], F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        perror("icm : fcntl");
        close(ppipeinfo->pfds[0]);
        ppipeinfo->pfds[0] = -1;
        close(ppipeinfo->pfds[1]);
        ppipeinfo->pfds[1] = -1;
        return -1;
    }

    return ppipeinfo->pfds[0];
}

/*
 * Function     : icm_deregister_event_recipient
 * Description  : de-register an ICM application internal event recipient
 * Input params : pointer to dev info structure, recipient
 * Return       : SUCCESS/FAILURE
 */
int icm_deregister_event_recipient(ICM_DEV_INFO_T* pdev,
        ICM_EVENT_RECIPIENT_T recipient)
{
    ICM_PIPE_T *ppipeinfo = NULL;

    if (pdev == NULL ||
            recipient >= ICM_EVENT_RECIPIENT_INVALID) {
        return FAILURE;
    }

    switch(recipient)
    {
        case ICM_EVENT_RECIPIENT_MAIN:
            ppipeinfo = ICM_GET_ADDR_OF_MNPIPE_INFO(pdev);
            break;

        case ICM_EVENT_RECIPIENT_SPECTRAL_LOOP:
            ppipeinfo = ICM_GET_ADDR_OF_SRPIPE_INFO(pdev);
            break;

        default:
            return FAILURE;
            break;
    }

    close(ppipeinfo->pfds[0]);
    ppipeinfo->pfds[0] = -1;
    close(ppipeinfo->pfds[1]);
    ppipeinfo->pfds[1] = -1;

    return SUCCESS;
}

/*
 * Function     : icm_send_event
 * Description  : send an ICM application internal event
 * Input params : pointer to dev info structure, recipient ID, and event ID
 * Return       : SUCCESS or FAILURE
 *
 */
int icm_send_event(ICM_DEV_INFO_T* pdev,
        ICM_EVENT_RECIPIENT_T recipient,
        ICM_EVENT_T event)
{
    ICM_PIPE_T *ppipeinfo = NULL;

    if (pdev == NULL ||
            recipient >= ICM_EVENT_RECIPIENT_INVALID ||
            event >= ICM_EVENT_INVALID) {
        return FAILURE;
    }

    switch(recipient)
    {
        case ICM_EVENT_RECIPIENT_MAIN:
            ppipeinfo = ICM_GET_ADDR_OF_MNPIPE_INFO(pdev);
            break;

        case ICM_EVENT_RECIPIENT_SPECTRAL_LOOP:
            ppipeinfo = ICM_GET_ADDR_OF_SRPIPE_INFO(pdev);
            break;

        default:
            return FAILURE;
            break;
    }

    if (ppipeinfo->pfds[1] == -1) {
        /* No registered recipient. Not an issue, silently exit */
        /* XXX - Can later add return code to denote this, if at all required */
        return SUCCESS;
    }

    if (write(ppipeinfo->pfds[1], (void*)&event, sizeof(event)) < 0) {
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : icm_get_event
 * Description  : get an ICM application internal event.
 * Input params : pointer to dev info structure,
 *                recipient ID
 * Output params: pointer to event
 * Return       : SUCCESS or FAILURE
 *
 */
int icm_get_event(ICM_DEV_INFO_T* pdev,
        ICM_EVENT_RECIPIENT_T recipient,
        ICM_EVENT_T *pevent)
{
    ICM_PIPE_T *ppipeinfo = NULL;
    int piperet = 0;

    if (pdev == NULL ||
            recipient >= ICM_EVENT_RECIPIENT_INVALID) {
        return FAILURE;
    }

    switch(recipient)
    {
        case ICM_EVENT_RECIPIENT_MAIN:
            ppipeinfo = ICM_GET_ADDR_OF_MNPIPE_INFO(pdev);
            break;

        case ICM_EVENT_RECIPIENT_SPECTRAL_LOOP:
            ppipeinfo = ICM_GET_ADDR_OF_SRPIPE_INFO(pdev);
            break;

        default:
            return FAILURE;
            break;
    }

    piperet = read(ppipeinfo->pfds[0], pevent, sizeof(ICM_EVENT_T));

    if (piperet < 0) {
        if (piperet == EAGAIN) {
            err("No event was available");
        }
        return FAILURE;
    }

    return SUCCESS;
}
/*
 * Function     : icm_init_rtnetlink_socket
 * Description  : initialize rtnetlink socket interface
 * Input params : pointer to icm info structure
 * Return       : SUCCESS or FAILURE
 *
 */
int icm_init_rtnetlink_socket(ICM_DEV_INFO_T* pdev)
{

    int err = FAILURE;
    ICM_NLSOCK_T *prtnlinfo = ICM_GET_ADDR_OF_RTNLSOCK_INFO(pdev);

    prtnlinfo->sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (prtnlinfo->sock_fd < 0) {
        perror("icm : err : unable to open netlink_route socket\n");
        return err;
    }

    /* Init source netlink address */
    memset(&prtnlinfo->src_addr, 0, sizeof(prtnlinfo->src_addr));
    prtnlinfo->src_addr.nl_family    = AF_NETLINK;
    prtnlinfo->src_addr.nl_groups    = RTMGRP_LINK;

    if ((err = bind(prtnlinfo->sock_fd, (struct sockaddr*)&prtnlinfo->src_addr,
                    sizeof(prtnlinfo->src_addr))) < 0) {
        perror("icm : err : unable to bind (rtnetlink)");
        close(prtnlinfo->sock_fd);
        return err;
    }
    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,"Created rtnetlink socket\n");
    return SUCCESS;
}

/*
 * Function     : icm_parse_netlink_msg
 * Description  : parse the received netlink msg to know
 *                the interface state changes.
 * Input params : pointer pointing to the ICM_DEV_INFO_T structure
 * Return       : SUCCESS or FAILURE
 *
 */
int icm_parse_rtnetlink_msg(ICM_DEV_INFO_T* pdev) {
    int len;
    char buf[RTNETLINKBUFSIZ] = {0};
    struct iovec iov = {buf, sizeof(buf)};
    struct sockaddr_nl sa;
    struct nlmsghdr *nh;
#ifdef AARCH64_WITH_MUSL
 #if __BYTE_ORDER == __BIG_ENDIAN
    struct msghdr msg = {(void *)&sa, sizeof(sa), &iov, 0, 1, NULL, 0, 0, 0};
 #else
    struct msghdr msg = {(void *)&sa, sizeof(sa), &iov, 1, 0, NULL, 0, 0, 0};
 #endif
#else
    struct msghdr msg = {(void *)&sa, sizeof(sa), &iov, 1, NULL, 0, 0};
#endif
    struct ifinfomsg *ifinfo;
    char ifname[IFNAMSIZ] = {0};
    ICM_NLSOCK_T *prtnlinfo = ICM_GET_ADDR_OF_RTNLSOCK_INFO(pdev);
    int sd = prtnlinfo->sock_fd;
#ifndef ICM_RTR_DRIVER
    int i;
    ICM_INFO_T *picm = NULL;
#endif /* ICM_RTR_DRIVER */
    len = recvmsg(sd, &msg, 0);

    /* Parsing the Netlink message */
    for(nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {

        if(nh->nlmsg_type == NLMSG_DONE) {
            break;
        }

        if(nh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }

        ifinfo = NLMSG_DATA(nh);
        if_indextoname(ifinfo->ifi_index, ifname);

#ifndef ICM_RTR_DRIVER
        for (i = 0; i < pdev->conf.num_radios; i++) {
            picm = get_picm(i);
            if (picm != NULL && !strcmp(picm->dev_ifname, ifname)
                             && picm->drv.ifindex != ifinfo->ifi_index) {
                icm_printf("IfIndex changed from %d to %d. Re-register nl event handle.", picm->drv.ifindex, ifinfo->ifi_index);
                if(nl80211_handle_ifindx_change(picm, pdev->nl80211) < 0)
                    return -1;
                picm->drv.ifindex = ifinfo->ifi_index;
            }
        }
#endif /* ICM_RTR_DRIVER */
        if((ifinfo->ifi_flags & IFF_RUNNING) && (ifinfo->ifi_flags & IFF_UP)) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,
                    "VAP %s ifindex %d is Created. Status: UP Running\n",
                    ifname, ifinfo->ifi_index);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,"Updating Device information\n");
        } else if((ifinfo->ifi_flags & IFF_UP) || (ifinfo->ifi_flags & IFF_RUNNING)) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,
                    "VAP %s ifindex %d is Created. Status: Down Not Running\n",
                    ifname, ifinfo->ifi_index);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,"Updating Device information\n");
        } else {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,
                    "VAP %s ifindex %d is Destroyed.\n",
                    ifname, ifinfo->ifi_index);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_SOCKET,"Updating Device information\n");
        }
#ifdef ICM_RTR_DRIVER
        icm_configure_radio_iface(pdev);
#endif /* ICM_RTR_DRIVER */
    }

    return SUCCESS;
}
