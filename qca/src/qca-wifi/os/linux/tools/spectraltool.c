/*
 * Copyright (c) 2013,2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2009, Atheros Communications Inc.
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
 *
 * Driver interaction with Linux nl80211/cfg80211
 * Copyright (c) 2002-2015, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#include <wlan_spectral_public_structs.h>
#include <cfg80211_external.h>
#include "if_athioctl.h"
#include <ol_ath_ucfg.h>
#include <qca_vendor.h>
#include <sys/stat.h>
#include <pthread.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/object-api.h>
#include <linux/pkt_sched.h>
#include <netlink/netlink.h>
#include <cfg80211_nl_adapt.h>
#include <assert.h>
#include <dirent.h>
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif
#include <ieee80211_external.h>
#include <ctype.h>

/* libnl 2.0 compatibility code */
#define nl_handle nl_sock
#define nl80211_handle_alloc nl_socket_alloc_cb
#define nl80211_handle_destroy nl_socket_free

#define HAL_PHYERR_PARAM_NOVAL  65535

struct nlIfaceInfo {
	struct nl_sock *cmd_sock;
	int sock_fd;
	struct nl_cb *nl_cb;
	pthread_mutex_t cb_lock;
	int nl80211_family_id;
	uint8_t clean_up;
};

/**
 * struct spectral_param - Spectral control path data structure which
 * contains parameter and its value
 * @id: Parameter ID
 * @value: Single parameter value
 * @value1: First value in a pair
 * @value2: Second value in a pair
 */
struct spectral_param {
    uint32_t id;
    union {
        u_int32_t value;
        struct {
            u_int32_t value1;
            u_int32_t value2;
        };
    };
};

#ifndef _BYTE_ORDER
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _BYTE_ORDER _LITTLE_ENDIAN
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define _BYTE_ORDER _BIG_ENDIAN
#endif
#endif  /* _BYTE_ORDER */
#include "ieee80211_external.h"

#define _LINUX_TYPES_H
/*
 * Provide dummy defs for kernel types whose definitions are only
 * provided when compiling with __KERNEL__ defined.
 * This is required because ah_internal.h indirectly includes
 * kernel header files, which reference these data types.
 */
#define __be64 u_int64_t
#define __le64 u_int64_t
#define __be32 u_int32_t
#define __le32 u_int32_t
#define __be16 u_int16_t
#define __le16 u_int16_t
#define __be8  u_int8_t
#define __le8  u_int8_t
#define loff_t off_t
typedef struct {
        volatile int counter;
} atomic_t;

#define SPECTRAL_LOG_VERSION_ID1 314157  /* Increment for new revision */
#define SPECTRAL_LOG_VERSION_ID2 314158  /* Increment for new revision */
#define SPECTRAL_LOG_VERSION_ID3 314159  /* Increment for new revision */

/* Enable compilation of code referencing SO_RCVBUFFORCE even on systems where
 * this isn't available. We should be able to determine availability at runtime.
 */
#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE                      (33)
#endif

/*
 * Maximum portion of free physical memory we allow ourselves to request for
 * while setting socket receive buffer size. This does not include cached
 * memory.
 * This is a float on a scale of 0-1.
 *
 * Note that the kernel doubles the value we request for, to account for
 * bookkeeping overhead. Be mindful of this when changing the below.
 */
#define QCA_SPECTOOL_MAX_FREEMEM_UTIL       (.30f)

/* Netlink timeout specification (second and microsecond components) */
#define QCA_SPECTOOL_NL_TIMEOUT_SEC         (2)
#define QCA_SPECTOOL_NL_TIMEOUT_USEC        (0)

/*White space macro*/
#define space ' '

/* Number for spectral params printed in the outfile */
#define NUM_SPECTRAL_PARAMS_ADVANCED (20)
#define NUM_SPECTRAL_PARAMS_NON_ADVANCED (5)

#include "spectral_ioctl.h"
#include "nl80211_copy.h"
#ifndef ATH_DEFAULT
#define	ATH_DEFAULT	"wifi0"
#endif
#define PATH_SYSNET_DEV "/sys/class/net/"
#define WIFI_STR "wifi"

#if UMAC_SUPPORT_CFG80211
#define NL80211_ATTR_MAX_INTERNAL    (256)
struct nlIfaceInfo *info;
enum qca_wlan_genric_data {
	QCA_WLAN_VENDOR_ATTR_PARAM_INVALID = 0,
	QCA_WLAN_VENDOR_ATTR_PARAM_DATA,
	QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH,
	QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS,

	/* keep last */
	QCA_WLAN_VENDOR_ATTR_PARAM_LAST,
	QCA_WLAN_VENDOR_ATTR_PARAM_MAX =
		QCA_WLAN_VENDOR_ATTR_PARAM_LAST - 1,
};
#endif /* UMAC_SUPPORT_CFG80211 */

struct spectralhandler {
    int    s;
    struct ath_diag atd;
#if UMAC_SUPPORT_CFG80211
    config_mode_type  cfg_flag;                    /* cfg flag */
#endif /* UMAC_SUPPORT_CFG80211 */
    struct spectral_caps caps;
    /* fraction of free memory to be used for sample capture */
    float mem_utilization_factor;
    /* MAC address of the interface */
    uint8_t macaddr[QDF_MAC_ADDR_SIZE];
    enum spectral_scan_mode sscan_mode;
};

static int spectralStartScan(struct spectralhandler *spectral);
static int spectralStopScan(struct spectralhandler *spectral);
void spectralset(struct spectralhandler *spectral, struct spectral_param *param);
static void spectralAtdClean(struct spectralhandler *spectral);
static int spectralIsAdvncdSpectral(struct spectralhandler *spectral);

#define MAX_PAYLOAD 1024  /* maximum payload size*/
#ifndef NETLINK_ATHEROS
#define NETLINK_ATHEROS 17
#endif
#define MAX_RAW_SPECT_DATA_SZ (600)
#define SCAN_COUNT_OFFSET     (95)
#define SAMPRECVBUF_SZ        (2048)

/* Default value for whether to enable generation 3 linear scaling */
#define SPECTRALTOOL_GEN3_ENABLE_LINEAR_SCALING_DEFAULT (false)

/* Fraction of free memory to be used for dumping samples */
#define DEFAULT_MEM_UTILIZATION_FACTOR (0.5)
/* Guard bytes to avoid buffer overflow */
#define GUARD_NUM_BYTES  (2500)
#define MAX_CAPTURE_SIZE_WITHOUT_FREE_MEM_CHECK  (50000)

#if UMAC_SUPPORT_CFG80211
#define IS_CFG80211_ENABLED(p)       (((p)->cfg_flag == CONFIG_CFG80211)?1:0)
#define SPECTRAL_NL_BUFF_SIZE (256*1024)

static int wext_to_cfg_param[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX];

void init_wext_to_cfg_param()
{
	#define convert(param) \
		wext_to_cfg_param[SPECTRAL_PARAM_##param] = QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_##param;

	convert(FFT_PERIOD);
	convert(SCAN_PERIOD);
	convert(SCAN_COUNT);
	convert(SHORT_REPORT);
	convert(FFT_SIZE);
	convert(GC_ENA);
	convert(RESTART_ENA);
	convert(NOISE_FLOOR_REF);
	convert(INIT_DELAY);
	convert(NB_TONE_THR);
	convert(STR_BIN_THR);
	convert(WB_RPT_MODE);
	convert(RSSI_RPT_MODE);
	convert(RSSI_THR);
	convert(PWR_FORMAT);
	convert(RPT_MODE);
	convert(BIN_SCALE);
	convert(DBM_ADJ);
	convert(CHN_MASK);
	wext_to_cfg_param[SPECTRAL_PARAM_SPECT_PRI] = QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY;
	convert(FREQUENCY);
}

static int
convert_to_cfg80211_spectral_mode(enum spectral_scan_mode mode,
                                  enum qca_wlan_vendor_spectral_scan_mode *nl_mode)
{
    switch (mode) {
    case SPECTRAL_SCAN_MODE_NORMAL:
        *nl_mode = QCA_WLAN_VENDOR_SPECTRAL_SCAN_MODE_NORMAL;
        break;

    case SPECTRAL_SCAN_MODE_AGILE:
        *nl_mode = QCA_WLAN_VENDOR_SPECTRAL_SCAN_MODE_AGILE;
        break;

    default:
        fprintf(stderr, "Invalid Spectral mode %u\n", mode);
        return -EINVAL;
    }

    return 0;
}

struct nl_msg *nl_prepare_command(int cmdid, const char *ifName)
{
	struct nl_msg *msg;
	msg = nlmsg_alloc();
	if (!msg) {
		printf("alloc nl msg failed\n");
		return NULL;
	}
	genlmsg_put(msg, 0, 0, info->nl80211_family_id, 0, 0,
					NL80211_CMD_VENDOR, 0);
	uint32_t ifidx = if_nametoindex(ifName);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifidx);
	nla_put_u32(msg, NL80211_ATTR_VENDOR_ID,QCA_NL80211_VENDOR_ID);
	nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, cmdid);
        return msg;
}

int nl_ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = (int *)arg;
	*err = 0;
	return NL_STOP;
}


int nl_finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;
	*ret = 0;
	return NL_SKIP;
}


int nl_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = (int *)arg;
	*ret = err->error;

	printf("nl_error_handler received : %d\n", err->error);
	return NL_SKIP;
}

static void nl80211_nlmsg_clear(struct nl_msg *msg)
{
	/*
	 * Clear nlmsg data, e.g., to make sure key material is not left in
	 * heap memory for unnecessarily long time.
	 */
	if (msg) {
		struct nlmsghdr *hdr = nlmsg_hdr(msg);
		void *data = nlmsg_data(hdr);
		/*
		 * This would use nlmsg_datalen() or the older nlmsg_len() if
		 * only libnl were to maintain a stable API.. Neither will work
		 * with all released versions, so just calculate the length
		 * here.
		 */
		int len = hdr->nlmsg_len - NLMSG_HDRLEN;

		memset(data, 0, len);
	}
}

static int32_t create_nl_socket(void)
{
	int32_t ret;
	int32_t sock_fd;
	struct sockaddr_nl src_addr;

	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	if (sock_fd < 0) {
		fprintf(stderr, "Socket creation failed sock_fd 0x%x\n",
			sock_fd);
		return -EINVAL;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_groups = 0x0;
	src_addr.nl_pid = getpid(); /* self pid */

	ret = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
	if (ret < 0) {
		close(sock_fd);
		return ret;
	}
	return sock_fd;
}

struct nlIfaceInfo *initialize(void)
{
	struct nl_sock *cmd_sock = NULL;
	uint32_t pid = getpid() & 0x3FFFFF;

	struct nlIfaceInfo *tmp_info = (struct nlIfaceInfo *)malloc( sizeof(
							struct nlIfaceInfo));
	if (tmp_info == NULL) {
		printf("Could not allocate nlIfaceInfo\n");
		return NULL;
	}
	tmp_info->sock_fd = -1;

	tmp_info->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (tmp_info->nl_cb == NULL) {
		printf("Failed to allocate netlink callbacks");
		goto cleanup;
	}
	cmd_sock = nl_socket_alloc_cb(tmp_info->nl_cb);
	if (!cmd_sock)
		goto cleanup;

	nl_socket_set_local_port(cmd_sock, pid);
	if (genl_connect(cmd_sock)) {
		printf("Failed to connect to generic netlink cmd_sock");
		goto cleanup;
	}

	tmp_info->sock_fd = create_nl_socket();
	if (tmp_info->sock_fd < 0)
		goto cleanup;

	/* Set the socket buffer size */
	if (nl_socket_set_buffer_size(cmd_sock, SPECTRAL_NL_BUFF_SIZE, 0) < 0)
		printf("Could not set nl_socket RX buffer size for cmd_sock: %s\n",
				strerror(errno));
	/* continue anyway with the default (smaller) buffer */

	tmp_info->cmd_sock = cmd_sock;

	tmp_info->nl80211_family_id = genl_ctrl_resolve(cmd_sock, "nl80211");
	if (tmp_info->nl80211_family_id < 0) {
		printf("Could not resolve nl80211 familty id\n");
		goto cleanup;
	}

	pthread_mutex_init(&tmp_info->cb_lock, NULL);

	return tmp_info;
cleanup:
	if (cmd_sock)
		nl_socket_free(cmd_sock);

	if (tmp_info) {
		if (tmp_info->sock_fd >= 0)
			close(tmp_info->sock_fd);

		if (tmp_info->nl_cb)
			nl_cb_put(tmp_info->nl_cb);

		free(tmp_info);
	}

	return NULL;
}

static int send_and_recv(struct nlIfaceInfo *info,
			 struct nl_handle *nl_handle, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;

	if (!msg)
		return -ENOMEM;

	cb = nl_cb_clone(info->nl_cb);
	if (!cb)
		goto out;

	err = nl_send_auto_complete(nl_handle, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, nl_error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl_ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0) {
		int res = nl_recvmsgs(nl_handle, cb);

		if (res < 0) {
			printf("nl80211: %s->nl_recvmsgs failed: %d",
				   __func__, res);
		}
	}
 out:
	nl_cb_put(cb);
	if (!valid_handler && valid_data == (void *) -1)
		nl80211_nlmsg_clear(msg);
	nlmsg_free(msg);
	return err;
}

#endif /* UMAC_SUPPORT_CFG80211 */

static int send_ioctl_command (struct spectralhandler *spectral, const char *ifname, void *buf, size_t buflen, int ioctl_sock_fd);

/**
 * send_ioctl_command; function to send the ioctl command.
 * @spectral  : pointer to spectralhandler
 * @ifname    : interface name
 * @buf       : buffer
 * @buflen    : buffer length
 * return     : 0 for sucess, -1 for failure
 */
int send_ioctl_command (struct spectralhandler *spectral, const char *ifname, void *buf, size_t buflen, int ioctl_sock_fd)
{
    struct ifreq ifr;
    int ioctl_cmd = SIOCGATHPHYERR;

    if (ifname) {
        memset(ifr.ifr_name, '\0', IFNAMSIZ);
        if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name)) {
            fprintf(stderr, "Interface name too long %s\n", ifname);
            return -1;
	}
    } else {
        fprintf(stderr, "no such file or device\n");
        return -1;
    }
    ifr.ifr_data = buf;
    if (ioctl(ioctl_sock_fd, ioctl_cmd, &ifr) < 0) {
        perror("ioctl failed");
        return -1;
    }

    return 0;
}

#if UMAC_SUPPORT_CFG80211
void print_spectral_error_code(enum qca_wlan_vendor_spectral_scan_error_code err) {
	switch(err) {
	case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_PARAM_UNSUPPORTED:
		fprintf(stderr, "Parameter unsupported\n");
		break;

	case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_MODE_UNSUPPORTED:
		fprintf(stderr, "Spectral scan mode unsupported\n");
		break;

	case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_PARAM_INVALID_VALUE:
		fprintf(stderr, "Invalid parameter value\n");
		break;

	case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_PARAM_NOT_INITIALIZED:
		fprintf(stderr, "A parameter is not initialized\n");
		break;

	default:
		fprintf(stderr, "Invalid error code %u\n", err);
		break;
	}

	return;
}

static int spectral_get_rchwidth_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    int32_t *rchwidth = arg;

    if (!msg) {
        fprintf(stderr, "nl message is null\n");
        return NL_SKIP;
    }

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    if (!rchwidth) {
        fprintf(stderr, "reference to radio channel width is null\n");
        return NL_SKIP;
    }

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_VENDOR_DATA]) {
        struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
        struct nlattr *tb_vendor[NL80211_ATTR_MAX_INTERNAL + 1];

        nla_parse(tb_vendor, NL80211_ATTR_MAX_INTERNAL,
              nla_data(nl_vendor), nla_len(nl_vendor), NULL);

        if (tb_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]) {
            void *temp;
            /* memcpy tb_vendor to data */
            temp = nla_data(tb_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]);
            *rchwidth = *((int32_t *)temp);
        }
    } else
        perror("vendor data attribute is not present in nl_msg");

    return NL_SKIP;
}
#endif /* UMAC_SUPPORT_CFG80211 */

int spectral_get_rchwidth(struct spectralhandler *spectral,
              int *rchwidth)
{
    if (!spectral) {
        fprintf(stderr, "spectral handler is null\n");
        return -EINVAL;
    }

    if (!rchwidth) {
        fprintf(stderr, "reference to radio channel width is null\n");
        return -EINVAL;
    }

#if UMAC_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(spectral)) {
        struct nl_msg *msg =
            nl_prepare_command(
                QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                spectral->atd.ad_name);
        if (!msg) {
            perror("nl_prepare_command failed\n");
            return -ENOMEM;
        }

        struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

        if (!data) {
            fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
            nlmsg_free(msg);
            return -ENOBUFS;
        }

        nla_put_u32(msg,
                QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND,
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS);

        nla_put_u32(msg,
                QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE,
                OL_ATH_PARAM_RCHWIDTH | OL_ATH_PARAM_SHIFT);

        nla_nest_end(msg, data);

        return send_and_recv(info, info->cmd_sock, msg, spectral_get_rchwidth_handler, rchwidth);
    } else
#endif
    {
        fprintf(stderr, "get radio channel width is not supported in ioctl mode\n");
        return -1;
    }
}

#if UMAC_SUPPORT_CFG80211
static int spectralGetThresholds_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX + 1];

		nla_parse(tb_vendor,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX,
		nla_data(nl_vendor), nla_len(nl_vendor), NULL);

		struct spectral_config *sp = (struct spectral_config *)arg;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_COUNT])
			sp->ss_count = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_COUNT]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_PERIOD])
			sp->ss_period = nla_get_u32(tb_vendor
			[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_PERIOD]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY])
			sp->ss_spectral_pri = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_SIZE])
			sp->ss_fft_size = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_SIZE]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_GC_ENA])
			sp->ss_gc_ena = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_GC_ENA]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RESTART_ENA])
			sp->ss_restart_ena = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RESTART_ENA]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NOISE_FLOOR_REF])
			sp->ss_noise_floor_ref = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NOISE_FLOOR_REF]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INIT_DELAY])
			sp->ss_init_delay = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INIT_DELAY]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NB_TONE_THR])
			sp->ss_nb_tone_thr = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NB_TONE_THR]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_STR_BIN_THR])
			sp->ss_str_bin_thr = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_STR_BIN_THR]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_WB_RPT_MODE])
			sp->ss_wb_rpt_mode = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_WB_RPT_MODE]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_RPT_MODE])
			sp->ss_rssi_rpt_mode = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_RPT_MODE]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_THR])
			sp->ss_rssi_thr = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_THR]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PWR_FORMAT])
			sp->ss_pwr_format = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PWR_FORMAT]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RPT_MODE])
			sp->ss_rpt_mode = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RPT_MODE]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_BIN_SCALE])
			sp->ss_bin_scale = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_BIN_SCALE]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DBM_ADJ])
			sp->ss_dbm_adj = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DBM_ADJ]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_CHN_MASK])
			sp->ss_chn_mask = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_CHN_MASK]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_PERIOD])
			sp->ss_fft_period = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_PERIOD]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SHORT_REPORT])
			sp->ss_short_report = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SHORT_REPORT]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY])
			sp->ss_frequency.cfreq1 = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY_2])
			sp->ss_frequency.cfreq2 = nla_get_u32(tb_vendor
			   [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY_2]);
	} else
		perror("vendor data attribute is not present in nl_msg");
	return NL_SKIP;
}

static int spectralSetThresholds_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh;

	if (!msg)
		return NL_SKIP;

	gnlh = nlmsg_data(nlmsg_hdr(msg));
	if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		      genlmsg_attrlen(gnlh, 0), NULL))
		return NL_SKIP;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX + 1];

		if (nla_parse(tb_vendor,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX,
			      nla_data(nl_vendor), nla_len(nl_vendor), NULL))
			return NL_SKIP;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]) {
			enum qca_wlan_vendor_spectral_scan_error_code err;

			err = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]);
			print_spectral_error_code(err);
		}
	} else
		perror("vendor data attribute is not present in nl_msg");

	return NL_SKIP;
}

static int spectral_stop_scan_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh;

	if (!msg)
		return NL_SKIP;

	gnlh = nlmsg_data(nlmsg_hdr(msg));
	if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		      genlmsg_attrlen(gnlh, 0), NULL))
		return NL_SKIP;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX + 1];

		if (nla_parse(tb_vendor,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX,
			      nla_data(nl_vendor), nla_len(nl_vendor), NULL))
			return NL_SKIP;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]) {
			enum qca_wlan_vendor_spectral_scan_error_code err;

			err = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]);
			print_spectral_error_code(err);
		}
	} else
		perror("vendor data attribute is not present in nl_msg");

	return NL_SKIP;
}

static int spectral_start_scan_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh;

	if (!msg)
		return NL_SKIP;

	gnlh = nlmsg_data(nlmsg_hdr(msg));
	if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		      genlmsg_attrlen(gnlh, 0), NULL))
		return NL_SKIP;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX + 1];

		if (nla_parse(tb_vendor,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX,
			      nla_data(nl_vendor), nla_len(nl_vendor), NULL))
			return NL_SKIP;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]) {
			enum qca_wlan_vendor_spectral_scan_error_code err;

			err = nla_get_u32(tb_vendor
				[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]);
			print_spectral_error_code(err);
		}
	} else
		perror("vendor data attribute is not present in nl_msg");

	return NL_SKIP;
}
#endif /* UMAC_SUPPORT_CFG80211 */

static int
spectralGetThresholds(struct spectralhandler *spectral, struct spectral_config *sp)
{
#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		enum qca_wlan_vendor_spectral_scan_mode nl_mode;
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CONFIG,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return -ENOMEM;
		}

		struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

		if (!data) {
			fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return -ENOBUFS;
		}

		if (convert_to_cfg80211_spectral_mode(spectral->sscan_mode, &nl_mode)) {
			nlmsg_free(msg);
			return -EINVAL;
		}
		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
			nl_mode);
		nla_nest_end(msg, data);
		return send_and_recv(info, info->cmd_sock, msg, spectralGetThresholds_handler, sp);
	} else {
#else
    {
#endif
    		spectral->atd.ad_id = SPECTRAL_GET_CONFIG | ATH_DIAG_DYN;
    		spectral->atd.ad_out_data = (void *) sp;
    		spectral->atd.ad_out_size = sizeof(struct spectral_config);
    		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
    		                       spectral->s) < 0) {
    		    err(1, "%s", spectral->atd.ad_name);
		    return -EINVAL;
    		}

		return 0;
	}
}

/*
 * Function    : get_free_mem_kB
 * Description : Get amount of free physical memory, in kB. We do not consider
 *               cached memory since caching behaviour cannot be modelled by the
 *               application and besides, we would like to avoid any actions
 *               that result in cache flushes.
 * Input       : None
 * Output      : On error: -1, on success: amount of free physical memory in kB
 */
static int get_free_mem_kB()
{
    FILE* fp = NULL;
    char line[256];
    int free_mem = -1;

    fp = fopen("/proc/meminfo", "r");

    if (NULL == fp)
    {
        perror("fopen");
        return -1;
    }

    while (fgets(line, sizeof(line), fp))
    {
        if (sscanf(line, "MemFree: %d kB", &free_mem) == 1)
        {
            break;
        }
    }

    fclose(fp);

    return free_mem;
}

/*
 * Function    : spectralGetNSamples
 * Description : Capture N spectral samples from the hardware FFT engine
 * Input       : Pointer to spectral structure, bit that indicates if start and
 *               stop scan is required, number of raw data to capture given as
 *               input by the user, delimiter to be used between values, whether
 *               to enable gen3 linear scaling
 * Output      : File that contains the spectral samples captured
 */
static int spectralGetNSamples(struct spectralhandler *spectral,
        int need_start_stop, u_int32_t num_raw_data_to_cap, char delimiter,
        bool enable_gen3_linear_scaling)
{
    int ret = 0;
    struct sockaddr_nl src_addr;
    socklen_t fromlen;
    struct nlmsghdr *nlh = NULL;
    int sock_fd = -1, read_bytes = 0;
    struct spectral_samp_msg *msg = NULL;
    u_int8_t *samprecvbuf = NULL;
    u_int32_t num_buf_written = 0;
    FILE *fp = NULL;
    int advncd_spectral = 0;
    struct spectral_config sp;
    int is_pwr_format_enabled = 0;
    u_int16_t bin_scale = 0;
    bool is_metadata_written = false;
    u_int16_t num_rbuff_errors = 0;
    uint8_t *radio_macaddr = spectral->macaddr;

    u_int16_t bin_cnt = 0;
    u_int32_t temp_scaled_binmag = 0;
    u_int16_t scan_count_orig;

    /* SO_RCVBUF/SO_RCVBUFFORCE expect receive buffer sizes as integer
     * values.
     */
    int rbuff_sz_req = 0;            /* Receive buffer size to be requested */
    int rbuff_sz_req_limit = 0;      /* Upper limit on receive buffer size to be
                                        requested */
    int rbuff_sz_curr = 0;           /* Current receive buffer size */
    socklen_t rbuff_sz_curr_len = 0; /* Length of current receive buffer size
                                        datatype */
    int free_mem = 0;                /* Free physical memory (not including
                                        caching) */
    struct timeval tv_timeout;
    fd_set readfds;
    struct statvfs file_system_stats;
    unsigned long long int free_mem_bytes = 0;
    loff_t max_usable_bytes = 0;
    loff_t num_bytes_written = 0;
    int wcnt;
    bool timed_out = false;

    if (spectral->caps.hw_gen == QCA_WLAN_VENDOR_SPECTRAL_SCAN_CAP_HW_GEN_3) {
        printf("Gen3 linear scaling: %s\n",
                enable_gen3_linear_scaling? "Enabled": "Disabled");
    }

    memset(&sp, 0, sizeof(sp));

    /* Check if the user input is within the valid allowed range */
    if (num_raw_data_to_cap <= 0) {
        fprintf(stderr, "Capture count need to be a non-zero positive number\n");
        ret = -1;
        goto out;
    }

    sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_ATHEROS);
    if (sock_fd < 0) {
        printf("socket errno=%d\n", sock_fd);
        ret = sock_fd;
        goto out;
    }

    /* On some platforms and under some circumstances, our netlink message
     * receive rate may not be able to keep up with the driver's send rate. This
     * can result in receive buffer errors.
     * To mitigate this, we increase the socket receive buffer size.
     *
     * An alternative considered is to have two threads, one purely for socket
     * receive operations, the other for processing the received information.
     * However, test results partially emulating this scenario showed that even
     * with this, we can run into the receive buffer errors (due to the high
     * rate at which the netlink messages arrive).
     */

    /* Get current receive buffer size */
    rbuff_sz_curr_len = sizeof(rbuff_sz_curr);
    if ((ret = getsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF,
                   (void *)&rbuff_sz_curr,
                   &rbuff_sz_curr_len)) < 0) {
            perror("getsockopt\n");
            goto out;
    }

    /* Calculate upper limit on receive buffer size we'd like to request */
    if ((free_mem = get_free_mem_kB()) < 0)
    {
        fprintf(stderr, "Could not determine amount of free physical memory\n");
        ret = -1;
        goto out;
    }
    rbuff_sz_req_limit = (int)(((float)free_mem * 1000) *
                                        QCA_SPECTOOL_MAX_FREEMEM_UTIL);

    /* Determine the receive buffer size to be requested */
    rbuff_sz_req = SAMPRECVBUF_SZ * sizeof(u_int8_t) * num_raw_data_to_cap;

    if (rbuff_sz_req > rbuff_sz_req_limit)
    {
        rbuff_sz_req = rbuff_sz_req_limit;
    }

    if (rbuff_sz_req > rbuff_sz_curr)
    {
        /* We first try SO_RCVBUFFORCE. This is available since Linux 2.6.14,
         * and if we have CAP_NET_ADMIN privileges.
         *
         * In case SO_RCVBUFFORCE is not available or we are not entitled to use
         * it, then an error will be returned and we can fall back to SO_RCVBUF.
         * If we use SO_RCVBUF, the kernel will cap our requested value as per
         * rmem_max. We will have to survive with the possibility of a few
         * netlink messages being lost under some circumstances.
         */
        ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                            (void *)&rbuff_sz_req, sizeof(rbuff_sz_req));

        if (ret < 0)
        {
            if ((ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF,
                             (void *)&rbuff_sz_req, sizeof(rbuff_sz_req))) < 0) {
                    perror("setsockopt\n");
                    goto out;
            }
        }
    }
    /* Else if rbuff_sz_req < rbuff_sz_curr, we go with the default configured
     * into the kernel. We will have to survive with the possibility of a few
     * netlink messages being lost under some circumstances.
     *
     * There can be circumstances where free_mem is 0, resulting in
     * rbuff_sz_req=0. We need not bother about these. It is the kernel's
     * responsibility to handle these situations appropriately.
     */

    fp = fopen("outFile", "wt");
    if (!fp) {
        printf("Could not open file to write\n");
        ret = -1;
        goto out;
    }

    /* Gets the avaialable free memory for outFile */
    fstatvfs(fileno(fp), &file_system_stats);
    free_mem_bytes = file_system_stats.f_bsize * file_system_stats.f_bavail;
    max_usable_bytes = (free_mem_bytes * spectral->mem_utilization_factor);


    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 1;

    if((read_bytes=bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr))) < 0) {
        if (read_bytes < 0)
            perror("bind(netlink)");
        printf("BIND errno=%d\n", read_bytes);
        ret = read_bytes;
        goto out;
    }

    samprecvbuf = (u_int8_t *)malloc(SAMPRECVBUF_SZ * sizeof(u_int8_t));
    if (samprecvbuf == NULL) {
        printf("Could not allocate buffer to receive SAMP data\n");
        ret = -1;
        goto out;
    }
    memset(samprecvbuf, 0, SAMPRECVBUF_SZ * sizeof(u_int8_t));

    FD_ZERO(&readfds);
    FD_SET(sock_fd, &readfds);

    /* Get current configurations */
    spectralGetThresholds(spectral, &sp);
    is_pwr_format_enabled = sp.ss_pwr_format;
    bin_scale = sp.ss_bin_scale;

    /* Setting scan count and starting spectral scan in case of N samples to capture */
    if(need_start_stop) {
         struct spectral_param param = {0};

        /* Save current scan count and set scan count to 0.
         * This is done since HW has a limitation of max scan count as 4000 */
        scan_count_orig = sp.ss_count;
        param.id = SPECTRAL_PARAM_SCAN_COUNT;
        param.value = 0;
        spectralset(spectral, &param);
        spectralStartScan(spectral);
    }

    printf("Waiting for message from kernel\n");

    while ((num_buf_written < num_raw_data_to_cap) &&
           ((num_raw_data_to_cap <= MAX_CAPTURE_SIZE_WITHOUT_FREE_MEM_CHECK) ||
            (num_bytes_written < (max_usable_bytes - GUARD_NUM_BYTES)))) {

        tv_timeout.tv_sec = QCA_SPECTOOL_NL_TIMEOUT_SEC;
        tv_timeout.tv_usec = QCA_SPECTOOL_NL_TIMEOUT_USEC;

        ret = select(sock_fd + 1, &readfds, NULL, NULL, &tv_timeout);

        if (ret < 0) {
            perror("select\n");
            goto stopscan;
        } else if (0 == ret) {
            printf("Warning - timed out waiting for messages.\n");
            timed_out = true;
            break;
        } else if (!FD_ISSET(sock_fd, &readfds)) {
            /* This shouldn't happen if the kernel is behaving correctly. */
            fprintf(stderr, "Unexpected condition waiting for messages - no "
                    "socket fd indicated by select()\n");
            ret = -1;
            goto stopscan;
        }

        fromlen = sizeof(src_addr);
        read_bytes = recvfrom(sock_fd, samprecvbuf,
                              SAMPRECVBUF_SZ * sizeof(u_int8_t), MSG_WAITALL,
                              (struct sockaddr *) &src_addr, &fromlen);
        if (read_bytes < 0) {
            if (ENOBUFS == errno)
            {
                num_rbuff_errors++;
            } else {
                perror("recvfrom(netlink)\n");
                printf("Error reading netlink\n");
                ret = read_bytes;
                goto stopscan;
            }
        } else {
            u_int16_t valCnt;
            u_int32_t scan_ch_width;

            nlh = (struct nlmsghdr *) samprecvbuf;
            msg = (struct spectral_samp_msg *) NLMSG_DATA(nlh);

            assert(sizeof(spectral->macaddr) == sizeof(msg->macaddr));
            if (memcmp(spectral->macaddr, msg->macaddr,
                        sizeof(spectral->macaddr))) {
                continue;
            }

            if (msg->samp_data.spectral_mode != spectral->sscan_mode)
                continue;

            if (msg->samp_data.spectral_mode == SPECTRAL_SCAN_MODE_NORMAL) {
                scan_ch_width = msg->samp_data.ch_width;
            } else if(msg->samp_data.spectral_mode == SPECTRAL_SCAN_MODE_AGILE) {
                scan_ch_width = msg->samp_data.agile_ch_width;
            } else {
                fprintf(stderr, "Invalid Spectral mode %d in SAMP message\n", msg->samp_data.spectral_mode);
                goto stopscan;
            }

            if (enable_gen3_linear_scaling &&
                    (spectral->caps.hw_gen ==
                        QCA_WLAN_VENDOR_SPECTRAL_SCAN_CAP_HW_GEN_3)) {
                /*
                 * Scale the gen3 bins to values approximately similar to those
                 * of gen2.
                 */

                for (bin_cnt = 0;
                     bin_cnt < msg->samp_data.bin_pwr_count;
                     bin_cnt++)
                {
                    /*
                     * Note: In a later phase we will get default max gain
                     * value, low level offset, RSSI threshold, and high level
                     * offset from Spectral capabilities structure once these
                     * are added there.
                     */
                    temp_scaled_binmag =
                        spectral_scale_linear_to_gen2(\
                                msg->samp_data.bin_pwr[bin_cnt],
                                SPECTRAL_QCA9984_MAX_GAIN,
                                SPECTRAL_IPQ8074_DEFAULT_MAX_GAIN_HARDCODE,
                                SPECTRAL_SCALING_LOW_LEVEL_OFFSET,
                                msg->samp_data.spectral_rssi,
                                SPECTRAL_SCALING_RSSI_THRESH,
                                msg->samp_data.spectral_agc_total_gain,
                                SPECTRAL_SCALING_HIGH_LEVEL_OFFSET,
                                bin_scale,
                                bin_scale);

                    msg->samp_data.bin_pwr[bin_cnt] =
                        (temp_scaled_binmag > 255) ? 255: temp_scaled_binmag;
                }

                if (scan_ch_width == IEEE80211_CWM_WIDTH160 ||
                    scan_ch_width == IEEE80211_CWM_WIDTH80_80) {
                    for (bin_cnt = 0;
                         bin_cnt < msg->samp_data.bin_pwr_count_sec80;
                         bin_cnt++)
                    {
                        /*
                         * Note: In a later phase we will get default max gain
                         * value, low level offset, RSSI threshold, and high
                         * level offset from Spectral capabilities structure
                         * once these are added there.
                         */
                        temp_scaled_binmag =
                            spectral_scale_linear_to_gen2(\
                                  msg->samp_data.bin_pwr_sec80[bin_cnt],
                                  SPECTRAL_QCA9984_MAX_GAIN,
                                  SPECTRAL_IPQ8074_DEFAULT_MAX_GAIN_HARDCODE,
                                  SPECTRAL_SCALING_LOW_LEVEL_OFFSET,
                                  msg->samp_data.spectral_rssi_sec80,
                                  SPECTRAL_SCALING_RSSI_THRESH,
                                  msg->samp_data.spectral_agc_total_gain_sec80,
                                  SPECTRAL_SCALING_HIGH_LEVEL_OFFSET,
                                  bin_scale,
                                  bin_scale);

                        msg->samp_data.bin_pwr_sec80[bin_cnt] =
                           (temp_scaled_binmag > 255) ? 255: temp_scaled_binmag;
                    }
                }
            }

            if (!is_metadata_written) {
                bool is_165mhz_opearation = (msg->samp_data.bin_pwr_count_5mhz > 0);

                wcnt = fprintf(fp, "***** THIS IS A MACHINE GENERATED FILE, DO NOT EDIT *****\n\n");

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "version:%c%u\n", delimiter, SPECTRAL_LOG_VERSION_ID3);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "mode:%c%u\n", delimiter, spectral->sscan_mode);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "primary_frequency:%c%u\n", delimiter, msg->freq);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "cfreq1:%c%u\n", delimiter, msg->vhtop_ch_freq_seg1);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "cfreq2:%c%u\n", delimiter, msg->vhtop_ch_freq_seg2);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "agile_frequency1:%c%u\n", delimiter,
                        msg->agile_freq1);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "agile_frequency2:%c%u\n", delimiter,
                        msg->agile_freq2);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "channel_width:%c%u\n", delimiter, msg->samp_data.ch_width);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "agile_channel_width:%c%u\n", delimiter, msg->samp_data.agile_ch_width);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "mac_address:%c%02x:%02x:%02x:%02x:%02x:%02x\n", delimiter,
                               radio_macaddr[0], radio_macaddr[1], radio_macaddr[2],
                               radio_macaddr[3], radio_macaddr[4], radio_macaddr[5]);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "gen3_linear_scaling:%c%u\n", delimiter,
                    enable_gen3_linear_scaling);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "165mhz_operation:%c%u\n", delimiter,
                               is_165mhz_opearation);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "lb_edge_extrabins:%c%u\n", delimiter,
                               msg->samp_data.lb_edge_extrabins);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "rb_edge_extrabins:%c%u\n", delimiter,
                               msg->samp_data.rb_edge_extrabins);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "\nspectral_caps\n\n");

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "phy_diag_cap:%c%u\n", delimiter, spectral->caps.phydiag_cap);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "radar_cap:%c%u\n", delimiter, spectral->caps.radar_cap);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "spectral_cap:%c%u\n", delimiter, spectral->caps.spectral_cap);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "advanced_spectral_cap:%c%u\n", delimiter,
                    spectral->caps.advncd_spectral_cap);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "hw_gen:%c%u\n", delimiter, spectral->caps.hw_gen);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "is_scaling_params_populated:%c%u\n", delimiter,
                               spectral->caps.is_scaling_params_populated);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "formula_id:%c%u\n", delimiter,
                               spectral->caps.formula_id);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "low_level_offset:%c%d\n", delimiter,
                               spectral->caps.low_level_offset);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "high_level_offset:%c%d\n", delimiter,
                               spectral->caps.high_level_offset);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "rssi_thr:%c%d\n", delimiter,
                               spectral->caps.rssi_thr);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "default_agc_max_gain:%c%u\n", delimiter,
                               spectral->caps.default_agc_max_gain);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "agile_spectral_cap:%c%u\n", delimiter,
                               spectral->caps.agile_spectral_cap);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "agile_spectral_cap_160:%c%u\n", delimiter,
                               spectral->caps.agile_spectral_cap_160);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "agile_spectral_cap_80p80:%c%u\n", delimiter,
                               spectral->caps.agile_spectral_cap_80p80);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "num_detectors_20mhz:%c%u\n", delimiter,
                               spectral->caps.num_detectors_20mhz);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "num_detectors_40mhz:%c%u\n", delimiter,
                               spectral->caps.num_detectors_40mhz);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "num_detectors_80mhz:%c%u\n", delimiter,
                               spectral->caps.num_detectors_80mhz);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "num_detectors_160mhz:%c%u\n", delimiter,
                               spectral->caps.num_detectors_160mhz);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "num_detectors_80p80mhz:%c%u\n", delimiter,
                               spectral->caps.num_detectors_80p80mhz);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                advncd_spectral = spectral->caps.advncd_spectral_cap;
                wcnt = fprintf(fp, "\nspectral_params\n\n");

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                if (advncd_spectral)
                    wcnt = fprintf(fp, "num_spectral_params:%c%u\n", delimiter,
                                   NUM_SPECTRAL_PARAMS_ADVANCED);
                else
                    wcnt = fprintf(fp, "num_spectral_params:%c%u\n", delimiter,
                                   NUM_SPECTRAL_PARAMS_NON_ADVANCED);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                if (!advncd_spectral) {
                    wcnt = fprintf(fp, "fft_period:%c%u\n", delimiter,
                                   sp.ss_fft_period);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;
                }

                wcnt = fprintf(fp, "scan_period:%c%u\n", delimiter,
                               sp.ss_period);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "scan_count:%c%u\n", delimiter, sp.ss_count);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                if (!advncd_spectral) {
                    wcnt = fprintf(fp, "short_report:%c%u\n", delimiter,
                                   sp.ss_short_report);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;
                }

                wcnt = fprintf(fp, "priority:%c%u\n", delimiter,
                               sp.ss_spectral_pri);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                if (advncd_spectral) {
                    wcnt = fprintf(fp, "fft_size:%c%u\n", delimiter,
                                   sp.ss_fft_size);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "gc_ena:%c%u\n", delimiter,
                                   sp.ss_gc_ena);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "restart_ena:%c%u\n", delimiter,
                                   sp.ss_restart_ena);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "noise_floor_ref:%c%d\n", delimiter,
                                   (int8_t)sp.ss_noise_floor_ref);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "init_delay:%c%u\n", delimiter,
                                   sp.ss_init_delay);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "nb_tone_thr:%c%u\n", delimiter,
                                   sp.ss_nb_tone_thr);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "str_bin_thr:%c%u\n", delimiter,
                                   sp.ss_str_bin_thr);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "wb_rpt_mode:%c%u\n", delimiter,
                                   sp.ss_wb_rpt_mode);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "rssi_rpt_mode:%c%u\n", delimiter,
                                   sp.ss_rssi_rpt_mode);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "rssi_thr:%c%d\n", delimiter,
                                   (int8_t)sp.ss_rssi_thr);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "pwr_format:%c%u\n", delimiter,
                                   sp.ss_pwr_format);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "rpt_mode:%c%u\n", delimiter,
                                   sp.ss_rpt_mode);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "bin_scale:%c%u\n", delimiter,
                                   sp.ss_bin_scale);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "dBm_adj:%c%u\n", delimiter, sp.ss_dbm_adj);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "chn_mask:%c%u\n", delimiter,
                                   sp.ss_chn_mask);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "frequency1:%c%u\n", delimiter,
                                   sp.ss_frequency.cfreq1);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;

                    wcnt = fprintf(fp, "frequency2:%c%u\n", delimiter,
                                   sp.ss_frequency.cfreq2);

                    if (wcnt < 0) {
                        ret = -1;
                        perror("Error while writing to outFile");
                        goto stopscan;
                    }

                    num_bytes_written += wcnt;
                }

                wcnt = fprintf(fp, "\n");

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(fp, "S.No %c Num-FFT-Bins(N) %c bin1 %c bin2 %c ... %c"
                               "binN %c Timestamp %c RSSI %c NF %c AGC-Gain %c Gain-Change %c Pri80-Indication %c"
                               "raw_timestamp %c timestamp_war_offset %c last_raw_timestamp %c reset_delay %c reset_count\n",
                               delimiter, delimiter, delimiter, delimiter,
                               delimiter, delimiter, delimiter, delimiter,
                               delimiter, delimiter, delimiter, delimiter,
                               delimiter, delimiter, delimiter, delimiter);

                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }

                num_bytes_written += wcnt;

                is_metadata_written = true;
            }

            /* Write sample number */
            wcnt = fprintf( fp, "%u %c ", (unsigned)num_buf_written, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write bin count */
            wcnt = fprintf( fp, "%u %c ", (unsigned)msg->samp_data.bin_pwr_count, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            for (valCnt = 0; valCnt < (unsigned)msg->samp_data.bin_pwr_count; valCnt++) {
                if (is_pwr_format_enabled)
                    /* Write bin values, dbm format */
                    wcnt = fprintf(fp, "%d %c ",
                                     (int8_t)(msg->samp_data.bin_pwr[valCnt]), delimiter);
                else
                    /* Write bin values, linear format */
                    wcnt = fprintf(fp, "%u %c ",
                                     (u_int8_t)(msg->samp_data.bin_pwr[valCnt]), delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;
            }

            /* Write timestamp */
            wcnt = fprintf(fp, "%u %c ", (unsigned)msg->samp_data.spectral_tstamp, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write RSSI */
            wcnt = fprintf(fp, "%d %c ", msg->samp_data.spectral_rssi, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write noise floor */
            wcnt = fprintf(fp, "%d %c ", msg->samp_data.noise_floor, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write AGC total gain */
            wcnt = fprintf(fp, "%d %c ", msg->samp_data.spectral_agc_total_gain, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write gain change bit */
            wcnt = fprintf(fp, "%d %c ", msg->samp_data.spectral_gainchange, delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write pri80 indication bit */
            wcnt = fprintf(fp, "%u %c ", msg->samp_data.spectral_pri80ind,
                           delimiter);
            if (wcnt < 0) {
                ret = -1;
                perror("Error while writing to outFile");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write raw_timestamp */
            wcnt = fprintf(fp, "%u %c", msg->samp_data.raw_timestamp, delimiter);
            if (wcnt < 0) {
                ret = -1;
                fprintf(stderr, "Error while writing to outFile\n");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write timestamp_war_offset */
            wcnt = fprintf(fp, "%u %c", msg->samp_data.timestamp_war_offset, delimiter);
            if (wcnt < 0) {
                ret = -1;
                fprintf(stderr, "Error while writing to outFile\n");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write last_raw_timestamp */
            wcnt = fprintf(fp, "%u %c", msg->samp_data.last_raw_timestamp, delimiter);
            if (wcnt < 0) {
                ret = -1;
                fprintf(stderr, "Error while writing to outFile\n");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write reset_delay */
            wcnt = fprintf(fp, "%u %c", msg->samp_data.reset_delay, delimiter);
            if (wcnt < 0) {
                ret = -1;
                fprintf(stderr, "Error while writing to outFile\n");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            /* Write target_rest_count */
            wcnt = fprintf(fp, "%u %c\n", msg->samp_data.target_reset_count, delimiter);
            if (wcnt < 0) {
                ret = -1;
                fprintf(stderr, "Error while writing to outFile\n");
                goto stopscan;
            }
            num_bytes_written += wcnt;

            if (scan_ch_width == IEEE80211_CWM_WIDTH160 || scan_ch_width == IEEE80211_CWM_WIDTH80_80) {
                /* Write sample number */
                wcnt = fprintf( fp, "%u %c ", (unsigned)num_buf_written, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write bin count */
                wcnt = fprintf(fp, "%u %c ",
                                 (unsigned)msg->samp_data.bin_pwr_count_sec80, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                for (valCnt = 0; valCnt < (unsigned)msg->samp_data.bin_pwr_count_sec80; valCnt++)
                {
                    if (is_pwr_format_enabled) {
                        /* Write bin values, dbm format */
                        wcnt =fprintf(fp, "%d %c ",
                                        (int8_t)(msg->samp_data.bin_pwr_sec80[valCnt]),
                                        delimiter);
                        if (wcnt < 0) {
                            ret = -1;
                            perror("Error while writing to outFile");
                            goto stopscan;
                        }
                        num_bytes_written += wcnt;

                    }
                    else {
                        /* Write bin values, linear format */
                        wcnt = fprintf(fp, "%u %c ",
                                         (u_int8_t)(msg->samp_data.bin_pwr_sec80[valCnt]),
                                         delimiter);
                        if (wcnt < 0) {
                            ret = -1;
                            perror("Error while writing to outFile");
                            goto stopscan;
                        }
                        num_bytes_written += wcnt;
                    }
                }

                /* Write timestamp */
                wcnt = fprintf(fp, "%u %c ",
                                 (unsigned)msg->samp_data.spectral_tstamp, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write RSSI */
                wcnt = fprintf(fp, "%d %c ", msg->samp_data.spectral_rssi_sec80, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write noise floor */
                wcnt = fprintf(fp, "%d %c ", msg->samp_data.noise_floor_sec80, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write AGC total gain */
                wcnt = fprintf(fp, "%d %c ",
                                 msg->samp_data.spectral_agc_total_gain_sec80, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write gain change bit */
                wcnt = fprintf(fp, "%d %c ",
                                 msg->samp_data.spectral_gainchange_sec80, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write pri80 indication bit */
                wcnt = fprintf(fp, "%u %c ",
                               msg->samp_data.spectral_pri80ind_sec80,
                               delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write raw_timestamp_sec80 */
                wcnt = fprintf(fp, "%u %c", msg->samp_data.raw_timestamp_sec80, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write timestamp_war_offset */
                wcnt = fprintf(fp, "%u %c", msg->samp_data.timestamp_war_offset, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write last_raw_timestamp */
                wcnt = fprintf(fp, "%u %c", msg->samp_data.last_raw_timestamp, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write reset_delay */
                wcnt = fprintf(fp, "%u %c", msg->samp_data.reset_delay, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write target_reset_count */
                wcnt = fprintf(fp, "%u %c\n", msg->samp_data.target_reset_count, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto stopscan;
                }
                num_bytes_written += wcnt;
            }

            if (msg->samp_data.bin_pwr_count_5mhz > 0) {
                /* Write sample number */
                wcnt = fprintf( fp, "%u %c ", (unsigned)num_buf_written, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                /* Write bin count */
                wcnt = fprintf(fp, "%u %c ",
                                 (unsigned)msg->samp_data.bin_pwr_count_5mhz, delimiter);
                if (wcnt < 0) {
                    ret = -1;
                    perror("Error while writing to outFile");
                    goto stopscan;
                }
                num_bytes_written += wcnt;

                for (valCnt = 0; valCnt < (unsigned)msg->samp_data.bin_pwr_count_5mhz; valCnt++)
                {
                    if (is_pwr_format_enabled) {
                        /* Write bin values, dbm format */
                        wcnt =fprintf(fp, "%d %c ",
                                        (int8_t)(msg->samp_data.bin_pwr_5mhz[valCnt]),
                                        delimiter);
                        if (wcnt < 0) {
                            ret = -1;
                            perror("Error while writing to outFile");
                            goto stopscan;
                        }
                        num_bytes_written += wcnt;

                    }
                    else {
                        /* Write bin values, linear format */
                        wcnt = fprintf(fp, "%u %c ",
                                         (u_int8_t)(msg->samp_data.bin_pwr_5mhz[valCnt]),
                                         delimiter);
                        if (wcnt < 0) {
                            ret = -1;
                            perror("Error while writing to outFile");
                            goto stopscan;
                        }
                        num_bytes_written += wcnt;
                    }
                }
                /* Write new line */
                wcnt = fprintf(fp, "\n");
                if (wcnt < 0) {
                    ret = -1;
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto stopscan;
                }
                num_bytes_written += wcnt;
            }

            num_buf_written++;
        }
    }

stopscan:
    /* Stopping spectral scan and resetting scan count to 0 in case of N samples to capture */
    if(need_start_stop) {
        struct spectral_param param = {0};

        param.id = SPECTRAL_PARAM_SCAN_COUNT;
        param.value = scan_count_orig;
        spectralStopScan(spectral);
        spectralset(spectral, &param);
    }

    if (msg) {
        /* Print noise floor value of last sample */
        printf("Noise Floor %d\n", msg->samp_data.noise_floor);
    }

    if ((num_buf_written != num_raw_data_to_cap) && (!timed_out))
	printf("Not enough memory to capture requested number of samples\n");

    printf("Number of samples captured %d\n", num_buf_written);

    if (num_rbuff_errors)
    {
        printf("Warning: %hu receive buffer errors. Some samples were lost due "
               "to receive-rate constraints\n", num_rbuff_errors);
    }

out:
    if (sock_fd >= 0) {
        close(sock_fd);
    }

    if (fp != NULL) {
        /* change file permissions to read only */
        fchmod(fileno(fp), S_IRUSR | S_IRGRP | S_IROTH);
        fclose(fp);
    }

    if (samprecvbuf != NULL) {
        free(samprecvbuf);
    }

    spectralAtdClean(spectral);
    return ret;
}

#define put_params(name) \
do { \
	if (config_params[SPECTRAL_PARAM_ ## name] != -1) { \
		printf("put %s value %d\n", # name, \
			config_params[SPECTRAL_PARAM_ ## name]); \
		nla_put_u32(msg, \
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_ ## name, \
			config_params[SPECTRAL_PARAM_ ## name]);  \
	} \
} while (0)

static void
spectralAtdClean(struct spectralhandler *spectral)
{
    spectral->atd.ad_id = 0;
    spectral->atd.ad_in_data = NULL;
    spectral->atd.ad_in_size = 0;
    spectral->atd.ad_out_data = NULL;
    spectral->atd.ad_out_size = 0;
}

#if UMAC_SUPPORT_CFG80211
static int spectralGetStatus_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
        	struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
        	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_STATUS_MAX + 1];

        	nla_parse(tb_vendor,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_STATUS_MAX,
        	        nla_data(nl_vendor), nla_len(nl_vendor), NULL);

		struct spectral_scan_state *status = (struct spectral_scan_state*)arg;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_STATUS_IS_ACTIVE])
			status->is_active = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_STATUS_IS_ENABLED])
			status->is_enabled = 1;
	} else
		perror("vendor data attribute is not there in nl_msg");
	return NL_SKIP;
}
#endif /* UMAC_SUPPORT_CFG80211 */

static int
spectralGetStatus(struct spectralhandler *spectral)
{
	u_int32_t enabled = 0;
	u_int32_t active = 0;
	#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		enum qca_wlan_vendor_spectral_scan_mode nl_mode;
		struct spectral_scan_state status;
    		memset(&status, 0, sizeof(status));

		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_STATUS,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return -ENOMEM;
		}

		struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

		if (!data) {
			fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return -ENOBUFS;
		}

		if (convert_to_cfg80211_spectral_mode(spectral->sscan_mode, &nl_mode)) {
			nlmsg_free(msg);
			return -EINVAL;
		}
		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_STATUS_MODE,
			nl_mode);
		nla_nest_end(msg, data);

		send_and_recv(info, info->cmd_sock, msg, spectralGetStatus_handler, &status);

		enabled = status.is_enabled;
		active = status.is_active;
	} else
	#endif
	{
		spectral->atd.ad_id = SPECTRAL_IS_ENABLED | ATH_DIAG_DYN;
		spectral->atd.ad_in_data = NULL;
		spectral->atd.ad_in_size = 0;
		spectral->atd.ad_out_data = (void *) &enabled;
		spectral->atd.ad_out_size = sizeof(u_int32_t);
		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
		                       spectral->s) < 0) {
		    err(1, "%s", spectral->atd.ad_name);
		}
		spectralAtdClean(spectral);

		spectral->atd.ad_id = SPECTRAL_IS_ACTIVE | ATH_DIAG_DYN;
    		spectral->atd.ad_in_data = NULL;
    		spectral->atd.ad_in_size = 0;
    		spectral->atd.ad_out_data = (void *) &active;
    		spectral->atd.ad_out_size = sizeof(u_int32_t);
    		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
    		                       spectral->s) < 0) {
    		    err(1, "%s", spectral->atd.ad_name);
    		}
    		spectralAtdClean(spectral);
	}
	printf("Spectral scan is %s\n", (enabled) ? "enabled": "disabled");
	printf("Spectral scan is %s\n", (active) ? "active": "inactive");

	return 0;
}

static int
spectralStartScan(struct spectralhandler *spectral)
{
	#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		enum qca_wlan_vendor_spectral_scan_mode nl_mode;
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return -ENOMEM;
		}

		struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

		if (!data) {
			fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return -ENOBUFS;
		}

		if (convert_to_cfg80211_spectral_mode(spectral->sscan_mode, &nl_mode)) {
			nlmsg_free(msg);
			return -EINVAL;
		}
		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
			nl_mode);

		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE_SCAN);
		nla_nest_end(msg, data);
		return send_and_recv(info, info->cmd_sock, msg, spectral_start_scan_handler, 0);
	} else
	#endif
	{
		u_int32_t result;

		spectral->atd.ad_id = SPECTRAL_ACTIVATE_SCAN | ATH_DIAG_DYN;
		spectral->atd.ad_out_data = NULL;
		spectral->atd.ad_out_size = 0;
		spectral->atd.ad_in_data = (void *) &result;
		spectral->atd.ad_in_size = sizeof(u_int32_t);
		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
    		                       spectral->s) < 0) {
    		    err(1, "%s", spectral->atd.ad_name);
    		}
		spectralAtdClean(spectral);
		return 0;
	}
}

static int
spectralStopScan(struct spectralhandler *spectral)
{
#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		enum qca_wlan_vendor_spectral_scan_mode nl_mode;
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_STOP,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return -ENOMEM;
		}

		struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

		if (!data) {
			fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return -ENOBUFS;
		}

		if (convert_to_cfg80211_spectral_mode(spectral->sscan_mode, &nl_mode)) {
			nlmsg_free(msg);
			return -EINVAL;
		}
		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
			nl_mode);
		nla_nest_end(msg, data);
		return send_and_recv(info, info->cmd_sock, msg, spectral_stop_scan_handler, 0);
	} else
#endif
	{
		u_int32_t result;

		spectral->atd.ad_id = SPECTRAL_STOP_SCAN | ATH_DIAG_DYN;
		spectral->atd.ad_out_data = NULL;
		spectral->atd.ad_out_size = 0;
		spectral->atd.ad_in_data = (void *) &result;
		spectral->atd.ad_in_size = sizeof(u_int32_t);
		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
		                       spectral->s) < 0) {
		    err(1, "%s", spectral->atd.ad_name);
		}
		spectralAtdClean(spectral);
		return 0;
	}
}

static int
spectralSetDebugLevel(struct spectralhandler *spectral, u_int32_t level)
{
	#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return -ENOMEM;
		}

		struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
		if (!data) {
			fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return -ENOBUFS;
		}

		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE_CONFIG);
		nla_put_u32(msg,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DEBUG_LEVEL, level);
		nla_nest_end(msg, data);
		send_and_recv(info, info->cmd_sock, msg, 0, 0);
	} else
	#endif
	{
		spectral->atd.ad_id = SPECTRAL_SET_DEBUG_LEVEL | ATH_DIAG_IN;
		spectral->atd.ad_out_data = NULL;
		spectral->atd.ad_out_size = 0;
		spectral->atd.ad_in_data = (void *) &level;
		spectral->atd.ad_in_size = sizeof(u_int32_t);
		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
		                       spectral->s) < 0) {
		    err(1, "%s", spectral->atd.ad_name);
		}
		spectralAtdClean(spectral);
	}
	return 0;
}

#if UMAC_SUPPORT_CFG80211
/**
 * spectralSetDMADebug() - Enable/disable the debug of Spectral DMA
 * @spectral : Spectral handler
 * @attribute: Attribute to set
 * @value    : Value to set to the attribute
 *
 * Enable/disable the debug of Spectral DMA ring/buffer
 *
 * Return    : 0 on success, else failure
 */
static int
spectralSetDMADebug(struct spectralhandler *spectral,
		    enum spectral_dma_debug dma_debug,
		    u_int8_t value)
{
	if (!spectral) {
		fprintf(stderr, "Spectral handler is NULL\n");
		return -EINVAL;
	}

	if (IS_CFG80211_ENABLED(spectral)) {
		enum qca_wlan_vendor_attr_spectral_scan attribute;
		int ret;
		struct nl_msg *msg;
		struct nlattr *data;

		switch(dma_debug) {
		case SPECTRAL_DMA_RING_DEBUG:
			attribute = QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DMA_RING_DEBUG;
			break;

		case SPECTRAL_DMA_BUFFER_DEBUG:
			attribute = QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DMA_BUFFER_DEBUG;
			break;

		default:
			fprintf(stderr, "Unsupported DMA debug(%d) requested\n",dma_debug);
			return -EINVAL;
		}

		msg = nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return -ENOMEM;
		}

		data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
		if (!data) {
			fprintf(stderr, "Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return -ENOBUFS;
		}

		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE_CONFIG);
		nla_put_u8(msg, attribute, value);
		nla_nest_end(msg, data);
		ret = send_and_recv(info, info->cmd_sock, msg, 0, 0);
		if (ret)
			fprintf(stderr, "Setting the DMA debug failed: return value = %d (%s)\n", ret, strerror(-ret));
		return ret;
	}
	return 0;
}
#else
static int
spectralSetDMADebug(struct spectralhandler *spectral,
		    enum spectral_dma_debug dma_debug,
		    u_int8_t value)
{
	fprintf(stderr, "Setting DMA debug isn't supported in the current driver configuration\n");
	return -EINVAL;
}
#endif /* UMAC_SUPPORT_CFG80211 */

#if UMAC_SUPPORT_CFG80211
static int spectralGetDiagStats_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_MAX + 1];

		nla_parse(tb_vendor,QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_MAX,
		        nla_data(nl_vendor), nla_len(nl_vendor), NULL);

		struct spectral_diag_stats *diag_stats = (struct spectral_diag_stats *)arg;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_SIG_MISMATCH])
			diag_stats->spectral_mismatch = nla_get_u64(tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_SIG_MISMATCH]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_SEC80_SFFT_INSUFFLEN])
			diag_stats->spectral_sec80_sfft_insufflen = nla_get_u64(tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_SEC80_SFFT_INSUFFLEN]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_NOSEC80_SFFT])
			diag_stats->spectral_no_sec80_sfft = nla_get_u64(tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_NOSEC80_SFFT]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_VHTSEG1ID_MISMATCH])
			diag_stats->spectral_vhtseg1id_mismatch = nla_get_u64(tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_VHTSEG1ID_MISMATCH]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_VHTSEG2ID_MISMATCH])
			diag_stats->spectral_vhtseg2id_mismatch = nla_get_u64(tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_DIAG_VHTSEG2ID_MISMATCH]);
	} else
		perror("vendor data attribute is not there in nl_msg");
	return NL_SKIP;
}
#endif /* UMAC_SUPPORT_CFG80211 */

static void
spectralGetDiagStats(struct spectralhandler *spectral,
                     struct spectral_diag_stats *diag_stats)
{
	#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_DIAG_STATS,
				spectral->atd.ad_name);
		send_and_recv(info, info->cmd_sock, msg, spectralGetDiagStats_handler, diag_stats);
	} else
	#endif
	{
    		spectral->atd.ad_id = SPECTRAL_GET_DIAG_STATS | ATH_DIAG_DYN;
    		spectral->atd.ad_out_data = (void *) diag_stats;
    		spectral->atd.ad_out_size = sizeof(struct spectral_diag_stats);
    		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
    		                       spectral->s) < 0) {
    		    err(1, "%s", spectral->atd.ad_name);
    		}
	}
}

static int
spectralPrintDiagStats(struct spectralhandler *spectral)
{
    struct spectral_diag_stats diag_stats;

    memset(&diag_stats, 0, sizeof(diag_stats));

    spectralGetDiagStats(spectral, &diag_stats);

    printf("Diagnostic statistics:\n");
    printf("Spectral TLV signature mismatches: %" PRIu64 "\n",
           diag_stats.spectral_mismatch);
    printf("Insufficient length when parsing for Secondary 80 Search FFT "
           "report: %" PRIu64 "\n",
           diag_stats.spectral_sec80_sfft_insufflen);
    printf("Secondary 80 Search FFT report TLV not found: %" PRIu64 "\n",
           diag_stats.spectral_no_sec80_sfft);
    printf("VHT Operation Segment 1 ID mismatches in Search FFT report: %"
           PRIu64 "\n",
           diag_stats.spectral_vhtseg1id_mismatch);
    printf("VHT Operation Segment 2 ID mismatches in Search FFT report: %"
           PRIu64 "\n",
           diag_stats.spectral_vhtseg2id_mismatch);

    spectralAtdClean(spectral);
    return 0;
}

#if UMAC_SUPPORT_CFG80211
static int spectralGetCapInfo_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_MAX + 1];

		nla_parse(tb_vendor, QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_MAX,
		        nla_data(nl_vendor), nla_len(nl_vendor), NULL);

		struct spectral_caps *caps = (struct spectral_caps*)arg;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_PHYDIAG])
			caps->phydiag_cap = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_RADAR])
			caps->radar_cap = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_SPECTRAL])
			caps->spectral_cap = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_ADVANCED_SPECTRAL])
			caps->advncd_spectral_cap = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HW_GEN])
			caps->hw_gen = nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HW_GEN]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_FORMULA_ID]) {
			caps->is_scaling_params_populated = true;
			caps->formula_id = nla_get_u16(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_FORMULA_ID]);
		} else {
			caps->is_scaling_params_populated = false;
		}

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_LOW_LEVEL_OFFSET])
			caps->low_level_offset = nla_get_u16(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_LOW_LEVEL_OFFSET]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HIGH_LEVEL_OFFSET])
			caps->high_level_offset = nla_get_u16(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HIGH_LEVEL_OFFSET]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_RSSI_THR])
			caps->rssi_thr = nla_get_u16(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_RSSI_THR]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_DEFAULT_AGC_MAX_GAIN])
			caps->default_agc_max_gain = nla_get_u8(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_DEFAULT_AGC_MAX_GAIN]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_AGILE_SPECTRAL])
			caps->agile_spectral_cap = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_AGILE_SPECTRAL_160])
			caps->agile_spectral_cap_160 = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_AGILE_SPECTRAL_80_80])
			caps->agile_spectral_cap_80p80 = 1;

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_20_MHZ])
			caps->num_detectors_20mhz = nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_20_MHZ]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_40_MHZ])
			caps->num_detectors_40mhz = nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_40_MHZ]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80_MHZ])
			caps->num_detectors_80mhz = nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80_MHZ]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_160_MHZ])
			caps->num_detectors_160mhz = nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_160_MHZ]);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80P80_MHZ])
			caps->num_detectors_80p80mhz = nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80P80_MHZ]);
	} else
		perror("vendor data attribute is not there in nl_msg");
	return NL_SKIP;
}
#endif /* UMAC_SUPPORT_CFG80211 */

static int
spectral_get_caps(struct spectralhandler *spectral)
{
    struct spectral_caps *caps = &spectral->caps;
    memset(caps, 0, sizeof(*caps));
    int ret;

#if UMAC_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(spectral)) {
        struct nl_msg *msg =
            nl_prepare_command(
                QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CAP_INFO,
                spectral->atd.ad_name);
        ret =  send_and_recv(info, info->cmd_sock, msg, spectralGetCapInfo_handler, caps);
        if (ret == -EPERM) {
            fprintf(stderr, "Spectral scan feature is disabled for %s\n",
                    spectral->atd.ad_name);
        }
    } else
#endif
    {
        fprintf(stderr, "Get capability command not implemented in WEXT");
        ret = -ENOTSUP;
    }

    return ret;
}

static int
spectralIsAdvncdSpectral(struct spectralhandler *spectral)
{
	struct spectral_caps caps;
	memset(&caps, 0, sizeof(caps));

	#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CAP_INFO,
				spectral->atd.ad_name);
		send_and_recv(info, info->cmd_sock, msg, spectralGetCapInfo_handler, &caps);
	} else
	#endif
	{
		spectral->atd.ad_id = SPECTRAL_GET_CAPABILITY_INFO | ATH_DIAG_DYN;
		spectral->atd.ad_out_data = (void *)&caps;
		spectral->atd.ad_out_size = sizeof(struct spectral_caps);
		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
		                       spectral->s) < 0) {
		    err(1, "%s", spectral->atd.ad_name);
		        spectralAtdClean(spectral);
		    return 0;
		}
		spectralAtdClean(spectral);
	}
	if (caps.advncd_spectral_cap) {
	    return 1;
	} else {
	    return 0;
	}
}



#if 0
static void
spectralGetClassifierParams(struct spectralhandler *spectral, struct spectral_classifier_params *sp)
{
	spectral->atd.ad_id = SPECTRAL_GET_CLASSIFIER_CONFIG | ATH_DIAG_DYN;
	spectral->atd.ad_out_data = (void *) sp;
	spectral->atd.ad_out_size = sizeof(struct spectral_classifier_params);
    if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
                           spectral->s) < 0) {
        err(1, "%s", spectral->atd.ad_name);
    }
}
#endif

void
spectralset(struct spectralhandler *spectral, struct spectral_param *param)
{
	struct spectral_config sp;

	sp.ss_period = HAL_PHYERR_PARAM_NOVAL;
	sp.ss_count = HAL_PHYERR_PARAM_NOVAL;
	sp.ss_fft_period = HAL_PHYERR_PARAM_NOVAL;
	sp.ss_short_report = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_spectral_pri = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_fft_size = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_gc_ena = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_restart_ena = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_noise_floor_ref = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_init_delay = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_nb_tone_thr = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_str_bin_thr = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_wb_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_rssi_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_rssi_thr = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_pwr_format = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_bin_scale = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_dbm_adj = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_chn_mask = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_frequency.cfreq1 = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_frequency.cfreq2 = HAL_PHYERR_PARAM_NOVAL;

	switch(param->id) {
        case SPECTRAL_PARAM_FFT_PERIOD:
            sp.ss_fft_period = param->value;
            break;
        case SPECTRAL_PARAM_SCAN_PERIOD:
            sp.ss_period = param->value;
            break;
        case SPECTRAL_PARAM_SHORT_REPORT:
                if (param->value)
                        sp.ss_short_report = true;
                    else
                        sp.ss_short_report = false;
                    printf("short being set to %d param %d\n", sp.ss_short_report, param->value);
            break;
        case SPECTRAL_PARAM_SCAN_COUNT:
            sp.ss_count = param->value;
            break;

        case SPECTRAL_PARAM_SPECT_PRI:
            sp.ss_spectral_pri = (!!param->value) ? true:false;
            printf("Spectral priority being set to %d\n",sp.ss_spectral_pri);
            break;

        case SPECTRAL_PARAM_FFT_SIZE:
            sp.ss_fft_size = param->value;
            break;

        case SPECTRAL_PARAM_GC_ENA:
            sp.ss_gc_ena = !!param->value;
            printf("gc_ena being set to %u\n",sp.ss_gc_ena);
            break;

        case SPECTRAL_PARAM_RESTART_ENA:
            sp.ss_restart_ena = !!param->value;
            printf("restart_ena being set to %u\n",sp.ss_restart_ena);
            break;

        case SPECTRAL_PARAM_NOISE_FLOOR_REF:
            sp.ss_noise_floor_ref = param->value;
            break;

        case SPECTRAL_PARAM_INIT_DELAY:
            sp.ss_init_delay = param->value;
            break;

        case SPECTRAL_PARAM_NB_TONE_THR:
            sp.ss_nb_tone_thr = param->value;
            break;

        case SPECTRAL_PARAM_STR_BIN_THR:
            sp.ss_str_bin_thr = param->value;
            break;

        case SPECTRAL_PARAM_WB_RPT_MODE:
            sp.ss_wb_rpt_mode = !!param->value;
            printf("wb_rpt_mode being set to %u\n",sp.ss_wb_rpt_mode);
            break;

        case SPECTRAL_PARAM_RSSI_RPT_MODE:
            sp.ss_rssi_rpt_mode = !!param->value;
            printf("rssi_rpt_mode being set to %u\n",sp.ss_rssi_rpt_mode);
            break;

        case SPECTRAL_PARAM_RSSI_THR:
            sp.ss_rssi_thr = param->value;
            break;

        case SPECTRAL_PARAM_PWR_FORMAT:
            sp.ss_pwr_format = !!param->value;
            printf("pwr_format being set to %u\n",sp.ss_pwr_format);
            break;

        case SPECTRAL_PARAM_RPT_MODE:
            sp.ss_rpt_mode = param->value;
            break;

        case SPECTRAL_PARAM_BIN_SCALE:
            sp.ss_bin_scale = param->value;
            break;

        case SPECTRAL_PARAM_DBM_ADJ:
            sp.ss_dbm_adj = !!param->value;
            printf("dBm_adj being set to %u\n",sp.ss_dbm_adj);
            break;

        case SPECTRAL_PARAM_CHN_MASK:
            sp.ss_chn_mask = param->value;
            break;

        case SPECTRAL_PARAM_FREQUENCY:
            sp.ss_frequency.cfreq1 = param->value1;
            sp.ss_frequency.cfreq2 = param->value2;
            break;
    }

	#if UMAC_SUPPORT_CFG80211
	if (IS_CFG80211_ENABLED(spectral)) {
		enum qca_wlan_vendor_spectral_scan_mode nl_mode;
		int ret;
		struct nl_msg *msg =
			nl_prepare_command(
				QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START,
				spectral->atd.ad_name);
		if (!msg) {
			perror("nl_prepare_command failed\n");
			return;
		}

		struct nlattr *data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

		if (!data) {
			fprintf(stderr,"Unable to create a nested Netlink attribute of type %d\n",NL80211_ATTR_VENDOR_DATA);
			nlmsg_free(msg);
			return;
		}

		if (convert_to_cfg80211_spectral_mode(spectral->sscan_mode, &nl_mode)) {
			nlmsg_free(msg);
			return;
		}
		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE_CONFIG);
		nla_put_u32(
			msg,
			QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
			nl_mode);
		if (param->id == SPECTRAL_PARAM_FREQUENCY) {
			nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY, param->value1);
			nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY_2, param->value2);
		} else {
			nla_put_u32(msg, wext_to_cfg_param[param->id], param->value);
		}
		nla_nest_end(msg, data);
		ret = send_and_recv(info, info->cmd_sock, msg, spectralSetThresholds_handler, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to set Spectral parameter\n");
			return;
		}
	} else
	#endif
	{
		spectral->atd.ad_id = SPECTRAL_SET_CONFIG | ATH_DIAG_IN;
		spectral->atd.ad_out_data = NULL;
		spectral->atd.ad_out_size = 0;
		spectral->atd.ad_in_data = (void *) &sp;
		spectral->atd.ad_in_size = sizeof(struct spectral_config);
		if (send_ioctl_command(spectral, spectral->atd.ad_name, (caddr_t)&spectral->atd, sizeof(struct ath_diag),
        	                   spectral->s) < 0) {
        	err(1, "%s", spectral->atd.ad_name);
    		}
		spectralAtdClean(spectral);
	}
}

/*
 * Function     : get_iface_macaddr
 * Description  : Get MAC address of interface
 * Input        : String providing interface name - must fit within IFNAMSIZ,
 *                Total length of the character buffer containing the interface
 *                name - must be atleast IFNAMSIZ,
 *                Buffer into which MAC address should be filled,
 *                Length of MAC address buffer - must be atleast
 *                QDF_MAC_ADDR_SIZE
 *                It is the responsibility of the caller to ensure that the
 *                lengths are correct.
 * Output       : MAC address filled into buffer passed, on success
 * Return       : 0 on success, -1 on failure
 */
static int get_iface_macaddr(const char *ifname, size_t ifname_len,
        u_int8_t *macaddr, size_t macaddr_len)
{
    struct ifreq ifr;
    int fd = 0;

    if (ifname == NULL) {
        fprintf(stderr, "ifname is NULL\n");
        return -1;
    }

    if (ifname_len < IFNAMSIZ) {
        fprintf(stderr, "ifname_len too short. Value=%zu Min expected=%u\n",
                ifname_len, IFNAMSIZ);
        return -1;
    }

    if (sizeof(ifr.ifr_name) < IFNAMSIZ) {
        /*
         * This is highly unlikely. But we explicitly check this to protect the
         * integrity of a strlcpy() involving this.
         */
        fprintf(stderr, "Asserting because of unexpected size of ifr.ifr_name. "
                "Value=%zu Min expected=%u. Investigate!\n",
                sizeof(ifr.ifr_name), IFNAMSIZ);
        assert(0);
    }

    if (macaddr == NULL) {
        fprintf(stderr, "macaddr is NULL\n");
        return -1;
    }

    if (macaddr_len < QDF_MAC_ADDR_SIZE) {
        fprintf(stderr, "macaddr_len too short. Value=%zu Min expected=%u\n",
                macaddr_len, QDF_MAC_ADDR_SIZE);
        return -1;
    }

    if (sizeof(ifr.ifr_hwaddr.sa_data) < QDF_MAC_ADDR_SIZE) {
        /*
         * This is highly unlikely. But we explicitly check this to protect the
         * integrity of a memcpy() involving this.
         */
        fprintf(stderr, "Asserting because of unexpected size of "
                "ifr.ifr_hwaddr.sa_data. Value=%zu Min expected=%u. "
                "Investigate!\n",
                sizeof(ifr.ifr_hwaddr.sa_data), QDF_MAC_ADDR_SIZE);
        assert(0);
    }

    memset(&ifr, 0, sizeof(ifr));

    if (strlcpy(ifr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ifname too long\n");
        return -1;
    }

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd == -1) {
        perror("socket");
        return -1;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(fd);
        return -1;
    }

    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, QDF_MAC_ADDR_SIZE);

    close(fd);
    return 0;
}

/*
 * Function     : is_radio_ifname_valid
 * Description  : Checks whether the Radio interface name given is valid
 * Input        : String with interface name
 * Return       : 1 on success, 0 on failure
 */
int is_radio_ifname_valid(char *radioname)
{
    DIR *dir = NULL;
    int i;
    int wifistr_len = strlen(WIFI_STR);

    if (radioname == NULL)
        return 0;
    /* To validate Radio name, check if it starts with "wifi" and
     * fifth character exists and is a digit.
     */
    if (strncmp(radioname, WIFI_STR, wifistr_len) != 0)
        return 0;

    if (!radioname[wifistr_len] || !isdigit(radioname[wifistr_len]))
        return 0;

    /* No assumptions are made on max no. of radio interfaces,
     * so checking radioname string till IFNAMSIZ
     */
    for (i = wifistr_len + 1; i < IFNAMSIZ; i++)
    {
        if (!radioname[i])
            break;

        if (!isdigit(radioname[i]))
            return 0;
    }

    /* We check whether a directory for given radioname exists
     * in /sys/class/net/. This will help to detect wrong input
     * name of radio interfaces that do not exist.
     */
    dir = opendir(PATH_SYSNET_DEV);
    if (!dir) {
        perror(PATH_SYSNET_DEV);
        return 0;
    }

    while (1)
    {
        struct dirent *dir_entry;
        const char *dir_name;

        dir_entry = readdir(dir);
        if (!dir_entry) {
            /* There are no more entries in this directory, so break
             * out of the while loop.
             */
            break;
        }
        dir_name = dir_entry->d_name;

        if ((dir_entry->d_type & DT_DIR) || (dir_entry->d_type & DT_LNK)) {
            if (strncmp(radioname, dir_name, IFNAMSIZ) == 0) {
                /* Directory for radioname found */
                closedir(dir);
                return 1;
            }
        }
    }

    closedir(dir);
    return 0;
}

static void
usage(void)
{
  fprintf(stderr, "\
      Usage: spectraltool [-i wifiX] [cmd] [cmd_parameter]\n\
           <cmd> = startscan, stopscan, get_advncd, raw_data, diag_stats \n\
                   do not require a param\n\
           <cmd> = fft_period, scan_period, short_report, scan_count, \n\
                   priority, fft_size, gc_ena,restart_ena, noise_floor_ref,\n\
                   init_delay, nb_tone_thr, str_bin_thr, wb_rpt_mode, \n\
                   rssi_rpt_mode, rssi_thr, pwr_format, rpt_mode, bin_scale,\n\
                   dBm_adj, chn_mask, debug, frequency require a param.\n\
                   Some of the above may or may not be available depending on \n\
                   whether advanced Spectral functionality is implemented \n\
                   in hardware, and details are documented in the Spectral \n\
                   configuration parameter description. Use the get_advncd command \n\
                   to determine if advanced Spectral functionality is supported \n\
                   by the interface.\n\
                   Also note that applications such as athssd may not work with \n\
                   some value combinations for the above parameters, or may \n\
                   choose to write values as required by their operation. \n\
           <cmd> = get_samples : Get n samples. Spectral is started and \n\
                   stopped automatically. Mandatory argument after cmd \n\
                   is number of samples n.\n\
                   Optional arguments after number of samples:\n\
                   -l <separation_character>\n\
                   Where separation_character is a single character to be \n\
                   used to separate values in output (e.g. ',' for comma)\n\
                   -x <0/1>\n\
                   To disable (0) or enable (1) generation III linear bin \n\
                   format scaling (default: %s). This is not applicable \n\
                   for other generations.\n\
           <cmd> = dma_ring_debug: Enable(1) or disable(0) the debug of Spectral\n\
                   DMA ring. Head and tail pointers of Spectral DMA ring will be\n\
                   tracked along with the time at which each buffer is\n\
                   received and replenished.\n\
           <cmd> = dma_buff_debug: Enable(1) or disable(0) the debug of Spectral\n\
                   DMA buffers. Spectral buffers will be poisoned before\n\
                   handing them over to the target and will be validated\n\
                   upon arrival, and the target will be asserted upon failure.\n\
           <cmd> = -h : print this usage message\n\
           <cmd> = -p : print description of Spectral configuration parameters.\n",
      SPECTRALTOOL_GEN3_ENABLE_LINEAR_SCALING_DEFAULT ? \
            "enabled" : "disabled");
}

static void
config_param_description(void)
{
	const char *msg = "\
spectraltool: Description of Spectral configuration parameters:\n\
('NA for Advanced': Not available for hardware having advanced Spectral \n\
                    functionality, i.e. 11ac chipsets onwards \n\
 'Advanced Only'  : Available (or exposed) only for hardware having advanced \n\
                    Spectral functionality, i.e. 11ac chipsets onwards) \n\
            fft_period      : Skip interval for FFT reports \n\
                              (NA for Advanced) \n\
            scan_period     : Spectral scan period \n\
            scan_count      : No. of reports to return \n\
            short_report    : Set to report ony 1 set of FFT results \n\
                              (NA for Advanced) \n\
            priority        : Priority \n\
            fft_size        : Defines the number of FFT data points to \n\
                              compute, defined as a log index:\n\
                              num_fft_pts = 2^fft_size \n\
                              (Advanced Only) \n\
            gc_ena          : Set, to enable targeted gain change before \n\
                              starting the spectral scan FFT \n\
                              (Advanced Only) \n\
            restart_ena     : Set, to enable abort of receive frames when \n\
                              in high priority and a spectral scan is queued \n\
                              (Advanced Only) \n\
            noise_floor_ref : Noise floor reference number (signed) for the \n\
                              calculation of bin power (dBm) \n\
                              (Advanced Only) \n\
            init_delay      : Disallow spectral scan triggers after Tx/Rx \n\
                              packets by setting this delay value to \n\
                              roughly  SIFS time period or greater. Delay \n\
                              timer counts in units of 0.25us \n\
                              (Advanced Only) \n\
            nb_tone_thr     : Number of strong bins (inclusive) per \n\
                              sub-channel, below which a signal is declared \n\
                              a narrowband tone \n\
                              (Advanced Only) \n\
            str_bin_thr     : bin/max_bin ratio threshold over which a bin is\n\
                              declared strong (for spectral scan bandwidth \n\
                              analysis). \n\
                              (Advanced Only) \n\
            wb_rpt_mode     : Set this to 1 to report spectral scans as \n\
                              EXT_BLOCKER (phy_error=36), if none of the \n\
                              sub-channels are deemed narrowband. \n\
                              (Advanced Only) \n\
            rssi_rpt_mode   : Set this to 1 to report spectral scans as \n\
                              EXT_BLOCKER (phy_error=36), if the ADC RSSI is \n\
                              below the threshold rssi_thr \n\
                              (Advanced Only) \n\
            rssi_thr        : ADC RSSI must be greater than or equal to this \n\
                              threshold (signed Db) to ensure spectral scan \n\
                              reporting with normal phy error codes (please \n\
                              see rssi_rpt_mode above) \n\
                              (Advanced Only) \n\
            pwr_format      : Format of frequency bin magnitude for spectral \n\
                              scan triggered FFTs: \n\
                              0: linear magnitude \n\
                              1: log magnitude \n\
                                 (20*log10(lin_mag), \n\
                                  1/2 dB step size) \n\
                              (Advanced Only) \n\
            rpt_mode        : Format of per-FFT reports to software for \n\
                              spectral scan triggered FFTs. \n\
                              0: No FFT report \n\
                                 (only pulse end summary) \n\
                              1: 2-dword summary of metrics \n\
                                 for each completed FFT \n\
                              2: 2-dword summary + \n\
                                 1x-oversampled bins(in-band) \n\
                                 per FFT \n\
                              3: 2-dword summary + \n\
                                 2x-oversampled bins (all) \n\
                                 per FFT \n\
                              (Advanced Only) \n\
            bin_scale       : Number of LSBs to shift out to scale the FFT bins \n\
                              for spectral scan triggered FFTs. \n\
                              (Advanced Only) \n\
            dBm_adj         : Set (with pwr_format=1), to report bin \n\
                              magnitudes converted to dBm power using the \n\
                              noisefloor calibration results. \n\
                              (Advanced Only) \n\
            chn_mask        : Per chain enable mask to select input ADC for \n\
                              search FFT. \n\
                              (Advanced Only)\n\
            frequency       : This parameter is applicable only for agile mode. \n\
                              Center frequency (in MHz) of the span of interest\n\
                              or for convenience, center frequency (in MHz) of\n\
                              any channel in the span of interest.\n\
                              (Advanced Only)\n";
	fprintf(stderr, "%s", msg);
}

int
main(int argc, char *argv[])
{
#define	streq(a,b)	(strcasecmp(a,b) == 0)
    char delim;
    bool enable_gen3_linear_scaling =
        SPECTRALTOOL_GEN3_ENABLE_LINEAR_SCALING_DEFAULT;
    struct spectralhandler spectral;
    int advncd_spectral = 0;
    int option_unavbl = 0;
    int ret = 0;
    int rchwidth;
    struct spectral_param param = {0};

    memset(&spectral, 0, sizeof(spectral));
    spectral.mem_utilization_factor = DEFAULT_MEM_UTILIZATION_FACTOR;
    /* Make normal Spectral scan as default mode */
    spectral.sscan_mode = SPECTRAL_SCAN_MODE_NORMAL;

#if UMAC_SUPPORT_CFG80211
    spectral.cfg_flag = get_config_mode_type();
    /* figure out whether cfg80211 is enabled */
    if (argc > 1 && strcmp(argv[1], "-n") == 0) {

	    if (!spectral.cfg_flag ) {
            fprintf(stderr, "Invalid tag '-n' for current mode.\n");
            return -EINVAL;
        }
        spectral.cfg_flag = CONFIG_CFG80211;
        argc -= 1, argv += 1;
    }

    if (IS_CFG80211_ENABLED(&spectral)) {
        /* init cfg80211 socket */
	info = initialize();
	if (info == NULL) {
		printf("Failed to initialize sockets\n");
		return -EINVAL;
	}
	init_wext_to_cfg_param();
    } else
#endif /* UMAC_SUPPORT_CFG80211 */
    {
        spectral.s = socket(AF_INET, SOCK_DGRAM, 0);
        if (spectral.s < 0)
            err(1, "socket");
    }

	if (argc > 1 && strcmp(argv[1], "-i") == 0) {
		if (argc <= 2) {
			fprintf(stderr, "%s: missing interface name for -i\n",
				argv[0]);
			exit(-1);
		}
		if (strlcpy(spectral.atd.ad_name, argv[2],
			sizeof (spectral.atd.ad_name)) >= sizeof (spectral.atd.ad_name)) {
			fprintf(stderr, "%s: interface name too long\n",
					argv[2]);
			exit(-1);
                }
		argc -= 2, argv += 2;
	} else
		strlcpy(spectral.atd.ad_name, ATH_DEFAULT, sizeof (spectral.atd.ad_name));

    if (!is_radio_ifname_valid(spectral.atd.ad_name)) {
        fprintf(stderr, "Radio interface name is incorrect. \n");
        exit(-1);
    }

    if (get_iface_macaddr(spectral.atd.ad_name, sizeof(spectral.atd.ad_name),
            spectral.macaddr, sizeof(spectral.macaddr)) != 0) {
        exit(-1);
    }

    if (spectral_get_caps(&spectral) < 0 ) {
        fprintf(stderr, "Failed to get Spectral scan capability\n");
        ret = EXIT_FAILURE;
        goto cleanup_and_exit;
    }
    advncd_spectral = spectralIsAdvncdSpectral(&spectral);

    if (spectral_get_rchwidth(&spectral, &rchwidth) < 0 ) {
        fprintf(stderr, "Failed to get rchwidth for radio %s\n", spectral.atd.ad_name);
        ret = EXIT_FAILURE;
        goto cleanup_and_exit;
    };
    /* check if agile scan is requested by user */
    if (argc > 1 && strcmp(argv[1], "-a") == 0) {
        if ((rchwidth == IEEE80211_CWM_WIDTH160 && !spectral.caps.agile_spectral_cap_160) ||
            (rchwidth != IEEE80211_CWM_WIDTH160 && !spectral.caps.agile_spectral_cap)) {
            fprintf(stderr,
                    "aSpectral scan is not supported for interface %s\n",
                    spectral.atd.ad_name);
            ret = EXIT_FAILURE;
            goto cleanup_and_exit;
        }
        spectral.sscan_mode = SPECTRAL_SCAN_MODE_AGILE;
        argc -= 1, argv += 1;
    }

	if (argc >= 2) {
        if(streq(argv[1], "fft_period") && (argc == 3)) {
            if (!advncd_spectral) {
                param.id = SPECTRAL_PARAM_FFT_PERIOD;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "scan_period") && (argc == 3)) {
            param.id = SPECTRAL_PARAM_SCAN_PERIOD;
            param.value = (u_int16_t) atoi(argv[2]);
            spectralset(&spectral, &param);
        } else if (streq(argv[1], "short_report") && (argc == 3)) {
            if (!advncd_spectral) {
                param.id = SPECTRAL_PARAM_SHORT_REPORT;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "scan_count") && (argc == 3)) {
            param.id = SPECTRAL_PARAM_SCAN_COUNT;
            param.value = (u_int16_t) atoi(argv[2]);
            spectralset(&spectral, &param);
        } else if (streq(argv[1], "priority") && (argc == 3)) {
            param.id = SPECTRAL_PARAM_SPECT_PRI;
            param.value = (u_int16_t) atoi(argv[2]);
            spectralset(&spectral, &param);
        } else if (streq(argv[1], "fft_size") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_FFT_SIZE;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "gc_ena") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_GC_ENA;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "restart_ena") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_RESTART_ENA;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "noise_floor_ref") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_NOISE_FLOOR_REF;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "init_delay") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_INIT_DELAY;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "nb_tone_thr") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_NB_TONE_THR;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "str_bin_thr") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_STR_BIN_THR;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "wb_rpt_mode") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_WB_RPT_MODE;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "rssi_rpt_mode") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_RSSI_RPT_MODE;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "rssi_thr") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_RSSI_THR;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "pwr_format") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_PWR_FORMAT;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "rpt_mode") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_RPT_MODE;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "bin_scale") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_BIN_SCALE;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "dBm_adj") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_DBM_ADJ;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "chn_mask") && (argc == 3)) {
            if (advncd_spectral) {
                param.id = SPECTRAL_PARAM_CHN_MASK;
                param.value = (u_int16_t) atoi(argv[2]);
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "frequency")) {
            if (advncd_spectral && argc == 4) {
                param.id = SPECTRAL_PARAM_FREQUENCY;
                param.value1 = (u_int32_t) atoi(argv[2]);
                param.value2 = (u_int32_t) atoi(argv[3]);
                spectralset(&spectral, &param);
            } else if (advncd_spectral && argc == 3) {
                param.id = SPECTRAL_PARAM_FREQUENCY;
                param.value1 = (u_int32_t) atoi(argv[2]);
                param.value2 = 0;
                spectralset(&spectral, &param);
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "startscan")) {
            spectralStartScan(&spectral);
        } else if (streq(argv[1], "stopscan")) {
            spectralStopScan(&spectral);
        } else if (streq(argv[1], "debug") && (argc == 3)) {
             spectralSetDebugLevel(&spectral, (u_int32_t)atoi(argv[2]));
        } else if (streq(argv[1], "dma_ring_debug") && (argc == 3)) {
             spectralSetDMADebug(&spectral,
				 SPECTRAL_DMA_RING_DEBUG,
				 (u_int8_t)atoi(argv[2]));
        } else if (streq(argv[1], "dma_buff_debug") && (argc == 3)) {
             spectralSetDMADebug(&spectral,
				 SPECTRAL_DMA_BUFFER_DEBUG,
				 (u_int8_t)atoi(argv[2]));
        } else if (streq(argv[1], "get_advncd")) {
            printf("Advanced Spectral functionality for %s: %s\n",
                   spectral.atd.ad_name,
                   advncd_spectral ? "available":"unavailable");
        } else if (streq(argv[1],"-h")) {
            usage();
        } else if (streq(argv[1],"-p")) {
            config_param_description();
        } else if (streq(argv[1],"raw_data")) {
            ret = spectralGetNSamples(&spectral, 0, 1000, space,
                    enable_gen3_linear_scaling);
        } else if (streq(argv[1],"diag_stats")) {
            spectralPrintDiagStats(&spectral);
            ret = 0;
        } else if (streq(argv[1],"get_samples") &&
                    ((argc == 3) || (argc == 5) || (argc == 7))) {
            delim = space;

            if (argc >= 5) {
                if (streq(argv[3], "-l")) {
                    delim = *argv[4];
                } else if (streq(argv[3], "-x")) {
                    enable_gen3_linear_scaling = !!atoi(argv[4]);
                } else {
                    fprintf(stderr, "Invalid command option used for "
                                    "spectraltool.\n");
                    usage();
                    goto cleanup_and_exit;
                }
            }

            if (argc == 7) {
                if (streq(argv[5], "-l")) {
                    delim = *argv[6];
                } else if (streq(argv[5], "-x")) {
                    enable_gen3_linear_scaling = !!atoi(argv[6]);
                } else {
                    fprintf(stderr, "Invalid command option used for "
                                    "spectraltool.\n");
                    usage();
                    goto cleanup_and_exit;
                }
            }

            if ((spectral.caps.hw_gen !=
                        QCA_WLAN_VENDOR_SPECTRAL_SCAN_CAP_HW_GEN_3) &&
                enable_gen3_linear_scaling) {
                fprintf(stderr,
                        "Gen3 linear scaling inapplicable for this radio.\n");
                usage();
                goto cleanup_and_exit;
            }

            ret = spectralGetNSamples(&spectral, 1, (u_int32_t)atoi(argv[2]),
                    delim, enable_gen3_linear_scaling);
        } else {
            fprintf(stderr,
                    "Invalid command option used for spectraltool\n");
            usage();
        }

        if (option_unavbl) {
                fprintf(stderr,
                        "Command option unavailable for interface %s\n",
                        spectral.atd.ad_name);
                usage();
        }
	} else if (argc == 1) {
	struct spectral_config sp;
        char *period_unit;
        memset(&sp, 0, sizeof(sp));
        period_unit = ((spectral.caps.hw_gen ==
            QCA_WLAN_VENDOR_SPECTRAL_SCAN_CAP_HW_GEN_3) ? " us" : "*256*Tclk us");
        printf ("SPECTRAL PARAMS\n");
	spectralGetStatus(&spectral);
        spectralGetThresholds(&spectral, &sp);
        if (!advncd_spectral) {
            printf ("fft_period:  %d\n",sp.ss_fft_period);
        }
        printf ("scan_period: %d%s\n",sp.ss_period, period_unit);
        printf ("scan_count: %d\n",sp.ss_count);
        if (!advncd_spectral) {
            printf ("short_report: %s\n",(sp.ss_short_report) ? "yes":"no");
        }
        printf ("priority: %s\n",(sp.ss_spectral_pri) ? "enabled":"disabled");

        if (advncd_spectral) {
             printf ("fft_size: %u\n", sp.ss_fft_size);
             printf ("gc_ena: %s\n",
                     (sp.ss_gc_ena) ? "enabled":"disabled");
             printf ("restart_ena: %s\n",
                     (sp.ss_restart_ena) ? "enabled":"disabled");
             printf ("noise_floor_ref: %d\n",(int8_t)sp.ss_noise_floor_ref);
             printf ("init_delay: %u\n",sp.ss_init_delay);
             printf ("nb_tone_thr: %u\n",sp.ss_nb_tone_thr);
             printf ("str_bin_thr: %u\n",sp.ss_str_bin_thr);
             printf ("wb_rpt_mode: %u\n",sp.ss_wb_rpt_mode);
             printf ("rssi_rpt_mode: %u\n",sp.ss_rssi_rpt_mode);
             printf ("rssi_thr: %d\n",(int8_t)sp.ss_rssi_thr);
             printf ("pwr_format: %u\n",sp.ss_pwr_format);
             printf ("rpt_mode: %u\n",sp.ss_rpt_mode);
             printf ("bin_scale: %u\n",sp.ss_bin_scale);
             printf ("dBm_adj: %u\n",sp.ss_dbm_adj);
             printf ("chn_mask: %u\n",sp.ss_chn_mask);
             printf ("frequency: %u, %u\n", sp.ss_frequency.cfreq1,
                     sp.ss_frequency.cfreq2);
        }

    } else {
		usage ();
	}

cleanup_and_exit:

#if UMAC_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(&spectral)) {
	if (info)
	{
		if (info->sock_fd >= 0)
			close(info->sock_fd);

		if (info->nl_cb)
			nl_cb_put(info->nl_cb);

		if (info->cmd_sock)
			nl_socket_free(info->cmd_sock);

		free(info);
	}
    } else
#endif /* UMAC_SUPPORT_CFG80211 */
    {
        close(spectral.s);
    }
	return ret;
}
