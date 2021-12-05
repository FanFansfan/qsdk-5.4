/*
 * Copyright (c) 2016, 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef _CFG80211_NLWRAPPER_H__
#define _CFG80211_NLWRAPPER_H__

typedef struct wifi_cfg80211_t {
	/* command socket object */
	struct nl_sock *cmd_sock;
	struct nl_sock *event_sock;
	/* private command socket ids*/
	int pvt_cmd_sock_id;
	int pvt_event_sock_id;
	/* family id for 80211 driver */
	int nl80211_family_id;
	void (*event_callback)(char *ifname, uint32_t subcmd, uint8_t *data,
			size_t len);
	pthread_t event_thread_handle;
	volatile int event_thread_running;
} wifi_cfg80211_context;

/* cfg80211 nlwrapper context that needs to be paseed when sending command */
struct cfg80211_data {

	void *data; /* data pointer */
	void *nl_vendordata; /* vendor data */
	unsigned int nl_vendordata_len; /* vendor data length */
	unsigned int length; /* data length */
	unsigned int flags; /* flags for data */
	unsigned int parse_data; /* 1 - data parsed by caller 0- data parsed by wrapper */
	/* callback that needs to be called when data recevied from driver */
	void (*callback) (struct cfg80211_data *);
};

#define NL80211_ATTR_32BIT 0x00000001
#define NL80211_ATTR_8BIT  0x00000010
/* nlwrapper specific data that needs to be passed when using std command */
struct nlwrapper_data {
	unsigned int cmd;        /* NL80211 cmd */
	unsigned int attr;       /* NL80211 attr */
	unsigned int value;      /* attr value */
	unsigned int flags;      /* flags */
};

/**
 * wifi_init_nl80211: initiliaze nlsocket
 * @ctx: wifi cfg80211 context
 *
 * return 1/0
 */
int wifi_init_nl80211(wifi_cfg80211_context *ctx);

/**
 * wifi_nl80211_start_event_thread: Start the thread which processes
 *                                  the async netlink events
 * @ctx: wifi cfg80211 context
 *
 * return 1/0
 */
int wifi_nl80211_start_event_thread(wifi_cfg80211_context *ctx);

/**
 * wifi_destroy_nl80211: destroy nl80211 socket
 * @ctx: wifi cfg80211 context
 *
 * return 1/0
 */
void wifi_destroy_nl80211(wifi_cfg80211_context *ctx);

/**
 * wifi_cfg80211_send_getparam_command: sends getparm command
 * @ctx: pointer to wifi_cfg80211_context
 * @cmdid: command id
 * @param: param (enum) for which value need to be retrived.
 * @ifname: interface name
 * @buffer: buffer data
 * @len: length
 *
 * return NL state.
 */
int wifi_cfg80211_send_getparam_command(wifi_cfg80211_context *ctx, int cmdid,
        int param, const char *ifname, char *buffer, int len);

/**
 * wifi_cfg80211_send_setparam_command: sends setparm command
 * @ctx: pointer to wifi_cfg80211_context
 * @cmdid: command id
 * @param: param (enum) for which value need to be set.
 * @ifname: interface name
 * @buffer: buffer data
 * @len: length
 *
 * return NL state.
 */
int wifi_cfg80211_send_setparam_command(wifi_cfg80211_context *ctx, int cmdid,
        int param, const char *ifname, char *buffer, int len);

/**
 * wifi_cfg80211_sendcmd: sends cfg80211 sendcmd
 * @ctx: pointer to wifi_cfg80211_context
 * @cmdid: command id
 * @ifname: interface name
 * @buffer: buffer data
 * @len: length
 *
 * return NL state.
 */
int wifi_cfg80211_sendcmd(wifi_cfg80211_context *ctx, int cmdid, const char *ifname,
		char *buffer, int len);

/**
 * wifi_cfg80211_user_send_geneic_command: sends cfg80211 sendcmd.
 * @ctx: pointer to wifi_cfg80211_context.
 * @vendor_command: vendor command.
 * @cmdid : internal command id.
 * @value : Data to fill in "value" filed of NL message.
 * @ifname: interface name.
 * @buffer: Buffer to fill in "data" filed of NL message.
 * @len    : Length to fill in "length" filed of NL message.
 * return NL state.
 */
int wifi_cfg80211_user_send_generic_command(wifi_cfg80211_context *ctx,
					    int vendor_command, int cmdid,
					    int value, const char *ifname,
					    char *buffer, uint32_t len);
/**
 * wifi_cfg80211_send_geneic_command: sends cfg80211 sendcmd
 * @ctx: pointer to wifi_cfg80211_context
 * @vendor_command: vendor command
 * @cmdid: internal command id
 * @ifname: interface name
 *
 * return NL state.
 */
int wifi_cfg80211_send_generic_command(wifi_cfg80211_context *ctx, int vendor_command, int cmdid, const char *ifname, char *buffer, int len);
/**
 * wifi_cfg80211_prepare_command: prepare cfg80211 command and return nl_msg to called
 * caller need to populate data.
 * @ctx: pointer to wifi_cfg80211_context
 * @cmdid: command id
 * @ifname: interface name
 *
 * return nl_msg pointer
 */

struct nl_msg *wifi_cfg80211_prepare_command(wifi_cfg80211_context *ctx, int cmdid, const char *ifname);

/**
 * send_nlmsg: send nlmsg to kernel.
 * caller need to populate data.
 * @ctx: pointer to wifi_cfg80211_context
 * @nlmsg: pointer to nl message.
 * @date: pointer to data
 *
 * return nl_msg pointer
 */

int send_nlmsg(wifi_cfg80211_context *ctx, struct nl_msg *nlmsg, void *data);

struct nlattr *start_vendor_data(struct nl_msg *nlmsg);
void end_vendor_data(struct nl_msg *nlmsg, struct nlattr *attr);

 /**
 * wifi_cfg80211_send_nl80211_standard_command: send cfg80211 send standard cmd
 * @ctx: pointer to wifi_cfg80211_context
 * @wifi_name: wifi interface name
 * @vap_name: vap interface name
 * @buffer: nlwrapper data buffer
 *
 * return NL state.
 */

int wifi_cfg80211_send_nl80211_standard_command(wifi_cfg80211_context *ctx,
	uint8_t *wifi_name,uint8_t *vap_name, char *buffer);

#endif
