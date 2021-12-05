/*
 * Copyright (c) 2011, 2017-2021 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros Inc.
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
 * Description:  Simple application to retrieve AP statistics at the AP level,
 *               Per-Radio level, Per-VAP level, and Per-Node level.
 *               Note: There are a variety of statistics which can be
 *               considered to fall under AP statistics. However, we limit
 *               ourselves to specific stats requested by customers. As further
 *               requests come in, this application can be expanded.
 *
 * Version    :  0.1
 * Created    :  Thursday, June 30, 2011
 * Revision   :  none
 * Compiler   :  gcc
 *
 */

#include <apstats.h>
#if UMAC_SUPPORT_CFG80211
#include <netlink/attr.h>
#endif

#include <cdp_txrx_stats_struct.h>
#if BUILD_X86
#include <qcatools_lib.h>
#endif

#define DESC_FIELD_PROVISIONING         31
#define LIST_STATION_CFG_ALLOC_SIZE 3*1024

#define APSTATS_NL80211_CMD_SOCK_ID  DEFAULT_NL80211_CMD_SOCK_ID
#define APSTATS_NL80211_EVENT_SOCK_ID  DEFAULT_NL80211_EVENT_SOCK_ID

#define APSTATS_ERROR(fmt, args...) \
    fprintf(stderr, "apstats: Error - "fmt , ## args)

#define APSTATS_WARNING(fmt, args...) \
    fprintf(stdout, "apstats: Warning - "fmt , ## args)

#define APSTATS_MESG(fmt, args...) \
    fprintf(stdout, "apstats: "fmt , ## args)

#define APSTATS_PRINT_GENERAL(fp, fmt, args...) \
    fprintf(fp, fmt , ## args)

#define APSTATS_PRINT_STAT64(fp, descr, x) \
    fprintf(fp, "%-*s = %"PRIu64"\n", DESC_FIELD_PROVISIONING, (descr), (x))

#define APSTATS_PRINT_STAT32(fp, descr, x) \
    fprintf(fp, "%-*s = %u\n", DESC_FIELD_PROVISIONING, (descr), (x))

#define APSTATS_PRINT_STAT16(fp, descr, x) \
    fprintf(fp, "%-*s = %hu\n", DESC_FIELD_PROVISIONING, (descr), (x))

#define APSTATS_PRINT_STAT16_SIGNED(fp, descr, x) \
    fprintf(fp, "%-*s = %hi\n", DESC_FIELD_PROVISIONING, (descr), (x))

#define APSTATS_PRINT_STAT8(fp, descr, x) \
    fprintf(fp, "%-*s = %hhu\n", DESC_FIELD_PROVISIONING, (descr), (x))

#define APSTATS_PRINT_STATFLT(fp, descr, x, precsn) \
    fprintf(fp, "%-*s = %.*f\n", DESC_FIELD_PROVISIONING, (descr), \
            (precsn), (x))

#define APSTATS_PRINT_STAT_UNVLBL(fp, descr, msg) \
    fprintf(fp, "%-*s = %s\n", DESC_FIELD_PROVISIONING, (descr), (msg))

#if !UMAC_SUPPORT_TXDATAPATH_NODESTATS
#define APSTATS_TXDPATH_NODESTATS_UNVLBL_MSG  "<Unavailable (Tx datapath " \
    "performance optimization)>"
#endif

static const unsigned NL80211_ATTR_MAX_INTERNAL = 256;
static int cfg_flag = 0;
static vaplevel_stats_t *head_vapstats = NULL;
struct socket_context sock_ctx = {0};

#if UMAC_SUPPORT_CFG80211
enum qca_wlan_get_params {
    QCA_WLAN_VENDOR_ATTR_GETPARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_GETPARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_GETPARAM_MAX =
        QCA_WLAN_VENDOR_ATTR_GETPARAM_LAST - 1
};

struct nla_policy
wlan_cfg80211_get_params_policy[QCA_WLAN_VENDOR_ATTR_GETPARAM_MAX + 1] = {

    [QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND] = {.type = NLA_U32 },
};
#endif
static int ap_send_command (const char *ifname, void *buf, size_t buflen, int cmd, unsigned int ioctl_cmd);

#ifndef APSTATS_API
/* Options processing */
static const char *optString = "argwvsi:m:RMhn?";
#endif
int display_mesh_stats = 0;

static const struct option longOpts[] = {
    { "aplevel", no_argument, NULL, 'a' },              /* Default */
    { "radiolevel", no_argument, NULL, 'r' },
    { "vaplevel", no_argument, NULL, 'v' },
    { "stalevel", no_argument, NULL, 's' },
    { "ifname", required_argument, NULL, 'i' },
    { "stamacaddr", required_argument, NULL, 'm' },
    { "recursive", no_argument, NULL, 'R' },            /* Default */
    { "help", no_argument, NULL, 'h' },
    { NULL, no_argument, NULL, 0 },
};

char *ieee80211_phymode_str[IEEE80211_MODE_MAX+1] =  {
    "IEEE80211_MODE_AUTO",
    "IEEE80211_MODE_11A",
    "IEEE80211_MODE_11B",
    "IEEE80211_MODE_11G",
    "IEEE80211_MODE_FH",
    "IEEE80211_MODE_TURBO_A",
    "IEEE80211_MODE_TURBO_G",
    "IEEE80211_MODE_11NA_HT20",
    "IEEE80211_MODE_11NG_HT20",
    "IEEE80211_MODE_11NA_HT40PLUS",
    "IEEE80211_MODE_11NA_HT40MINUS",
    "IEEE80211_MODE_11NG_HT40PLUS",
    "IEEE80211_MODE_11NG_HT40MINUS",
    "IEEE80211_MODE_11NG_HT40",
    "IEEE80211_MODE_11NA_HT40",
    "IEEE80211_MODE_11AC_VHT20",
    "IEEE80211_MODE_11AC_VHT40PLUS",
    "IEEE80211_MODE_11AC_VHT40MINUS",
    "IEEE80211_MODE_11AC_VHT40",
    "IEEE80211_MODE_11AC_VHT80",
    "IEEE80211_MODE_11AC_VHT160",
    "IEEE80211_MODE_11AC_VHT80_80",
    "IEEE80211_MODE_11AXA_HE20",
    "IEEE80211_MODE_11AXG_HE20",
    "IEEE80211_MODE_11AXA_HE40PLUS",
    "IEEE80211_MODE_11AXA_HE40MINUS",
    "IEEE80211_MODE_11AXG_HE40PLUS",
    "IEEE80211_MODE_11AXG_HE40MINUS",
    "IEEE80211_MODE_11AXA_HE40",
    "IEEE80211_MODE_11AXG_HE40",
    "IEEE80211_MODE_11AXA_HE80",
    "IEEE80211_MODE_11AXA_HE160",
    "IEEE80211_MODE_11AXA_HE80_80",
    (char *)NULL,
};

#define ATH_IOCTL_GETPARAM  (SIOCIWFIRSTPRIV + 1)

#define APSTATS_VERSION     "0.1"

#define PATH_PROCNET_DEV    "/proc/net/dev"
#define PATH_SYSNET_DEV     "/sys/class/net/"

/* Rates in kbps */
#define RATE_10K_KBPS       (10000)
#define RATE_100K_KBPS      (100000)
#define RATE_1000K_KBPS     (1000000)

/* Structure to hold radio and VAP names read from /proc */
typedef struct
{
    char **ifnames;
    int max_size;
    int curr_size;
} sys_ifnames;

static int sys_ifnames_init(sys_ifnames *ifs, int base_max_size);
static int sys_ifnames_extend(sys_ifnames *ifs, int additional_size);
static void sys_ifnames_deinit(sys_ifnames *ifs);
static int sys_ifnames_add(sys_ifnames *ifs, char *ifname);

#ifndef APSTATS_API
static int apstats_config_init(apstats_config_t *config);
static int apstats_config_populate(apstats_config_t *config,
                            const apstats_level_t level,
                            const bool recursion,
                            const char *ifname,
                            const char *stamacaddr);

static void display_help();
#endif

static int is_radio_ifname_valid(const char *ifname);
static int is_vap_ifname_valid(const char *ifname);

static int is_vap_radiochild(vaplevel_stats_t *vapstats,
        radiolevel_stats_t *radiostats);
static int nodestats_hierarchy_init(vaplevel_stats_t *apstats, int sockfd);
static int stats_hierachy_init(aplevel_stats_t *apstats, int sockfd);
static radiolevel_stats_t* stats_hierarchy_findradio(aplevel_stats_t *apstats,
        char *ifname);
static vaplevel_stats_t* stats_hierarchy_findvap(aplevel_stats_t *apstats,
        char *ifname);
static nodelevel_stats_t*
stats_hierarchy_findnode(aplevel_stats_t *apstats,
        struct ether_addr *stamacaddr);
static int stats_hierachy_deinit(aplevel_stats_t *apstats);

static int get_vap_priv_int_param(int sockfd, const char *ifname, int param);
static int get_radio_priv_int_param(int sockfd, const char *ifname, int param);

static int aplevel_gather_stats(int sockfd,
        aplevel_stats_t *apstats, bool recursion);
static int aplevel_display_stats(FILE *fp, aplevel_stats_t *apstats,
        bool recursion);
static int radiolevel_gather_stats(int sockfd,
        radiolevel_stats_t *radiostats, bool is_recursion);
static int radiolevel_display_stats(FILE *fp, radiolevel_stats_t *radiostats,
        bool recursion);
static int vaplevel_gather_stats(int sockfd,
        vaplevel_stats_t *vapstats, bool is_recursion);
static int vaplevel_display_stats(FILE *fp, vaplevel_stats_t *vapstats,
        bool recursion);
static int nodelevel_gather_stats(int sockfd,
        nodelevel_stats_t *nodestats);
static char* macaddr_to_str(const struct ether_addr *addr);
static int nodelevel_display_stats(FILE *fp, nodelevel_stats_t *nodestats);

#ifndef APSTATS_API
static int aplevel_handler(FILE *fp, int sockfd,
        aplevel_stats_t *apstats,
        bool recursion);
static int radiolevel_handler(FILE *fp, int sockfd,
        radiolevel_stats_t *radiostats,
        bool recursion);
static int vaplevel_handler(FILE *fp, int sockfd,
        vaplevel_stats_t *vapstats,
        bool recursion);
static int nodelevel_handler(FILE *fp, int sockfd,
        nodelevel_stats_t *nodestats);
static int apstats_main(apstats_config_t *config);
#endif

/**
 * ap_send_command; function to send the cfg commandggggioctl command.
 * @ifname :interface name
 * @buf: buffer
 * @buflen : buffer length
 * @cmd : command type
 * @ioctl_cmd: ioctl command type
 * return : 0 for success
 */
static int ap_send_command (const char *ifname, void *buf, size_t buflen, int cmd, unsigned int ioctl_cmd)
{
#if UMAC_SUPPORT_WEXT
    struct ifreq ifr;
    int sock_fd, err;
#endif
#if UMAC_SUPPORT_CFG80211
    int msg;
    struct cfg80211_data buffer;
#endif
    if (cfg_flag) {
#if UMAC_SUPPORT_CFG80211
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                cmd, ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            fprintf(stderr,"Couldn't send NL command\n");
            return -EIO;
        }
        return buffer.flags;
#endif
    } else {
#if UMAC_SUPPORT_WEXT
        sock_fd = sock_ctx.sock_fd;
        if (strlcpy(ifr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
            fprintf(stderr,"Error creating ifname \n");
            return -1;
        }
        ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
        ifr.ifr_data = buf;
        err = ioctl(sock_fd, ioctl_cmd, &ifr);
        if (err < 0) {
            fprintf(stderr,"send command failed: %d \n", ioctl_cmd);
            return -EIO;
        }
#endif
    }

    return 0;
}

/* We assume ifname has atleast IFNAMSIZ characters,
   as is the convention for Linux interface names. */
static int is_radio_ifname_valid(const char *ifname)
{
    int i;

    assert(ifname != NULL);

    /*
     * At this step, we only validate if the string makes sense.
     * If the interface doesn't actually exist, we'll throw an
     * error at the place where we make system calls to try and
     * use the interface.
     * Reduces the no. of ioctl calls.
     */

    if (strncmp(ifname, "wifi", 4) != 0) {
        return 0;
    }

    if (!ifname[4] || !isdigit(ifname[4])) {
        return 0;
    }

    /*
     * We don't make any assumptions on max no. of radio interfaces,
     * at this step.
     */
    for (i = 5; i < IFNAMSIZ; i++)
    {
        if (!ifname[i]) {
            break;
        }

        if (!isdigit(ifname[i])) {
            return 0;
        }
    }

    return 1;
}

/* We assume ifname has atleast IFNAMSIZ characters,
   as is the convention for Linux interface names. */
static int is_vap_ifname_valid(const char *ifname)
{
    char path[100];
    FILE *fp;
    ssize_t bufsize = sizeof(path);

    assert(ifname != NULL);

    if ((strlcpy(path, PATH_SYSNET_DEV, bufsize) >= bufsize)
            || (strlcat(path, ifname, bufsize) >= bufsize)
            || (strlcat(path, "/parent", bufsize) >= bufsize)) {
        APSTATS_ERROR("%s(): %d Error creating pathname \n",
                __func__, __LINE__);
        return -1;
    }

    if ((fp = fopen(path, "r"))) {
        fclose(fp);
        return 1;
    }
    return 0;
}


#ifndef APSTATS_API
static void display_help()
{
    printf("\napstats v"APSTATS_VERSION": Display Access Point Statistics.\n"
            "\n"
            "Usage:\n"
            "\n"
            "apstats [Level] [[-i interface_name] | [-m STA_MAC_Address]] [-R]  \n"
            "\n"
            "One of four levels can be selected. The levels are as follows (from \n"
            "the top to the bottom of the hierarchy): \n"
            "Entire Access Point, Radio, VAP and STA. \n"
            "The default is Entire Access Point. Information for sub-levels below \n"
            "the selected level can be displayed by choosing the -R (recursive) \n"
            "option (not applicable for the STA level, where information for a \n"
            "single STA is displayed). \n"
            "\n"
            "LEVELS:\n"
            "\n"
            "-a or --aplevel\n"
            "    Entire Access Point Level (WLAN).\n"
            "    No Interface or STA MAC needs to be provided.\n"
            "\n"
            "-r or --radiolevel\n"
            "    Radio Level.\n"
            "    Radio Interface Name needs to be provided.\n"
            "\n"
            "-v or --vaplevel\n"
            "    VAP Level.\n"
            "    VAP Interface Name needs to be provided.\n"
            "\n"
            "-s or --stalevel\n"
            "    STA Level.\n"
            "    STA MAC Address needs to be provided.\n"
            "\n"
            "INTERFACE:\n"
            "\n"
            "If Radio Level is selected:\n"
            "-i wifiX or --ifname=wifiX\n"
            "\n"
            "If VAP Level is selected:\n"
            "-i <VAP_name> or --ifname=<VAP_name>\n"
            "\n"
            "STA MAC ADDRESS:\n"
            "\n"
            "Required if STA Level is selected:\n"
            "-m xx:xx:xx:xx:xx:xx or --stamacaddr xx:xx:xx:xx:xx:xx\n"
            "\n"
            "OTHER OPTIONS:\n"
            "-R or --recursive\n"
            "    Recursive display\n"
            "-M Mesh stats\n"
            );
}
#endif

/*
 * Determine if VAP with given H/W address is the child of
 * radio with given H/W address.
 * To determine this, we check if the last 5 octets are the same.
 * Incase of proxy STA vap check for the parent name
 */
static int is_vap_radiochild(vaplevel_stats_t *vapstats,
        radiolevel_stats_t *radiostats)
{
    char path[100];
    char parent[IFNAMSIZ];
    const char *radioname = radiostats->ifname;
    FILE *fp;
    ssize_t bufsize = sizeof(path);

    /* Last 5 bytes of macaddr of all vap inside same radio should match */
    if (!memcmp(&(vapstats->macaddr[1]), &(radiostats->macaddr[1]), 5))
        return 1;

    if ((strlcpy(path, PATH_SYSNET_DEV, bufsize) >= bufsize)
            || (strlcat(path, vapstats->ifname, bufsize) >= bufsize)
            || (strlcat(path, "/parent", bufsize) >= bufsize)) {
        APSTATS_ERROR("%s(): %d Error creating pathname \n",
                __func__, __LINE__);
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL)
        return 0;

    fgets(parent, IFNAMSIZ, fp);
    fclose(fp);

    if (strncmp(parent, radioname, 5) == 0)
        return 1;

    return 0;

}

int sys_ifnames_init(sys_ifnames *ifs, int base_max_size)
{
    int i;

    assert(ifs != NULL);

    ifs->ifnames = (char**)malloc(base_max_size * sizeof(char*));
    if (!(ifs->ifnames)) {
        return -ENOMEM;
    }

    ifs->curr_size = 0;

    for (i = 0; i < base_max_size; i++) {
        ifs->ifnames[i] = (char*)malloc(IFNAMSIZ * sizeof(char));
        if (!(ifs->ifnames[i])) {
            sys_ifnames_deinit(ifs);
            return -1;
        }
        ifs->max_size += 1;
    }

    return 0;
}

int sys_ifnames_extend(sys_ifnames *ifs, int additional_size)
{
    int i;
    char **tempptr;
    int size = 0;
    assert(ifs != NULL);

    tempptr = (char**)realloc(ifs->ifnames,
            (ifs->max_size + additional_size) * sizeof(char *));

    if (!tempptr) {
        /* Original block untouched */
        return -ENOMEM;
    }

    ifs->ifnames = tempptr;
    size = ifs->max_size + additional_size;

    for (i = ifs->max_size; i < size; i++) {
        ifs->ifnames[i] = (char*)malloc(IFNAMSIZ * sizeof(char));

        if (!(ifs->ifnames[i])) {
            return -ENOMEM;
        }
        ifs->max_size += 1;
    }
    return 0;
}

void sys_ifnames_deinit(sys_ifnames *ifs)
{
    int i;

    assert(ifs != NULL);

    if (!ifs->ifnames) {
        return;
    }

    for (i = 0; i < ifs->max_size; i++) {
        free(ifs->ifnames[i]);
    }

    free(ifs->ifnames);
    ifs->ifnames = NULL;
    ifs->max_size = 0;
    ifs->curr_size = 0;
}

int sys_ifnames_add(sys_ifnames *ifs, char *ifname)
{
    int tempidx = 0;

    if (ifs->curr_size == ifs->max_size) {
        // Full
        return -ENOMEM;
    }

    tempidx = ifs->curr_size;
    memset(ifs->ifnames[tempidx], '\0', IFNAMSIZ);
    if (strlcpy(ifs->ifnames[tempidx], ifname, IFNAMSIZ) >= IFNAMSIZ) {
        APSTATS_ERROR("%s(): %d Error creating ifname \n",
                __func__, __LINE__);
        return -1;
    }
    ifs->curr_size++;
    return 0;
}

#if UMAC_SUPPORT_CFG80211
static void get_sta_info(struct cfg80211_data *buffer)
{
    u_int8_t *buf = NULL, *cp = NULL;
    struct ieee80211req_sta_info *si = NULL;
    nodelevel_stats_t *curr_ns_ptr = NULL;
    int remaining_len = 0;
    buf = buffer->data;

    /*
     * buffer->length is actual data length recevied from driver
     */
    remaining_len = buffer->length;
    cp = buf;

    /* Return if the length of the buffer is less than sta_info */
    if (remaining_len < sizeof(struct ieee80211req_sta_info)) {
        return;
    }

    do {
        si = (struct ieee80211req_sta_info *) cp;

        nodelevel_stats_t *nodestats =
            (nodelevel_stats_t *)malloc(sizeof(nodelevel_stats_t));

        if (NULL == nodestats) {
            APSTATS_ERROR("Unable to allocate memory for node stats\n");
            free(buf);
            /* For now, the caller of stats_hierachy_init() is expected to
               call stats_hierachy_deinit() to clean up the linked
               list under apstats */
            return ;
        }
        memset(nodestats, 0 , sizeof(nodelevel_stats_t));
        nodestats->obj.level = APSTATS_LEVEL_NODE;
        nodestats->obj.subtree_root = 0;
        memcpy(nodestats->macaddr.ether_addr_octet,
                si->isi_macaddr,
                QDF_MAC_ADDR_SIZE);

        /* As an optimization, copy ieee80211req_sta_info right
           away. */
        memcpy(&nodestats->si, si, sizeof(struct ieee80211req_sta_info));

        nodestats->obj.parent = head_vapstats;

        if (!head_vapstats->obj.firstchild) {
            head_vapstats->obj.firstchild = nodestats;
        } else {
            curr_ns_ptr = (nodelevel_stats_t*)head_vapstats->obj.firstchild;

            while(curr_ns_ptr->obj.next != NULL)
            {
                curr_ns_ptr = curr_ns_ptr->obj.next;
            }

            curr_ns_ptr->obj.next = nodestats;
            nodestats->obj.prev = curr_ns_ptr;
        }

        cp += si->isi_len, remaining_len -= si->isi_len;
    } while (remaining_len >= sizeof(struct ieee80211req_sta_info));

    /*
     * when application requires multiple callbacks from driver, restore
     * buffer->length to max expected length to make sure libqca_nl80211 library
     * sends valid data to the sub sequent call backs.
     */
    buffer->length = LIST_STATION_CFG_ALLOC_SIZE;

}
#endif

/* Helper function to help stats_hierachy_init() fill node level information.*/
#define EXPECTED_MAX_NODES_PERVAP       (50)
#define EXPECTED_NODES_PERVAP_INCREMENT (10)
static int nodestats_hierarchy_init(vaplevel_stats_t *vapstats, int sockfd)
{
    struct iwreq iwr;
    u_int8_t *buf = NULL, *cp = NULL, *tempptr = NULL;
    struct ieee80211req_sta_info *si = NULL;
    nodelevel_stats_t *curr_ns_ptr = NULL;
    int buflen = 0;
    int remaining_len = 0;
    int ret;
    u_int32_t opmode;
#if UMAC_SUPPORT_CFG80211
    struct cfg80211_data buffer;
#endif
    buflen = sizeof(struct ieee80211req_sta_info) *
        EXPECTED_MAX_NODES_PERVAP;

    buf = (u_int8_t*)malloc(buflen);
    if (NULL == buf) {
        APSTATS_ERROR("Unable to allocate memory for node information\n");
        return -ENOMEM;
    }
    if (!cfg_flag) {
#if UMAC_SUPPORT_WEXT
        memset(&iwr, 0, sizeof(iwr));
        if (strlcpy(iwr.ifr_name, vapstats->ifname, sizeof(iwr.ifr_name))
                >= sizeof(iwr.ifr_name)) {
            APSTATS_ERROR("%s(): %d Error creating ifname \n",
                    __func__, __LINE__);
            free(buf);
            return -1;
        }
        iwr.u.data.pointer = (void *)buf;
        iwr.u.data.length = buflen;
        if ((ret = ioctl(sockfd, IEEE80211_IOCTL_STA_INFO, &iwr)) < 0) {
            perror("IEEE80211_IOCTL_STA_INFO");
            free(buf);
            return ret;
        }

        if (0 == iwr.u.data.length) {
            free(buf);
            return 0;
        }
        /* Failed case is that no change in data.length */
        while (iwr.u.data.length == buflen)
        {
            /* Attempt to find the required buffer size */
            buflen += EXPECTED_NODES_PERVAP_INCREMENT;
            tempptr = (u_int8_t*)realloc(buf, buflen);
            if (NULL == tempptr) {
                APSTATS_ERROR("Unable to allocate memory for node information\n");
                free(buf);
                return -ENOMEM;
            }
            buf = tempptr;

            iwr.u.data.pointer = (void *)buf;
            iwr.u.data.length = buflen;

            if ((ret = ioctl(sockfd, IEEE80211_IOCTL_STA_INFO, &iwr)) < 0) {
                perror("IEEE80211_IOCTL_STA_INFO");
                free(buf);
                return ret;
            }
        }

        remaining_len = iwr.u.data.length;
        if (remaining_len >= sizeof(struct ieee80211req_sta_info)) {
            cp = buf;
            do {
                si = (struct ieee80211req_sta_info *) cp;

                nodelevel_stats_t *nodestats =
                    (nodelevel_stats_t *)malloc(sizeof(nodelevel_stats_t));

                if (NULL == nodestats) {
                    APSTATS_ERROR("Unable to allocate memory for node stats\n");
                    free(buf);
                    /* For now, the caller of stats_hierachy_init() is expected to
                       call stats_hierachy_deinit() to clean up the linked
                       list under apstats */
                    return -ENOMEM;
                }
                memset(nodestats, 0 , sizeof(nodelevel_stats_t));
                nodestats->obj.level = APSTATS_LEVEL_NODE;
                nodestats->obj.subtree_root = 0;
                memcpy(nodestats->macaddr.ether_addr_octet,
                        si->isi_macaddr,
                        QDF_MAC_ADDR_SIZE);

                /* As an optimization, copy ieee80211req_sta_info right
                   away. */
                memcpy(&nodestats->si, si, sizeof(struct ieee80211req_sta_info));

                nodestats->obj.parent = vapstats;

                if (!vapstats->obj.firstchild) {
                    vapstats->obj.firstchild = nodestats;
                } else {
                    curr_ns_ptr = (nodelevel_stats_t*)vapstats->obj.firstchild;

                    while(curr_ns_ptr->obj.next != NULL)
                    {
                        curr_ns_ptr = curr_ns_ptr->obj.next;
                    }

                    curr_ns_ptr->obj.next = nodestats;
                    nodestats->obj.prev = curr_ns_ptr;
                    nodestats->obj.next = NULL;
                }

                cp += si->isi_len, remaining_len -= si->isi_len;
            } while (remaining_len >= sizeof(struct ieee80211req_sta_info));
        }
#endif
    } else {
#if UMAC_SUPPORT_CFG80211
        opmode  = get_vap_priv_int_param(
                sockfd,
                vapstats->ifname,
                IEEE80211_PARAM_GET_OPMODE);
        memset(&buffer, 0, sizeof(buffer));
        buffer.data = buf;
        buffer.length = LIST_STATION_CFG_ALLOC_SIZE;
        buffer.flags = 0;
        buffer.parse_data = 0;
        buffer.callback = &get_sta_info;
        head_vapstats = vapstats;
        if (opmode == IEEE80211_M_HOSTAP )
            wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
                    QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                    QCA_NL80211_VENDOR_SUBCMD_LIST_STA, vapstats->ifname, (char *)&buffer, buffer.length);
#endif
    }
    free(buf);
    return 0;
}

#define EXPECTED_MAX_RADIOS     (4)
#define EXPECTED_MAX_VAPS       (15 * EXPECTED_MAX_RADIOS)

/*
 * For now, we require the caller to call stats_hierachy_deinit()
 * in case stats_hierachy_init() fails.
 */
static int stats_hierachy_init(aplevel_stats_t *apstats, int sockfd)
{
    int           i = 0;
    int           ret = 0;
    struct ifreq  dev = {0};
    char          temp_name[IFNAMSIZ] = {0};
    sys_ifnames   radio_listing = {0};
    sys_ifnames   vap_listing = {0};
    radiolevel_stats_t *curr_rs_ptr = NULL;
    vaplevel_stats_t *curr_vs_ptr = NULL;
    DIR *dir = NULL;

    assert(apstats != NULL);

    memset(apstats, 0, sizeof(aplevel_stats_t));
    apstats->obj.level = APSTATS_LEVEL_AP;
    apstats->obj.subtree_root = 0;

    ret = sys_ifnames_init(&radio_listing, EXPECTED_MAX_RADIOS);
    if (ret < 0) {
        return ret;
    }
    ret = sys_ifnames_init(&vap_listing, EXPECTED_MAX_VAPS);
    if (ret < 0) {
        sys_ifnames_deinit(&radio_listing);
        return ret;
    }

    /*
     * Note: Since the number of interfaces is small, we
     * use a simple algorithm to build the stats hierarchy.
     * Also, since this is a quick single run program, we assume the
     * interfaces do not 'disappear' during its execution.
     */


    /* Get radio and VAP names */
    dir = opendir(PATH_SYSNET_DEV);
    if (!dir) {
        sys_ifnames_deinit(&radio_listing);
        sys_ifnames_deinit(&vap_listing);
        perror(PATH_SYSNET_DEV);
        return -1;
    }

    while (1) {
        struct dirent *entry;
        const char *d_name;

        /* "Readdir" gets subsequent entries from "dir". */
        entry = readdir(dir);
        if (!entry) {
            /*
             * There are no more entries in this directory, so break
             * out of the while loop.
             */
            break;
        }
        d_name = entry->d_name;

        if ((entry->d_type & DT_DIR) || (entry->d_type & DT_LNK)) {
            if (strlcpy(temp_name, d_name, IFNAMSIZ) >= IFNAMSIZ) {
                APSTATS_ERROR("%s(): %d Error creating ifname \n",
                        __func__, __LINE__);
                sys_ifnames_deinit(&radio_listing);
                sys_ifnames_deinit(&vap_listing);
                closedir(dir);
                return -1;
            }
        }
        else {
            continue;
        }
        if (strncmp(d_name, "..", 2) == 0 ||
                strncmp (d_name, ".", 1) == 0) {
            continue;
        }
        if (is_radio_ifname_valid(temp_name)) {
            ret = sys_ifnames_add(&radio_listing, temp_name);

            if (ret < 0) {
                ret = sys_ifnames_extend(&radio_listing, 10);

                if (ret < 0)
                {
                    sys_ifnames_deinit(&radio_listing);
                    sys_ifnames_deinit(&vap_listing);
                    closedir(dir);
                    return ret;
                }

                ret = sys_ifnames_add(&radio_listing, temp_name);

                if (ret < 0)
                {
                    sys_ifnames_deinit(&radio_listing);
                    sys_ifnames_deinit(&vap_listing);
                    closedir(dir);
                    return ret;
                }
            }
        } else if (is_vap_ifname_valid(temp_name)) {
            ret = sys_ifnames_add(&vap_listing, temp_name);

            if (ret < 0) {
                ret = sys_ifnames_extend(&vap_listing, 10);

                if (ret < 0)
                {
                    sys_ifnames_deinit(&radio_listing);
                    sys_ifnames_deinit(&vap_listing);
                    closedir(dir);
                    return ret;
                }

                ret = sys_ifnames_add(&vap_listing, temp_name);

                if (ret < 0)
                {
                    sys_ifnames_deinit(&radio_listing);
                    sys_ifnames_deinit(&vap_listing);
                    closedir(dir);
                    return ret;
                }
            }
        }
    }

    closedir(dir);

    /* Add radios */
    dev.ifr_addr.sa_family = AF_INET;

    for (i = 0; i < radio_listing.curr_size; i++)
    {
        radiolevel_stats_t *radiostats = NULL;
        memset(dev.ifr_name, '\0', IFNAMSIZ);
        if (strlcpy(dev.ifr_name, radio_listing.ifnames[i], IFNAMSIZ) > IFNAMSIZ) {
            APSTATS_ERROR("%s(): %d Error creating ifname \n",
                    __func__, __LINE__);
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            return -1;
        }

        /* Get the MAC address */
        if (ioctl(sockfd, SIOCGIFHWADDR, &dev) < 0)
        {
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            perror("SIOCGIFHWADDR");
            return -1;
        }

        if (ioctl(sockfd, SIOCGIFFLAGS, &dev) < 0)
        {
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            perror("SIOCGIFFLAGS");
            return -1;
        }

        if (!(dev.ifr_flags & IFF_RUNNING))
            continue;

        radiostats = (radiolevel_stats_t *)malloc(sizeof(radiolevel_stats_t));
        if (radiostats == NULL) {
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            return -ENOMEM;
        }
        memset(radiostats, 0, sizeof(radiolevel_stats_t));
        radiostats->obj.level = APSTATS_LEVEL_RADIO;
        radiostats->obj.subtree_root = 0;

        radiostats->obj.parent = apstats;
        if (strlcpy(radiostats->ifname, dev.ifr_name, IFNAMSIZ) >= IFNAMSIZ) {
            APSTATS_ERROR("%s(): %d Error creating ifname \n",
                    __func__, __LINE__);
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            return -1;
        }
        memcpy(radiostats->macaddr, dev.ifr_hwaddr.sa_data,
               IEEE80211_ADDR_LEN);

        if (curr_rs_ptr) {
            curr_rs_ptr->obj.next = radiostats;
            radiostats->obj.prev = curr_rs_ptr;
        }

        curr_rs_ptr = radiostats;

        if (!(apstats->obj.firstchild)) {
            apstats->obj.firstchild = radiostats;
        }
    }

    /* Add VAPs */

    for (i = 0; i < vap_listing.curr_size; i++)
    {
        vaplevel_stats_t *vapstats = NULL;
        memset(dev.ifr_name, '\0', IFNAMSIZ);
        if (strlcpy(dev.ifr_name, vap_listing.ifnames[i], IFNAMSIZ)
                >= IFNAMSIZ) {
            APSTATS_ERROR("%s(): %d Error creating ifname \n",
                    __func__, __LINE__);
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            return -1;
        }
        /* Get the MAC address */
        if (ioctl(sockfd, SIOCGIFHWADDR, &dev) < 0)
        {
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            perror("SIOCGIFHWADDR");
            return -1;
        }

        if (ioctl(sockfd, SIOCGIFFLAGS, &dev) < 0)
        {
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            perror("SIOCGIFFLAGS");
            return -1;
        }

        if (!(dev.ifr_flags & IFF_UP) && !(dev.ifr_flags & IFF_RUNNING))
            continue;

        vapstats = (vaplevel_stats_t *)malloc(sizeof(vaplevel_stats_t));
        if(vapstats == NULL)
        {
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            return -ENOMEM;
        }
        memset(vapstats, 0, sizeof(vaplevel_stats_t));
        vapstats->obj.level = APSTATS_LEVEL_VAP;
        vapstats->obj.subtree_root = 0;

        if (strlcpy(vapstats->ifname, dev.ifr_name, IFNAMSIZ) >= IFNAMSIZ) {
            APSTATS_ERROR("%s(): %d Error creating vap ifname \n",
                    __func__, __LINE__);
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            return -1;
        }
        memcpy(vapstats->macaddr, dev.ifr_hwaddr.sa_data, IEEE80211_ADDR_LEN);

        /* Find parent radio */

        curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

        while(curr_rs_ptr != NULL)
        {
            if (is_vap_radiochild(vapstats, curr_rs_ptr))
                break;

            curr_rs_ptr = curr_rs_ptr->obj.next;
        }

        if (!curr_rs_ptr) {
            /* Huh? This should never happen. */
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            APSTATS_ERROR("Serious: Found orphaned VAP\n");
            free(vapstats);
            head_vapstats = NULL;
            return -ENOENT;
        }
        if ((ret = nodestats_hierarchy_init(vapstats, sockfd)) < 0)
        {
            free(vapstats);
            head_vapstats = NULL;
            sys_ifnames_deinit(&radio_listing);
            sys_ifnames_deinit(&vap_listing);
            if (ret == -EPERM)
                return 0;
            else
                return ret;
        }

        vapstats->obj.parent = curr_rs_ptr;
        if (!curr_rs_ptr->obj.firstchild) {
            curr_rs_ptr->obj.firstchild = vapstats;
        } else {
            curr_vs_ptr = (vaplevel_stats_t*)curr_rs_ptr->obj.firstchild;

            while (curr_vs_ptr->obj.next != NULL) {
                curr_vs_ptr = curr_vs_ptr->obj.next;
            }

            curr_vs_ptr->obj.next = vapstats;
            vapstats->obj.prev = curr_vs_ptr;
            /*
             * No need to update curr_vs_ptr itself - since this is a
             * simple implementation, the ptr will be detected on the next pass.
             * We have multiple radios, and we don't wan't to maintain
             * a curr_vs_ptr per radio
             */
        }
    }

    sys_ifnames_deinit(&radio_listing);
    sys_ifnames_deinit(&vap_listing);
    return 0;
}

static radiolevel_stats_t* stats_hierarchy_findradio(aplevel_stats_t *apstats,
        char *ifname)
{
    radiolevel_stats_t *curr_rs_ptr = NULL;
    assert(apstats != NULL);

    curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

    while(curr_rs_ptr) {
        if (!strncmp(curr_rs_ptr->ifname, ifname, IFNAMSIZ)) {
            return curr_rs_ptr;
        }
        curr_rs_ptr = curr_rs_ptr->obj.next;
    }

    return NULL;
}

static vaplevel_stats_t* stats_hierarchy_findvap(aplevel_stats_t *apstats,
        char *ifname)
{
    radiolevel_stats_t *curr_rs_ptr = NULL;
    vaplevel_stats_t *curr_vs_ptr = NULL;

    assert(apstats != NULL);

    curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

    while(curr_rs_ptr) {
        curr_vs_ptr = (vaplevel_stats_t*)curr_rs_ptr->obj.firstchild;

        while(curr_vs_ptr) {
            if (!strncmp(curr_vs_ptr->ifname, ifname, IFNAMSIZ)) {
                return curr_vs_ptr;
            }
            curr_vs_ptr = curr_vs_ptr->obj.next;
        }

        curr_rs_ptr = curr_rs_ptr->obj.next;
    }

    return NULL;
}

/*
 * The below code can be made more efficient. But we keep it simple
 * since it is called just once during application init.
 */
    static nodelevel_stats_t*
stats_hierarchy_findnode(aplevel_stats_t *apstats,
        struct ether_addr *stamacaddr)
{
    radiolevel_stats_t *curr_rs_ptr = NULL;
    vaplevel_stats_t *curr_vs_ptr = NULL;
    nodelevel_stats_t *curr_ns_ptr = NULL;

    assert(apstats != NULL);

    curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

    while(curr_rs_ptr) {
        curr_vs_ptr = (vaplevel_stats_t*)curr_rs_ptr->obj.firstchild;

        while(curr_vs_ptr) {
            curr_ns_ptr = (nodelevel_stats_t*)curr_vs_ptr->obj.firstchild;

            while(curr_ns_ptr) {
                if (memcmp(&curr_ns_ptr->macaddr,
                            stamacaddr,
                            sizeof(struct ether_addr)) == 0) {
                    return curr_ns_ptr;
                }

                curr_ns_ptr = curr_ns_ptr->obj.next;
            }

            curr_vs_ptr = curr_vs_ptr->obj.next;
        }

        curr_rs_ptr = curr_rs_ptr->obj.next;
    }

    return NULL;
}

static int stats_hierachy_deinit(aplevel_stats_t *apstats)
{
    radiolevel_stats_t *curr_rs_ptr = NULL;
    vaplevel_stats_t *curr_vs_ptr = NULL;
    nodelevel_stats_t *curr_ns_ptr = NULL;
    radiolevel_stats_t *next_rs_ptr = NULL;
    vaplevel_stats_t *next_vs_ptr = NULL;
    nodelevel_stats_t *next_ns_ptr = NULL;

    assert(apstats != NULL);

    curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

    while(curr_rs_ptr)
    {
        curr_vs_ptr = (vaplevel_stats_t*)curr_rs_ptr->obj.firstchild;

        while(curr_vs_ptr) {

            curr_ns_ptr = (nodelevel_stats_t*)curr_vs_ptr->obj.firstchild;

            while(curr_ns_ptr) {
                next_ns_ptr = curr_ns_ptr->obj.next;
                free(curr_ns_ptr);
                curr_ns_ptr = next_ns_ptr;
            }

            next_vs_ptr = curr_vs_ptr->obj.next;
            free(curr_vs_ptr);
            curr_vs_ptr = next_vs_ptr;
        }

        next_rs_ptr = curr_rs_ptr->obj.next;
        free(curr_rs_ptr);
        curr_rs_ptr = next_rs_ptr;
    }

    apstats->obj.firstchild = NULL;
    return 0;
}

#if UMAC_SUPPORT_CFG80211
void cfg80211_parse_param(struct cfg80211_data *buffer)
{
    uint32_t temp;
    uint32_t *value = (uint32_t *)buffer->data;
    struct nlattr *attr_vendor[NL80211_ATTR_MAX_INTERNAL];
    /* extract data from NL80211_ATTR_VENDOR_DATA attributes */
    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_GETPARAM_MAX,
            (struct nlattr *)buffer->nl_vendordata,
            buffer->nl_vendordata_len, wlan_cfg80211_get_params_policy);

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND]) {
        /* memcpy tb_vendor to data */
        temp = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND]);
        *value = temp;
    } else {
        fprintf(stderr,"\n Invalid value. Failed to get the value form driver!");
        *value = -EINVAL;
    }

    return;
}
#endif
static int get_vap_priv_int_param(int sockfd, const char *ifname, int param)
{
#if UMAC_SUPPORT_CFG80211
    struct cfg80211_data buffer;
#endif
    uint32_t value;
    int msg, err;
#if UMAC_SUPPORT_WEXT
    struct iwreq iwr;
    int sock_fd;
#endif

    if (cfg_flag) {
#if UMAC_SUPPORT_CFG80211
        buffer.data = &value;
        buffer.length = sizeof(uint32_t);
        buffer.parse_data = 0;
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, param, ifname, (char *)&buffer, sizeof(uint32_t));
        /* we need to pass subcommand as well */
        if (msg < 0) {
            fprintf(stderr,"Couldn't send NL command\n");
            return -EIO;
        }
        return value;
#endif
    } else {
#if UMAC_SUPPORT_WEXT
        sock_fd = sock_ctx.sock_fd;
        memset(&iwr, 0, sizeof(iwr));
        iwr.u.mode = param;
        if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
            APSTATS_ERROR("%s(): %d Error creating ifname \n",
                    __func__, __LINE__);
            return -1;
        }
        err = ioctl(sock_fd, IEEE80211_IOCTL_GETPARAM, &iwr);
        if (err < 0) {
            errx(1, "unable to send comamnd");
            return -EINVAL;
        }
        return iwr.u.param.value;
#endif
    }
    return 0;
}

static int get_radio_priv_int_param(int sockfd, const char *ifname, int param)
{
#if UMAC_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    int msg;
#endif
    uint32_t value;
#if UMAC_SUPPORT_WEXT
    int sock_fd;
    struct iwreq iwr;
#endif
    int err;

    if (param == OL_ATH_PARAM_GET_IF_ID) {
#if ATH_PERF_PWR_OFFLOAD
        if (cfg_flag) {
#if UMAC_SUPPORT_CFG80211
            buffer.data = &value;
            buffer.length = sizeof(uint32_t);
            buffer.parse_data = 0;
            buffer.callback = NULL;
            buffer.parse_data = 0;
            msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                    QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, param | ATH_PARAM_SHIFT, ifname, (char *)&buffer, sizeof(uint32_t));
            /* we need to pass subcommand as well */
            if (msg < 0) {
                fprintf(stderr,"Couldn't send NL command\n");
                return -EIO;
            }
            return value;
#endif
        } else {
#if UMAC_SUPPORT_WEXT
            sock_fd = sock_ctx.sock_fd;
            memset(&iwr, 0, sizeof(iwr));
            iwr.u.mode = param | ATH_PARAM_SHIFT;
            if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
                fprintf(stderr,"Error creating ifname \n");
                return -1;
            }
            err = ioctl(sock_fd, ATH_IOCTL_GETPARAM, &iwr);
            if (err < 0) {
                errx(1, "unable to send comamnd");
                return 0;
            }
            return iwr.u.param.value;
#endif
        }
#endif
    } else {
        if (cfg_flag) {
#if UMAC_SUPPORT_CFG80211
            buffer.data = &value;
            buffer.length = sizeof(uint32_t);
            buffer.parse_data = 0;
            buffer.callback = NULL;
            buffer.parse_data = 0;
            msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                    QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, param | ATH_PARAM_SHIFT, ifname, (char *)&buffer, sizeof(uint32_t));
            /* we need to pass subcommand as well */
            if (msg < 0) {
                fprintf(stderr,"Couldn't send NL command\n");
                return -EIO;
            }
            return value;
#endif
        } else {
#if UMAC_SUPPORT_WEXT
            sock_fd = sock_ctx.sock_fd;
            memset(&iwr, 0, sizeof(iwr));
            iwr.u.mode = param | ATH_PARAM_SHIFT;
            if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
                fprintf(stderr,"Error creating ifname \n");
                return -1;
            }
            err = ioctl(sock_fd, ATH_IOCTL_GETPARAM, &iwr);
            if (err < 0) {
                errx(1, "unable to send comamnd");
                return -EIO;
            }
            return iwr.u.param.value;
#endif
        }
    }
    return 0;
}

static int aplevel_gather_stats(int sockfd,
        aplevel_stats_t *apstats, bool recursion)
{
    radiolevel_stats_t *curr_rs_ptr = NULL;
    u_int32_t chan_util_numrtr = 0;
    u_int16_t chan_util_denomntr = 0;
    u_int16_t prdic_per_numrtr = 0;
    u_int16_t prdic_per_denomntr = 0;
    u_int16_t total_per_numrtr = 0;
    u_int16_t total_per_denomntr = 0;
    u_int64_t tx_rate_numrtr = 0;
    u_int64_t rx_rate_numrtr = 0;
    u_int16_t txrx_rate_denomntr = 0;

    assert(apstats != NULL);

    /* Gather WLAN statistics */
    apstats->res_util_enab  = 1;
    apstats->prdic_per_enab = 1;

    curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

    while(curr_rs_ptr) {
        radiolevel_gather_stats(sockfd, curr_rs_ptr, recursion);

        apstats->tx_data_packets += curr_rs_ptr->tx_data_packets;
        apstats->tx_data_bytes   += curr_rs_ptr->tx_data_bytes;
        apstats->rx_data_packets += curr_rs_ptr->rx_data_packets;
        apstats->rx_data_bytes   += curr_rs_ptr->rx_data_bytes;

        apstats->tx_ucast_data_packets  +=
            curr_rs_ptr->tx_ucast_data_packets;
        apstats->tx_mbcast_data_packets +=
            curr_rs_ptr->tx_mbcast_data_packets;

        apstats->rx_phyerr       += curr_rs_ptr->rx_phyerr;
        apstats->rx_crcerr       += curr_rs_ptr->rx_crcerr;
        apstats->rx_micerr       += curr_rs_ptr->rx_micerr;
        apstats->rx_decrypterr   += curr_rs_ptr->rx_decrypterr;
        apstats->rx_err          += curr_rs_ptr->rx_err;

        apstats->tx_discard      += curr_rs_ptr->tx_discard;
        apstats->tx_err          += curr_rs_ptr->tx_err;

        /*
         * We need all radios to have valid channel utilization
         * numbers, for the AP resource utilization to make sense.
         */
        apstats->res_util_enab   &= curr_rs_ptr->chan_util_enab;

        if (apstats->res_util_enab) {
            chan_util_numrtr += curr_rs_ptr->chan_util;
            chan_util_denomntr++;
        }

        if (curr_rs_ptr->txrx_rate_available) {
            apstats->txrx_rate_available = 1;
            txrx_rate_denomntr++;
            tx_rate_numrtr += curr_rs_ptr->tx_rate;
            rx_rate_numrtr += curr_rs_ptr->rx_rate;
        }

        if (curr_rs_ptr->thrput_enab) {
            apstats->thrput_enab = 1;
            apstats->thrput += curr_rs_ptr->thrput;
        }

        total_per_numrtr += curr_rs_ptr->total_per;
        apstats->total_per = curr_rs_ptr->total_per;
        total_per_denomntr++;

        /*
         * We need all radios to have valid periodic PER numbers,
         * for the AP periodic PER to make sense.
         */
        apstats->prdic_per_enab   &= curr_rs_ptr->prdic_per_enab;

        if (apstats->prdic_per_enab) {
            prdic_per_numrtr         += curr_rs_ptr->prdic_per;
            prdic_per_denomntr++;
        }

        curr_rs_ptr = curr_rs_ptr->obj.next;
    }

    if (apstats->obj.firstchild != NULL) {
        if (apstats->res_util_enab) {
            apstats->res_util = chan_util_numrtr/chan_util_denomntr;
        }

        if (apstats->txrx_rate_available) {
            apstats->tx_rate = tx_rate_numrtr/txrx_rate_denomntr;
            apstats->rx_rate = rx_rate_numrtr/txrx_rate_denomntr;
        }


        if (apstats->prdic_per_enab) {
            apstats->prdic_per = prdic_per_numrtr/prdic_per_denomntr;
        }
    }
    return 0;
}

static int aplevel_display_stats(FILE *fp, aplevel_stats_t *apstats,
        bool recursion)
{
    radiolevel_stats_t *curr_rs_ptr = NULL;

    assert(apstats != NULL);

    APSTATS_PRINT_GENERAL(fp, "AP Level Stats:\n");
    APSTATS_PRINT_GENERAL(fp, "\n");

    if (apstats->obj.firstchild != NULL) {
        APSTATS_PRINT_GENERAL(fp, "WLAN Stats:\n");
        APSTATS_PRINT_STAT64(fp, "Tx Data Packets",      apstats->tx_data_packets);
        APSTATS_PRINT_STAT64(fp, "Tx Data Bytes",        apstats->tx_data_bytes);
        APSTATS_PRINT_STAT64(fp, "Rx Data Packets",      apstats->rx_data_packets);
        APSTATS_PRINT_STAT64(fp, "Rx Data Bytes",        apstats->rx_data_bytes);
        APSTATS_PRINT_STAT64(fp, "Tx Unicast Data Packets",
                apstats->tx_ucast_data_packets);
        APSTATS_PRINT_STAT64(fp, "Tx Multi/Broadcast Data Packets",
                apstats->tx_mbcast_data_packets);

        if (apstats->res_util_enab) {
            APSTATS_PRINT_STAT16(fp, "Resource Utilization (0-255)",  apstats->res_util);
        } else {
            APSTATS_PRINT_STAT_UNVLBL(fp, "Resource Utilization (0-255)", "<DISABLED>");
        }

        if (apstats->txrx_rate_available) {
            APSTATS_PRINT_STAT32(fp, "Average Tx Rate (kbps)", apstats->tx_rate);
            APSTATS_PRINT_STAT32(fp, "Average Rx Rate (kbps)", apstats->rx_rate);
        } else {
            APSTATS_PRINT_STAT_UNVLBL(fp, "Average Tx Rate (kbps)", "<NO STA>");
            APSTATS_PRINT_STAT_UNVLBL(fp, "Average Rx Rate (kbps)", "<NO STA>");
        }

        APSTATS_PRINT_STAT64(fp, "Rx PHY errors",        apstats->rx_phyerr);
        APSTATS_PRINT_STAT64(fp, "Rx CRC errors",        apstats->rx_crcerr);
        APSTATS_PRINT_STAT64(fp, "Rx MIC errors",        apstats->rx_micerr);
        APSTATS_PRINT_STAT64(fp, "Rx Decryption errors", apstats->rx_decrypterr);
        APSTATS_PRINT_STAT64(fp, "Rx errors",            apstats->rx_err);
        APSTATS_PRINT_STAT64(fp, "Tx failures",          apstats->tx_err);
        APSTATS_PRINT_STAT64(fp, "Tx Dropped",           apstats->tx_discard);

        if (apstats->thrput_enab) {
            APSTATS_PRINT_STAT32(fp, "Throughput (kbps)", apstats->thrput);
        } else {
            APSTATS_PRINT_STAT_UNVLBL(fp, "Throughput (kbps)", "<DISABLED>");
        }

        APSTATS_PRINT_STAT8(fp, "Total PER (%)",          apstats->total_per);

        if (apstats->prdic_per_enab) {
            APSTATS_PRINT_STAT8(fp, "PER over configured period (%)",
                    apstats->prdic_per);
        } else {
            APSTATS_PRINT_STAT_UNVLBL(fp, "PER over configured period (%)",
                    "<DISABLED>");
        }

        APSTATS_PRINT_GENERAL(fp, "\n");
    } else {
        APSTATS_PRINT_GENERAL(fp, "WLAN stats:\nNo radio interfaces found\n\n");
    }

    if (!recursion) {
        return 0;
    }

    curr_rs_ptr = (radiolevel_stats_t*)apstats->obj.firstchild;

    while(curr_rs_ptr) {
        radiolevel_display_stats(fp, curr_rs_ptr, recursion);
        curr_rs_ptr = curr_rs_ptr->obj.next;
    }
    return 0;
}

void vaplevel_accumulate_txrx_rate(vaplevel_stats_t *vapstats)
{
    struct ieee80211req_sta_info *si;
    u_int64_t tx_rate_numrtr = 0;
    u_int64_t rx_rate_numrtr = 0;
    u_int16_t txrx_rate_denomntr = 0;
    nodelevel_stats_t *nodestats = NULL;

    nodestats = (nodelevel_stats_t*)vapstats->obj.firstchild;

    /*
     * Store rate stats as it is already calculated in
     * nodestats_hierarchy_init
     */
    while(nodestats) {
        si = &nodestats->si;
        /*
         * As an optimization, ieee80211req_sta_info has already
         * been copied into nodestats after the IEEE80211_IOCTL_STA_INFO
         * ioctl call in nodestats_hierarchy_init()
         */
        if (si->isi_txratekbps == 0) {
            nodestats->tx_rate = ((si->isi_rates[si->isi_txrate] &
                IEEE80211_RATE_VAL) * 1000) / 2;
        } else {
            nodestats->tx_rate = si->isi_txratekbps;
        }
        nodestats->rx_rate       = si->isi_rxratekbps;

        tx_rate_numrtr += nodestats->tx_rate;
        rx_rate_numrtr += nodestats->rx_rate;
        txrx_rate_denomntr++;
        nodestats = nodestats->obj.next;
    }
    if (vapstats->obj.firstchild != NULL) {
        vapstats->tx_rate = tx_rate_numrtr/txrx_rate_denomntr;
        vapstats->rx_rate = rx_rate_numrtr/txrx_rate_denomntr;
    }
}

void radiolevel_accumulate_txrx_rate(radiolevel_stats_t *radiostats)
{
    vaplevel_stats_t *vapstats;
    u_int64_t tx_rate_numrtr = 0;
    u_int64_t rx_rate_numrtr = 0;
    vapstats = (vaplevel_stats_t*)radiostats->obj.firstchild;

    while(vapstats) {
        vaplevel_accumulate_txrx_rate(vapstats);
        tx_rate_numrtr += vapstats->tx_rate;
        rx_rate_numrtr += vapstats->rx_rate;
        vapstats = vapstats->obj.next;
    }
    radiostats->tx_rate = tx_rate_numrtr;
    radiostats->rx_rate = rx_rate_numrtr;
}

static int collect_vaplevel_stats(vaplevel_stats_t *vapstats)
{
    struct cfg80211_data buffer = {0};
    int msg;
    u_int32_t tx_rate = 0;
    u_int32_t rx_rate = 0;

    /*
     * Fields inside vapstats will be reset when
     * it is sent to driver.But for cleanup activity in de-init path
     * in apstats application, we will be needing apobject field and
     * Hence take backup of needed field in below variable.
     */
    apstats_obj_t apstats_obj;
    char ifname[IFNAMSIZ];
    struct ether_addr macaddr;

    if (strlcpy(ifname, vapstats->ifname, IFNAMSIZ) >= IFNAMSIZ) {
        APSTATS_ERROR("%s(): %d Error copying ifname \n",
              __func__, __LINE__);
        return -1;
    }
    memcpy(&macaddr, vapstats->macaddr, sizeof(struct ether_addr));
    memcpy(&apstats_obj, &(vapstats->obj), sizeof(apstats_obj_t));

    buffer.data = vapstats;
    buffer.length = sizeof(vaplevel_stats_t);
    buffer.callback = NULL;
    buffer.parse_data = 0;

    /* Accumulate vap level tx rx rate, as it is already calculated */
    vaplevel_accumulate_txrx_rate(vapstats);
    tx_rate = vapstats->tx_rate;
    rx_rate = vapstats->rx_rate;
	/* Reset field */
    vapstats->tx_rate = 0;
    vapstats->rx_rate = 0;

    /* NL command to gather vap level stats */
    msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
        QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
        QCA_NL80211_VENDOR_SUBCMD_VAP_STATS,
        (const char *)(vapstats->ifname), (char *)&buffer, sizeof(vaplevel_stats_t));
    if (msg < 0) {
        APSTATS_ERROR("%s(): %d Couldn't send NL command to get vap stats \n",
              __func__, __LINE__);
        return -EIO;
    }

    if (strlcpy(vapstats->ifname, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        APSTATS_ERROR("%s(): %d Error restoring ifname \n",
              __func__, __LINE__);
        return -1;
    }
    memcpy(&(vapstats->macaddr), &macaddr, sizeof(macaddr));
    memcpy(&(vapstats->obj), &apstats_obj, sizeof(apstats_obj_t));

    /* Hierarchy is created in stats_hierarchy_init and hence it is valid */
    if (vapstats->obj.firstchild != NULL) {
        if (vapstats->txrx_rate_available) {
            vapstats->tx_rate = tx_rate;
            vapstats->rx_rate = rx_rate;
        }
    }
    return 0;
}

static int collect_radiolevel_stats(radiolevel_stats_t *radiostats)
{
    struct cfg80211_data buffer;
    u_int32_t tx_rate = 0;
    u_int32_t rx_rate = 0;
    int flag = 0;
    /*
     * Fields inside radiostats will be reset when
     * it is sent to driver.But for cleanup activity in de-init path
     * in apstats application, we will be needing apobject field and
     * Hence take backup of needed field in below variable.
     */
    apstats_obj_t apstats_obj;
    char ifname[IFNAMSIZ];
    struct ether_addr macaddr;

    if (strlcpy(ifname, radiostats->ifname, IFNAMSIZ) >= IFNAMSIZ) {
        APSTATS_ERROR("%s(): %d Error copying ifname \n",
              __func__, __LINE__);
        return -1;
    }
    memcpy(&macaddr, radiostats->macaddr, sizeof(struct ether_addr));
    memcpy(&apstats_obj, &(radiostats->obj), sizeof(apstats_obj_t));

    /* Accumulate Radio level tx rx rate, as it is already calculated */
    radiolevel_accumulate_txrx_rate(radiostats);
    tx_rate = radiostats->tx_rate;
    rx_rate = radiostats->rx_rate;
	/* Reset field */
    radiostats->tx_rate = 0;
    radiostats->rx_rate = 0;
    buffer.data = radiostats;
    buffer.length = sizeof(radiolevel_stats_t);
    buffer.callback = NULL;
    buffer.parse_data = 0;

    /* NL command to gather Radio level stats */
    flag = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_RADIO_STATS,
            (const char *)(radiostats->ifname), (char *)&buffer, sizeof(radiolevel_stats_t));
    if (flag < 0) {
        APSTATS_ERROR("%s(): %d Couldn't send NL command to get radio stats \n",
              __func__, __LINE__);
        return -EIO;
    }

    if (strlcpy(radiostats->ifname, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        APSTATS_ERROR("%s(): %d Error restoring ifname \n",
              __func__, __LINE__);
        return -1;
    }
    memcpy(&(radiostats->macaddr), &macaddr, sizeof(macaddr));
    memcpy(&(radiostats->obj), &apstats_obj, sizeof(apstats_obj_t));

    /* Hierarchy is created in stats_hierarchy_init and hence it is valid */
    if (radiostats->obj.firstchild != NULL) {
        if (radiostats->txrx_rate_available) {
            /* calculate rx rate first to keep hold of tx rate */
            radiostats->rx_rate = rx_rate/radiostats->tx_rate;
            radiostats->tx_rate = tx_rate/radiostats->tx_rate;
        }
    }
    return 0;
}

static int radiolevel_gather_stats(int sockfd,
        radiolevel_stats_t *radiostats, bool recursion)
{
    vaplevel_stats_t *curr_vs_ptr = NULL;
    struct ath_phy_stats phystats[WIRELESS_MODE_MAX];
    struct ath_stats stats = { 0 };
    struct ath_stats_container stats_cntnr;
#if ATH_PERF_PWR_OFFLOAD
    struct ol_ath_radiostats ol_stats;
#define max(a, b) (((a) > (b)) ? a : b)
    int buf_sz = max(sizeof(struct cdp_pdev_stats), sizeof(struct ol_stats));
#else
    int buf_sz = sizeof(struct ath_stats);
#endif
    char buffer[buf_sz];
    struct ath_stats_container asc = {0};
    int flag = 0;
    struct ifreq ifr;
    u_int32_t chan_util_numrtr = 0;
    u_int16_t chan_util_denomntr = 0;
    u_int64_t tx_rate_numrtr = 0;
    u_int64_t rx_rate_numrtr = 0;
    u_int16_t txrx_rate_denomntr = 0;
    u_int16_t total_per_numrtr = 0;
    u_int16_t total_per_denomntr = 0;
    int i = 0;
    int tx_beacon_flag = 0;

    assert(radiostats != NULL);

    /* Gather pure radio-level stats */

    /* PHY stats */
    memset(ifr.ifr_name, '\0', sizeof(ifr.ifr_name));
    if (strlcpy(ifr.ifr_name, radiostats->ifname, sizeof(ifr.ifr_name))
            >= sizeof(ifr.ifr_name)) {
        APSTATS_ERROR("%s(): %d Error creating ifname \n", __func__, __LINE__);
        return -1;
    }

#if !(UMAC_SUPPORT_PERIODIC_PERFSTATS)
#if UMAC_SUPPORT_CFG80211
#if ATH_PERF_PWR_OFFLOAD
    if (!recursion && cfg_flag)
        return collect_radiolevel_stats(radiostats);
#endif
#endif
#endif

#if ATH_PERF_PWR_OFFLOAD
    /*  which interface is this Off-Load or Direct-Attach */
    asc.size = buf_sz;
    asc.address = (struct ath_stats *)buffer;
    asc.offload_if = -1;

    flag = ap_send_command(radiostats->ifname, &asc, sizeof(asc), QCA_NL80211_VENDOR_SUBCMD_ATHSTATS, SIOCGATHSTATS);

    if (cfg_flag) {
        radiostats->ol_enable = flag;
    } else {
        radiostats->ol_enable = asc.offload_if;
    }

    if (radiostats->ol_enable == -1) {
        return -1;
    }

    if (radiostats->ol_enable == 0) {
#endif
        memset(phystats, 0, sizeof(phystats));

        ap_send_command(radiostats->ifname, &phystats, sizeof(phystats), QCA_NL80211_VENDOR_SUBCMD_PHYSTATS, SIOCGATHPHYSTATS);

        for (i = 0; i < WIRELESS_MODE_MAX; i++) {
            radiostats->rx_phyerr +=
                (phystats[i].ast_rx_phyerr -
                 phystats[i].ast_rx_phy[HAL_PHYERR_RADAR & 0x1f] -
                 phystats[i].ast_rx_phy[HAL_PHYERR_FALSE_RADAR_EXT & 0x1f] -
                 phystats[i].ast_rx_phy[HAL_PHYERR_SPECTRAL & 0x1f]);

            radiostats->rx_crcerr +=
                (phystats[i].ast_rx_crcerr);

        }

        /* Other radio level stats */

        stats_cntnr.size = sizeof(struct ath_stats);
        stats_cntnr.address = &stats;
        ap_send_command(radiostats->ifname, &stats_cntnr, sizeof(stats_cntnr), QCA_NL80211_VENDOR_SUBCMD_ATHSTATS, SIOCGATHSTATS);

        radiostats->tx_beacon_frames = stats.ast_be_xmit;
        radiostats->tx_mgmt_frames = stats.ast_tx_mgmt;
        radiostats->rx_mgmt_frames = stats.ast_rx_num_mgmt;
        radiostats->rx_rssi = stats.ast_rx_rssi;

        radiostats->self_bss_util = stats.ast_self_bss_util;
        radiostats->obss_util     = stats.ast_obss_util;
#if ATH_PERF_PWR_OFFLOAD
    } else if (radiostats->ol_enable == 1 || radiostats->ol_enable == 2) {
        memset(&ol_stats, 0, sizeof(ol_stats));

        ap_send_command(radiostats->ifname, &ol_stats, sizeof(ol_stats), QCA_NL80211_VENDOR_SUBCMD_PHYSTATS, SIOCGATHPHYSTATS);
        // ol_stats = (struct ol_ath_radiostats *)buffer;
        radiostats->rx_phyerr = ol_stats.rx_phyerr;
        radiostats->rx_phyerr += ol_stats.phy_err_count;
        radiostats->tx_beacon_frames = ol_stats.tx_beacon;
        radiostats->tx_mgmt_frames = (long unsigned int)ol_stats.tx_mgmt;
        radiostats->rx_mgmt_frames = (long unsigned int)(ol_stats.rx_mgmt + ol_stats.rx_num_mgmt);
        radiostats->rx_mgmt_frames_rssi_drop = (long unsigned int)ol_stats.rx_mgmt_rssi_drop;

        radiostats->rx_rssi = ol_stats.rx_rssi_comb;
        radiostats->rx_crcerr = ol_stats.rx_crcerr;
        //Right now we can only accumulate only successful RTS frames
        radiostats->tx_ctl_frames = ol_stats.rtsgood;
        radiostats->rx_ctl_frames = ol_stats.rx_num_ctl;
        radiostats->chan_nf = ol_stats.chan_nf;
        radiostats->tx_frame_count = ol_stats.tx_frame_count;
        radiostats->rx_frame_count = ol_stats.rx_frame_count;
        radiostats->rx_clear_count = ol_stats.rx_clear_count;
        radiostats->cycle_count = ol_stats.cycle_count;
        radiostats->phy_err_count = ol_stats.phy_err_count;
        radiostats->chan_tx_pwr = ol_stats.chan_tx_pwr;

        radiostats->self_bss_util = ol_stats.self_bss_util;
        radiostats->obss_util     = ol_stats.obss_util;

        /* co-located rnr stats */
        radiostats->created_vap = ol_stats.created_vap;
        radiostats->active_vap = ol_stats.active_vap;
        radiostats->rnr_count = ol_stats.rnr_count;
        radiostats->soc_status_6ghz = ol_stats.soc_status_6ghz;
    }
#endif

    if (radiostats->tx_beacon_frames == 0)
        tx_beacon_flag = 1;

#if UMAC_SUPPORT_PERIODIC_PERFSTATS
    /* Throughput */
#if ATH_PERF_PWR_OFFLOAD
    if (radiostats->ol_enable == 0) {
#endif
        radiostats->thrput_enab  = get_radio_priv_int_param(
                sockfd,
                radiostats->ifname,
                ATH_PARAM_PRDPERFSTAT_THRPUT_ENAB);

        if (radiostats->thrput_enab) {
            radiostats->thrput  = get_radio_priv_int_param(
                    sockfd,
                    radiostats->ifname,
                    ATH_PARAM_PRDPERFSTAT_THRPUT);
        }

        /* PER */
        radiostats->prdic_per_enab  = get_radio_priv_int_param(
                sockfd,
                radiostats->ifname,
                ATH_PARAM_PRDPERFSTAT_PER_ENAB);

        if (radiostats->prdic_per_enab) {
            radiostats->prdic_per  = get_radio_priv_int_param(
                    sockfd,
                    radiostats->ifname,
                    ATH_PARAM_PRDPERFSTAT_PER);
        }
#if ATH_PERF_PWR_OFFLOAD
    } else if (radiostats->ol_enable == 1){
        radiostats->thrput_enab  = get_radio_priv_int_param(
                sockfd,
                radiostats->ifname,
                OL_ATH_PARAM_PRDPERFSTAT_THRPUT_ENAB);
        if (radiostats->thrput_enab) {
            radiostats->thrput  = get_radio_priv_int_param(
                    sockfd,
                    radiostats->ifname,
                    OL_ATH_PARAM_PRDPERFSTAT_THRPUT);
        }
        /* PER */
        radiostats->prdic_per_enab  = get_radio_priv_int_param(
                sockfd,
                radiostats->ifname,
                OL_ATH_PARAM_PRDPERFSTAT_PER_ENAB);

        if (radiostats->prdic_per_enab) {
            radiostats->prdic_per  = get_radio_priv_int_param(
                    sockfd,
                    radiostats->ifname,
                    OL_ATH_PARAM_PRDPERFSTAT_PER);

        }
    }
#endif
#else
    radiostats->thrput_enab = 0;
    radiostats->prdic_per_enab = 0;
#endif /* UMAC_SUPPORT_PERIODIC_PERFSTATS */

#if ATH_PERF_PWR_OFFLOAD
    if (radiostats->ol_enable == 0) {
#endif
        radiostats->total_per  = get_radio_priv_int_param(
                sockfd,
                radiostats->ifname,
                ATH_PARAM_TOTAL_PER);
#if ATH_PERF_PWR_OFFLOAD
    } else if (radiostats->ol_enable == 1){
        radiostats->total_per  = get_radio_priv_int_param(
                sockfd,
                radiostats->ifname,
                OL_ATH_PARAM_TOTAL_PER);
    }
#endif
    /* Gather VAP level stats and populate stats which depend on VAP level */

    curr_vs_ptr = (vaplevel_stats_t*)radiostats->obj.firstchild;

    while(curr_vs_ptr) {
        vaplevel_gather_stats(sockfd, curr_vs_ptr, recursion);

        radiostats->current_pp = curr_vs_ptr->current_pp;
        radiostats->no_act_vaps = curr_vs_ptr->no_act_vaps;
        radiostats->tx_vap = curr_vs_ptr->tx_vap;
        radiostats->tx_data_packets += curr_vs_ptr->tx_data_packets;
        radiostats->tx_data_bytes   += curr_vs_ptr->tx_data_bytes;
        radiostats->rx_data_packets += curr_vs_ptr->rx_data_packets;
        radiostats->rx_data_bytes   += curr_vs_ptr->rx_data_bytes;
        radiostats->rx_mgmt_frames  += curr_vs_ptr->rx_mgmt;
        radiostats->tx_mgmt_frames  += curr_vs_ptr->tx_mgmt;

        radiostats->tx_ucast_data_packets  +=
            curr_vs_ptr->tx_ucast_data_packets;
        radiostats->tx_mbcast_data_packets +=
            curr_vs_ptr->tx_mbcast_data_packets;

        if (tx_beacon_flag == 1) {
            radiostats->tx_beacon_frames += curr_vs_ptr->tx_bcn_succ_cnt;
            radiostats->tx_beacon_frames += curr_vs_ptr->tx_bcn_outage_cnt;
        }

        for (i = 0;i < WME_NUM_AC; i++) {
            radiostats->tx_data_wme[i] += curr_vs_ptr->tx_data_wme[i];
            radiostats->rx_data_wme[i] += curr_vs_ptr->rx_data_wme[i];
        }

        radiostats->rx_micerr       += curr_vs_ptr->rx_micerr;
        radiostats->rx_decrypterr   += curr_vs_ptr->rx_decrypterr;
        radiostats->rx_err          += curr_vs_ptr->rx_err;

        radiostats->tx_discard      += curr_vs_ptr->tx_discard;
        radiostats->tx_err          += curr_vs_ptr->tx_err;

        /*
         * If at least one of the VAPs have channel utilization
         * enabled, then we are good.
         */
        radiostats->chan_util_enab   |= curr_vs_ptr->chan_util_enab;

        if (curr_vs_ptr->chan_util_enab) {
            chan_util_numrtr            += curr_vs_ptr->chan_util;
            chan_util_denomntr++;
        }

        if (curr_vs_ptr->txrx_rate_available) {
            radiostats->txrx_rate_available = 1;
            txrx_rate_denomntr++;
            tx_rate_numrtr += curr_vs_ptr->tx_rate;
            rx_rate_numrtr += curr_vs_ptr->rx_rate;
        }
        total_per_numrtr += curr_vs_ptr->last_per;
        total_per_denomntr++;

        radiostats->sta_xceed_rlim += curr_vs_ptr->sta_xceed_rlim;
        radiostats->sta_xceed_vlim += curr_vs_ptr->sta_xceed_vlim;
        radiostats->mlme_auth_attempt += curr_vs_ptr->mlme_auth_attempt;
        radiostats->mlme_auth_success += curr_vs_ptr->mlme_auth_success;
        radiostats->authorize_attempt += curr_vs_ptr->authorize_attempt;
        radiostats->authorize_success += curr_vs_ptr->authorize_success;

        curr_vs_ptr = curr_vs_ptr->obj.next;
    }

    if (radiostats->obj.firstchild != NULL) {
        if (radiostats->chan_util_enab) {
            /*
             * Take the average of channel utilization values across VAPs.
             * One might initially assume that these should be the same across
             * VAPs.
             * However, these are calculated as per the standard, factoring
             * individual beacon periods. These periods are currently the same
             * for all VAPS, but we shouldn't assume they will remain so in
             * the future.
             * Besides, there are variances in the time at which channel utilization
             * calculation takes place for individual VAPs.
             */
            radiostats->chan_util = chan_util_numrtr/chan_util_denomntr;
        }

        if (radiostats->txrx_rate_available) {
            radiostats->tx_rate = tx_rate_numrtr/txrx_rate_denomntr;
            radiostats->rx_rate = rx_rate_numrtr/txrx_rate_denomntr;
        }

        /* Other averaging goes here */
        radiostats->total_per = total_per_numrtr/total_per_denomntr;
    }
    return 0;
}

static int radiolevel_display_stats(FILE *fp, radiolevel_stats_t *radiostats,
        bool recursion)
{
    vaplevel_stats_t *curr_vs_ptr = NULL;

    assert(radiostats != NULL);

    APSTATS_PRINT_GENERAL(fp, "Radio Level Stats: %s\n",
            radiostats->ifname);
    APSTATS_PRINT_STAT64(fp, "Tx Data Packets",      radiostats->tx_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Data Bytes",        radiostats->tx_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Rx Data Packets",      radiostats->rx_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Data Bytes",        radiostats->rx_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Tx Unicast Data Packets",
            radiostats->tx_ucast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Multi/Broadcast Data Packets",
            radiostats->tx_mbcast_data_packets);

    APSTATS_PRINT_GENERAL(fp, "Tx Data Packets per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", radiostats->tx_data_wme[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", radiostats->tx_data_wme[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", radiostats->tx_data_wme[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", radiostats->tx_data_wme[WME_AC_VO]);

    APSTATS_PRINT_GENERAL(fp, "Rx Data Packets per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", radiostats->rx_data_wme[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", radiostats->rx_data_wme[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", radiostats->rx_data_wme[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", radiostats->rx_data_wme[WME_AC_VO]);

    if (radiostats->chan_util_enab) {
        APSTATS_PRINT_STAT16(fp, "Channel Utilization (0-255)",  radiostats->chan_util);
    } else {
        APSTATS_PRINT_STAT_UNVLBL(fp, "Channel Utilization (0-255)", "<DISABLED>");
    }

    APSTATS_PRINT_STAT64(fp, "Tx Beacon Frames",     radiostats->tx_beacon_frames);
    APSTATS_PRINT_STAT64(fp, "Tx Mgmt Frames",       radiostats->tx_mgmt_frames);
    APSTATS_PRINT_STAT64(fp, "Rx Mgmt Frames",       radiostats->rx_mgmt_frames);
    APSTATS_PRINT_STAT64(fp, "Rx Mgmt Frames dropped(RSSI too low)", radiostats->rx_mgmt_frames_rssi_drop);
    APSTATS_PRINT_STAT64(fp, "Tx Ctl Frames",        radiostats->tx_ctl_frames);
    APSTATS_PRINT_STAT64(fp, "Rx Ctl Frames",        radiostats->rx_ctl_frames);
    APSTATS_PRINT_STAT8(fp, "Rx RSSI",               radiostats->rx_rssi);
    APSTATS_PRINT_STAT64(fp, "Rx PHY errors",        radiostats->rx_phyerr);
    APSTATS_PRINT_STAT64(fp, "Rx CRC errors",        radiostats->rx_crcerr);
    APSTATS_PRINT_STAT64(fp, "Rx MIC errors",        radiostats->rx_micerr);
    APSTATS_PRINT_STAT64(fp, "Rx Decryption errors", radiostats->rx_decrypterr);
    APSTATS_PRINT_STAT64(fp, "Rx errors",            radiostats->rx_err);
    APSTATS_PRINT_STAT64(fp, "Tx failures",          radiostats->tx_err);
    APSTATS_PRINT_STAT64(fp, "Tx Dropped",           radiostats->tx_discard);
    APSTATS_PRINT_STAT64(fp, "Connections refuse Radio limit",    radiostats->sta_xceed_rlim);
    APSTATS_PRINT_STAT64(fp, "Connections refuse Vap limit",      radiostats->sta_xceed_vlim);
    APSTATS_PRINT_STAT64(fp, "802.11 Auth Attempts",       radiostats->mlme_auth_attempt);
    APSTATS_PRINT_STAT64(fp, "802.11 Auth Success",        radiostats->mlme_auth_success);
    APSTATS_PRINT_STAT64(fp, "MLME Authorize Attempts",    radiostats->authorize_attempt);
    APSTATS_PRINT_STAT64(fp, "MLME Authorize Success",     radiostats->authorize_success);
    APSTATS_PRINT_STAT8(fp, "Self BSS chan util",          radiostats->self_bss_util);
    APSTATS_PRINT_STAT8(fp, "OBSS chan util",              radiostats->obss_util);
    APSTATS_PRINT_GENERAL(fp, "lithium_cycle_counts:\n");
    APSTATS_PRINT_STAT16_SIGNED(fp, "lithium_cycle_cnt: Chan NF (BDF averaged NF_dBm)",
            radiostats->chan_nf);
    APSTATS_PRINT_STAT32(fp, "lithium_cycle_cnt: Tx Frame Cnt",
            radiostats->tx_frame_count);
    APSTATS_PRINT_STAT32(fp, "lithium_cycle_cnt: Rx Frame Cnt",
            radiostats->rx_frame_count);
    APSTATS_PRINT_STAT32(fp, "lithium_cycle_cnt: Rx Clear Cnt",
            radiostats->rx_clear_count);
    APSTATS_PRINT_STAT32(fp, "lithium_cycle_cnt: Cycle Cnt",
            radiostats->cycle_count);
    APSTATS_PRINT_STAT32(fp, "lithium_cycle_cnt: Phy Err Cnt",
            radiostats->phy_err_count);
    APSTATS_PRINT_STAT32(fp, "lithium_cycle_cnt: Chan Tx Pwr",
            radiostats->chan_tx_pwr);
    if (radiostats->current_pp) {
        APSTATS_PRINT_STAT32(fp, "Current profile periodicity",
                             radiostats->current_pp);
    } else {
        APSTATS_PRINT_STAT_UNVLBL(fp, "Current profile periodicity",
                                  "<DISABLED>");
    }

    APSTATS_PRINT_STAT32(fp, "Number of Active Vaps", radiostats->no_act_vaps);
    if (radiostats->tx_vap != NO_TX_VAP) {
        APSTATS_PRINT_STAT32(fp, "TX Vap ID", radiostats->tx_vap);
    } else {
        APSTATS_PRINT_STAT_UNVLBL(fp, "TX Vap ID", "<DISABLED>");
    }

    if (radiostats->thrput_enab) {
        APSTATS_PRINT_STAT32(fp, "Throughput (kbps)",  radiostats->thrput);
    } else {
        APSTATS_PRINT_STAT_UNVLBL(fp, "Throughput (kbps)", "<DISABLED>");
    }

    if (radiostats->prdic_per_enab) {
        APSTATS_PRINT_STAT8(fp, "PER over configured period (%)",
                radiostats->prdic_per);
    } else {
        APSTATS_PRINT_STAT_UNVLBL(fp, "PER over configured period (%)",
                "<DISABLED>");
    }

    APSTATS_PRINT_STAT8(fp, "Total PER (%)",         radiostats->total_per);

    APSTATS_PRINT_GENERAL(fp, "Co-located RNR stats:\n");
    APSTATS_PRINT_STAT32(fp, " Created vap:", radiostats->created_vap);
    APSTATS_PRINT_STAT32(fp, " Active vap:", radiostats->active_vap);
    APSTATS_PRINT_STAT32(fp, " RNR count:", radiostats->rnr_count);
    APSTATS_PRINT_STAT32(fp, " 6GHz SoC status:", radiostats->soc_status_6ghz);
    APSTATS_PRINT_GENERAL(fp, "\n");

    if (!recursion) {
        return 0;
    }

    curr_vs_ptr = (vaplevel_stats_t*)radiostats->obj.firstchild;

    while(curr_vs_ptr) {
        vaplevel_display_stats(fp, curr_vs_ptr, recursion);
        curr_vs_ptr = curr_vs_ptr->obj.next;
    }
    return 0;
}

static int vaplevel_gather_stats(int sockfd,
        vaplevel_stats_t *vapstats, bool recursion)
{
    nodelevel_stats_t *curr_ns_ptr = NULL;
    u_int64_t tx_rate_numrtr = 0;
    u_int64_t rx_rate_numrtr = 0;
    u_int16_t txrx_rate_denomntr = 0;
    u_int16_t total_per_numrtr = 0;
    u_int16_t total_per_denomntr = 0;

    struct ieee80211_stats *stats;
    struct ieee80211_mac_stats *ucaststats;
    struct ieee80211_mac_stats *mcaststats;
    struct ifreq ifr;
    int    stats_total_len = sizeof(struct ieee80211_stats) +
        (2 * sizeof(struct ieee80211_mac_stats)) +
        4;
    int i = 0;

    assert(vapstats != NULL);

    /*
     * APSTATS optimization is done only for CFG80211.
     * In all other case, It will take older Path
     */
#if UMAC_SUPPORT_CFG80211
    if (!recursion && cfg_flag)
        return collect_vaplevel_stats(vapstats);
#endif

    /* Gather pure VAP level stats */

    stats = (struct ieee80211_stats *)malloc(stats_total_len);
    if (stats == NULL) {
        return -ENOMEM;
    }

    memset(stats, 0, stats_total_len);
    memset(ifr.ifr_name, '\0', sizeof(ifr.ifr_name));
    if (strlcpy(ifr.ifr_name, vapstats->ifname, sizeof(ifr.ifr_name))
            >= sizeof(ifr.ifr_name)) {
        APSTATS_ERROR("%s(): %d Error creating ifname \n", __func__, __LINE__);
        free(stats);
        return -1;
    }
    ap_send_command(vapstats->ifname, (void *)stats, sizeof(struct ieee80211_stats) +
            (2 * sizeof(struct ieee80211_mac_stats)) +
            4 , QCA_NL80211_VENDOR_SUBCMD_80211STATS, SIOCG80211STATS);

    ucaststats = (struct ieee80211_mac_stats*)
        ((unsigned char *)stats +
         sizeof(struct ieee80211_stats));
    mcaststats = (struct ieee80211_mac_stats*)
        ((unsigned char *)ucaststats +
         sizeof(struct ieee80211_mac_stats));

    /*
     * Note that mcaststats cover broadcast stats as well.
     * Multicast and broadcast frames are treated the same
     * way in most portions of the WLAN driver, and this is
     * reflected in bunching together of the stats as well.
     */
    vapstats->tx_offer_packets = stats->tx_offer_pkt_cnt;
    vapstats->tx_offer_packets_bytes = stats->tx_offer_pkt_bytes_cnt;
    vapstats->mgmt_tx_fail = stats->mgmt_tx_fail;
    vapstats->tx_data_packets = ucaststats->ims_tx_data_packets +
        mcaststats->ims_tx_data_packets;
    vapstats->tx_data_bytes   = ucaststats->ims_tx_data_bytes +
                                mcaststats->ims_tx_data_bytes;
    vapstats->tx_eapol_packets = ucaststats->ims_tx_eapol_packets;
    vapstats->rx_data_packets = ucaststats->ims_rx_data_packets +
        mcaststats->ims_rx_data_packets;
    vapstats->rx_data_bytes   = ucaststats->ims_rx_data_bytes +
        mcaststats->ims_rx_data_bytes;

    vapstats->tx_datapyld_bytes   = ucaststats->ims_tx_datapyld_bytes +
        mcaststats->ims_tx_datapyld_bytes;
    vapstats->rx_datapyld_bytes   = ucaststats->ims_rx_datapyld_bytes +
        mcaststats->ims_rx_datapyld_bytes;

    for (i = 0;i < WME_NUM_AC; i++) {
        vapstats->tx_data_wme[i] = ucaststats->ims_tx_wme[i] +
            mcaststats->ims_tx_wme[i];
        vapstats->rx_data_wme[i] = ucaststats->ims_rx_wme[i] +
            mcaststats->ims_rx_wme[i];
    }

    vapstats->tx_ucast_data_packets  = ucaststats->ims_tx_data_packets;
    vapstats->rx_ucast_data_packets  = ucaststats->ims_rx_data_packets;
    vapstats->tx_mbcast_data_packets = mcaststats->ims_tx_data_packets;
    vapstats->rx_mbcast_data_packets = mcaststats->ims_rx_data_packets;
    vapstats->tx_bcast_data_packets = mcaststats->ims_tx_bcast_data_packets;
    vapstats->tx_bcast_data_bytes = mcaststats->ims_tx_bcast_data_bytes;
    vapstats->rx_bcast_data_packets = mcaststats->ims_rx_bcast_data_packets;

    vapstats->rx_micerr       = ucaststats->ims_rx_tkipmic +
        ucaststats->ims_rx_ccmpmic +
        ucaststats->ims_rx_wpimic  +
        mcaststats->ims_rx_tkipmic +
        mcaststats->ims_rx_ccmpmic +
        mcaststats->ims_rx_wpimic;

    vapstats->rx_decrypterr   = ucaststats->ims_rx_decryptcrc +
        mcaststats->ims_rx_decryptcrc;

    /*
     * There are various definitions possible for Rx error count.
     * We use the pre-existing, standard definition for
     * compatibility.
     */
    vapstats->rx_err          = stats->is_rx_tooshort +
        stats->is_rx_decap +
        stats->is_rx_nobuf +
        vapstats->rx_decrypterr +
        vapstats->rx_micerr +
        ucaststats->ims_rx_tkipicv +
        mcaststats->ims_rx_tkipicv +
        ucaststats->ims_rx_wepfail +
        mcaststats->ims_rx_wepfail +
        ucaststats->ims_rx_fcserr +
        mcaststats->ims_rx_fcserr +
        ucaststats->ims_rx_tkipmic +
        mcaststats->ims_rx_tkipmic +
        ucaststats->ims_rx_decryptcrc +
        mcaststats->ims_rx_decryptcrc;


    vapstats->tx_discard      = ucaststats->ims_tx_discard +
        mcaststats->ims_tx_discard+
        stats->is_tx_nobuf;
    vapstats->host_discard    = stats->is_tx_nobuf;
    vapstats->tx_err          = stats->is_tx_not_ok ;
    vapstats->total_num_offchan_tx_mgmt = stats->total_num_offchan_tx_mgmt;
    vapstats->total_num_offchan_tx_data = stats->total_num_offchan_tx_data;
    vapstats->num_offchan_tx_failed = stats->num_offchan_tx_failed;
    vapstats->tx_beacon_swba_cnt = stats->tx_beacon_swba_cnt;
    vapstats->tx_mgmt         = ucaststats->ims_tx_mgmt;
    vapstats->rx_mgmt         = ucaststats->ims_rx_mgmt;
    vapstats->sta_xceed_rlim  = stats->sta_xceed_rlim;
    vapstats->sta_xceed_vlim  = stats->sta_xceed_vlim;
    vapstats->mlme_auth_attempt  = stats->mlme_auth_attempt;
    vapstats->mlme_auth_success  = stats->mlme_auth_success;
    vapstats->authorize_attempt  = stats->authorize_attempt;
    vapstats->authorize_success  = stats->authorize_success;
    vapstats->peer_delete_req    = stats->peer_delete_req;
    vapstats->peer_delete_resp   = stats->peer_delete_resp;
    vapstats->peer_delete_all_req    = stats->peer_delete_all_req;
    vapstats->peer_delete_all_resp   = stats->peer_delete_all_resp;
    vapstats->prob_req_drops  = stats->prob_req_drops;
    vapstats->oob_probe_req_count    = stats->oob_probe_req_count;
    vapstats->wc_probe_req_drops    = stats->wc_probe_req_drops;
    vapstats->current_pp = get_vap_priv_int_param(sockfd, vapstats->ifname,
                                                  IEEE80211_PARAM_CURRENT_PP);
    vapstats->no_act_vaps = get_vap_priv_int_param(sockfd, vapstats->ifname,
                                                   IEEE80211_PARAM_NO_ACT_VAPS);
    vapstats->tx_vap = get_vap_priv_int_param(sockfd, vapstats->ifname,
                                              IEEE80211_PARAM_TX_VAP);
    vapstats->fils_frames_sent   = stats->fils_frames_sent;
    vapstats->fils_frames_sent_fail   = stats->fils_frames_sent_fail;
    vapstats->fils_enable       = get_vap_priv_int_param(
                                                sockfd,
                                                vapstats->ifname,
                                                IEEE80211_PARAM_FILS_IS_ENABLE);

#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    vapstats->chan_util_enab  = get_vap_priv_int_param(
            sockfd,
            vapstats->ifname,
            IEEE80211_PARAM_CHAN_UTIL_ENAB);

    if (vapstats->chan_util_enab) {
        vapstats->chan_util       = get_vap_priv_int_param(
                sockfd,
                vapstats->ifname,
                IEEE80211_PARAM_CHAN_UTIL);
    }
#else
    vapstats->chan_util_enab = 0;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
    vapstats->u_last_tx_rate  = ucaststats->ims_last_tx_rate;
    vapstats->m_last_tx_rate  = mcaststats->ims_last_tx_rate;
    vapstats->u_last_tx_rate_mcs  = ucaststats->ims_last_tx_rate_mcs;
    vapstats->m_last_tx_rate_mcs  = mcaststats->ims_last_tx_rate_mcs;
    vapstats->retries = ucaststats->ims_retries;
    vapstats->tx_bcn_succ_cnt = stats->tx_bcn_succ_cnt;
    vapstats->tx_bcn_outage_cnt = stats->tx_bcn_outage_cnt;

    vapstats->tx_offload_prb_resp_succ_cnt =
                    stats->tx_offload_prb_resp_succ_cnt;
    vapstats->tx_offload_prb_resp_fail_cnt =
                    stats->tx_offload_prb_resp_fail_cnt;
    vapstats->tx_20TU_prb_resp = stats->tx_20TU_prb_resp;
    vapstats->tx_20TU_prb_interval = stats->tx_20TU_prb_interval;

    free(stats);

    /* Gather Node level stats. */
    curr_ns_ptr = (nodelevel_stats_t*)vapstats->obj.firstchild;

    while(curr_ns_ptr) {
        nodelevel_gather_stats(sockfd, curr_ns_ptr);

        total_per_numrtr += curr_ns_ptr->last_per;
        total_per_denomntr++;
        vapstats->txrx_rate_available = 1;
        txrx_rate_denomntr++;
        tx_rate_numrtr += curr_ns_ptr->tx_rate;
        rx_rate_numrtr += curr_ns_ptr->rx_rate;
        for (i = 0;i < WME_NUM_AC;i++) {
            vapstats->excretries[i] +=
                curr_ns_ptr->excretries[i];
        }

        vapstats->rx_mgmt += curr_ns_ptr->rx_mgmt;
        vapstats->tx_mgmt += curr_ns_ptr->tx_mgmt;
        curr_ns_ptr = curr_ns_ptr->obj.next;
    }

    if (vapstats->obj.firstchild != NULL) {
        if (vapstats->txrx_rate_available) {
            vapstats->tx_rate = tx_rate_numrtr/txrx_rate_denomntr;
            vapstats->rx_rate = rx_rate_numrtr/txrx_rate_denomntr;
        }

        /* Other averaging goes here. */
        vapstats->last_per = total_per_numrtr/total_per_denomntr;
    }
    return 0;
}

static int vaplevel_display_stats(FILE *fp, vaplevel_stats_t *vapstats,
        bool recursion)
{
    nodelevel_stats_t *curr_ns_ptr = NULL;

    assert(vapstats != NULL);

    APSTATS_PRINT_GENERAL(fp, "VAP Level Stats: %s (under radio %s)\n",
            vapstats->ifname,
            ((radiolevel_stats_t*)vapstats->obj.parent)->ifname);
    APSTATS_PRINT_STAT64(fp, "Tx Data Packets",       vapstats->tx_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Data Bytes",         vapstats->tx_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Tx Offer Data Packets", vapstats->tx_offer_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Offer Data Bytes",   vapstats->tx_offer_packets_bytes);
    APSTATS_PRINT_STAT64(fp, "Tx Data Payload Bytes", vapstats->tx_datapyld_bytes);
    APSTATS_PRINT_STAT64(fp, "Tx Eapol Packets",      vapstats->tx_eapol_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Data Packets",       vapstats->rx_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Data Bytes",         vapstats->rx_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Rx Data Payload Bytes", vapstats->rx_datapyld_bytes);

    APSTATS_PRINT_GENERAL(fp, "Tx Data Packets per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", vapstats->tx_data_wme[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", vapstats->tx_data_wme[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", vapstats->tx_data_wme[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", vapstats->tx_data_wme[WME_AC_VO]);

    APSTATS_PRINT_GENERAL(fp, "Rx Data Packets per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", vapstats->rx_data_wme[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", vapstats->rx_data_wme[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", vapstats->rx_data_wme[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", vapstats->rx_data_wme[WME_AC_VO]);

    APSTATS_PRINT_STAT64(fp, "Tx Unicast Data Packets",
            vapstats->tx_ucast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Unicast Data Packets",
            vapstats->rx_ucast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Multi/Broadcast Data Packets",
            vapstats->tx_mbcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Multi/Broadcast Data Packets",
            vapstats->rx_mbcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Last Packet Error Rate(PER)",
            vapstats->last_per);

    if (vapstats->txrx_rate_available) {
        APSTATS_PRINT_STAT32(fp, "Average Tx Rate (kbps)",vapstats->tx_rate);
        APSTATS_PRINT_STAT32(fp, "Average Rx Rate (kbps)",vapstats->rx_rate);
    } else {
        APSTATS_PRINT_STAT_UNVLBL(fp, "Average Tx Rate (kbps)", "<NO STA>");
        APSTATS_PRINT_STAT_UNVLBL(fp, "Average Rx Rate (kbps)", "<NO STA>");
    }

    APSTATS_PRINT_STAT64(fp, "Tx multicast Data Packets",
            vapstats->tx_mbcast_data_packets - vapstats->tx_bcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Broadcast Data Packets",
            vapstats->tx_bcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Broadcast Data Bytes",
            vapstats->tx_bcast_data_bytes);

    if (vapstats->rx_mbcast_data_packets >= vapstats->rx_bcast_data_packets) {
        APSTATS_PRINT_STAT64(fp, "Rx multicast Data Packets",
                vapstats->rx_mbcast_data_packets - vapstats->rx_bcast_data_packets);
    } else {
        APSTATS_PRINT_STAT64(fp, "Rx multicast Data Packets", vapstats->rx_mbcast_data_packets);
    }

    APSTATS_PRINT_STAT64(fp, "Rx Broadcast Data Packets",
            vapstats->rx_bcast_data_packets);

    APSTATS_PRINT_STAT64(fp, "Packets Dropped",vapstats->rx_discard + vapstats->tx_discard);
    APSTATS_PRINT_STAT64(fp, "Packets Errored",vapstats->rx_err + vapstats->tx_err);
    APSTATS_PRINT_STAT64(fp, "Rx errors",             vapstats->rx_err);
    APSTATS_PRINT_STAT64(fp, "Rx Dropped",         vapstats->rx_discard);
    APSTATS_PRINT_STAT64(fp, "Tx failures",           vapstats->tx_err);
    APSTATS_PRINT_STAT64(fp, "Tx Dropped",            vapstats->tx_discard);
    APSTATS_PRINT_STAT64(fp, "Tx Mgmt Failures",      vapstats->mgmt_tx_fail);
    APSTATS_PRINT_STAT64(fp, "Host Discard",           vapstats->host_discard);
    APSTATS_PRINT_STAT64(fp, "Rx MIC Errors",          vapstats->rx_micerr);
    APSTATS_PRINT_STAT64(fp, "Last Tx rate for unicast Packets       ",      vapstats->u_last_tx_rate);
    APSTATS_PRINT_STAT64(fp, "Last Tx rate for unicast Packets(mcs)  ",      vapstats->u_last_tx_rate_mcs);
    APSTATS_PRINT_STAT64(fp, "Last Tx rate for multicast Packets     ",      vapstats->m_last_tx_rate);
    APSTATS_PRINT_STAT64(fp, "Last Tx rate for multicast Packets(mcs)",      vapstats->m_last_tx_rate_mcs);
    APSTATS_PRINT_STAT32(fp, "Total number of offchan TX mgmt frames",       vapstats->total_num_offchan_tx_mgmt);
    APSTATS_PRINT_STAT32(fp, "Total number of offchan TX data frames",       vapstats->total_num_offchan_tx_data);
    APSTATS_PRINT_STAT32(fp, "Number of failed offchan TX frames",           vapstats->num_offchan_tx_failed);
    APSTATS_PRINT_STAT64(fp, "Total beacons sent to fw in SWBA intr",      vapstats->tx_beacon_swba_cnt);
    APSTATS_PRINT_STAT64(fp, "Retries", vapstats->retries);
    APSTATS_PRINT_STAT64(fp, "Tx Mgmt Packets",        vapstats->tx_mgmt);
    APSTATS_PRINT_STAT64(fp, "Rx Mgmt Packets",        vapstats->rx_mgmt);

    APSTATS_PRINT_STAT64(fp, "Connections refuse Radio limit",    vapstats->sta_xceed_rlim);
    APSTATS_PRINT_STAT64(fp, "Connections refuse Vap limit",      vapstats->sta_xceed_vlim);
    APSTATS_PRINT_STAT64(fp, "802.11 Auth Attempts",       vapstats->mlme_auth_attempt);
    APSTATS_PRINT_STAT64(fp, "802.11 Auth Success",        vapstats->mlme_auth_success);
    APSTATS_PRINT_STAT64(fp, "MLME Authorize Attempts",    vapstats->authorize_attempt);
    APSTATS_PRINT_STAT64(fp, "MLME Authorize Success",     vapstats->authorize_success);
    APSTATS_PRINT_STAT64(fp, "Peer delete req",            vapstats->peer_delete_req);
    APSTATS_PRINT_STAT64(fp, "Peer delete resp",           vapstats->peer_delete_resp);
    APSTATS_PRINT_STAT64(fp, "Peer delete all req", vapstats->peer_delete_all_req);
    APSTATS_PRINT_STAT64(fp, "Peer delete all resp", vapstats->peer_delete_all_resp);

    APSTATS_PRINT_GENERAL(fp, "Excessive retries per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", vapstats->excretries[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", vapstats->excretries[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", vapstats->excretries[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", vapstats->excretries[WME_AC_VO]);
    APSTATS_PRINT_STAT64(fp, "Beacon success", (u_int64_t) vapstats->tx_bcn_succ_cnt);
    APSTATS_PRINT_STAT64(fp, "Beacon failed", (u_int64_t) vapstats->tx_bcn_outage_cnt);
    APSTATS_PRINT_STAT64(fp, "Probe request drops", (u_int64_t) vapstats->prob_req_drops);
    APSTATS_PRINT_STAT64(fp, "OOB probe requests", (u_int64_t) vapstats->oob_probe_req_count);
    APSTATS_PRINT_STAT64(fp, "Wildcard probe requests drops", (u_int64_t) vapstats->wc_probe_req_drops);
    APSTATS_PRINT_STAT64(fp, "FILS enable", (u_int64_t) vapstats->fils_enable);
    APSTATS_PRINT_STAT64(fp, "FILS frames sent", (u_int64_t) vapstats->fils_frames_sent);
    APSTATS_PRINT_STAT64(fp, "FILS frames sent fail", (u_int64_t) vapstats->fils_frames_sent_fail);

    APSTATS_PRINT_GENERAL(fp, "6GHz stats:\n");
    APSTATS_PRINT_STAT64(fp, " unsolicited probe response success", (u_int64_t) vapstats->tx_offload_prb_resp_succ_cnt);
    APSTATS_PRINT_STAT64(fp, " unsolicited probe response failed", (u_int64_t) vapstats->tx_offload_prb_resp_fail_cnt);
    APSTATS_PRINT_STAT64(fp, " 20TU probe response status" , (u_int64_t) vapstats->tx_20TU_prb_resp);
    APSTATS_PRINT_STAT64(fp, " 20TU probe response interval" , (u_int64_t) vapstats->tx_20TU_prb_interval);
    APSTATS_PRINT_STAT64(fp, "Non-Tx Profile rollback count when ema_ext enabled" , (u_int64_t) vapstats->ntx_pfl_rollback_stats);
    APSTATS_PRINT_STAT64(fp, "IE Overflow count for Tx/Non-Tx VAP Beacon resource overflow", (u_int64_t) vapstats->ie_overflow_stats);
    APSTATS_PRINT_GENERAL(fp, "\n");

    if (!recursion) {
        return 0;
    }

    curr_ns_ptr = (nodelevel_stats_t*)vapstats->obj.firstchild;

    while(curr_ns_ptr) {
        nodelevel_display_stats(fp, curr_ns_ptr);
        curr_ns_ptr = curr_ns_ptr->obj.next;
    }
    return 0;
}

#ifdef VDEV_PEER_PROTOCOL_COUNT
static void update_nodestats_peer_prot(nodelevel_stats_t *nodestats,
                                       const struct ieee80211_nodestats *ns)
{
    nodestats->icmp_tx_ingress = ns->icmp_tx_ingress;
    nodestats->icmp_tx_egress  = ns->icmp_tx_egress;
    nodestats->icmp_rx_ingress = ns->icmp_rx_ingress;
    nodestats->icmp_rx_egress  = ns->icmp_rx_egress;

    nodestats->arp_tx_ingress = ns->arp_tx_ingress;
    nodestats->arp_tx_egress  = ns->arp_tx_egress;
    nodestats->arp_rx_ingress = ns->arp_rx_ingress;
    nodestats->arp_rx_egress  = ns->arp_rx_egress;

    nodestats->eap_tx_ingress = ns->eap_tx_ingress;
    nodestats->eap_tx_egress  = ns->eap_tx_egress;
    nodestats->eap_rx_ingress = ns->eap_rx_ingress;
    nodestats->eap_rx_egress  = ns->eap_rx_egress;
}
#else
static void update_nodestats_peer_prot(nodelevel_stats_t *nodestats,
                                       const struct ieee80211_nodestats *ns)
{
}
#endif

static int nodelevel_gather_stats(int sockfd,
        nodelevel_stats_t *nodestats)
{
    struct iwreq iwr;
    struct ieee80211req_sta_stats stats = {0};
    const struct ieee80211_nodestats *ns = &stats.is_stats;
    struct ieee80211req_sta_info *si = &nodestats->si;
    int i = 0;
#if UMAC_SUPPORT_CFG80211
    struct cfg80211_data buffer;
#endif
    int msg;

    assert(nodestats != NULL);
    memset(&iwr, 0, sizeof(iwr));
    if (strlcpy(iwr.ifr_name, ((vaplevel_stats_t*)nodestats->obj.parent)->ifname,
                sizeof(iwr.ifr_name))
            >= sizeof(iwr.ifr_name)) {
        APSTATS_ERROR("%s(): %d Error creating ifname \n", __func__, __LINE__);
        return -1;
    }

    /* Is the sta connected to DA or OFFLOAD device */
    nodestats->ol_enable = get_radio_priv_int_param(sockfd, ((radiolevel_stats_t*)((vaplevel_stats_t*)
                    nodestats->obj.parent)->obj.parent)->ifname, OL_ATH_PARAM_GET_IF_ID);

    iwr.u.data.pointer = (void *)&stats;
    iwr.u.data.length = sizeof(stats);
    memcpy(stats.is_u.macaddr,
            nodestats->macaddr.ether_addr_octet,
            QDF_MAC_ADDR_SIZE);

    if (!cfg_flag) {
        if (ioctl(sockfd, IEEE80211_IOCTL_STA_STATS, &iwr) < 0) {
            perror("IEEE80211_IOCTL_STA_STATS");
            return -1;
        }
    } else {
#if UMAC_SUPPORT_CFG80211
        buffer.data = (uint8_t *)&stats;
        buffer.length = sizeof(stats);
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_STA_STATS,
                ((vaplevel_stats_t*)nodestats->obj.parent)->ifname, (char *)&buffer, LIST_STATION_CFG_ALLOC_SIZE);
        if (msg < 0) {
            fprintf(stderr, "Couldn't send NL command\n");
            return -EIO;
        }
#endif
    }

#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    nodestats->tx_data_packets  = ns->ns_tx_data;
    nodestats->tx_data_bytes    = ns->ns_tx_bytes;
    nodestats->tx_data_packets_success = ns->ns_tx_data_success;
    nodestats->tx_data_bytes_success   = ns->ns_tx_bytes_success;
#endif
    update_nodestats_peer_prot(nodestats, ns);

    nodestats->rx_data_packets  = ns->ns_rx_data;
    nodestats->rx_data_bytes    = ns->ns_rx_bytes;
#if WLAN_SUPPORT_TWT
    nodestats->tx_data_packets_success_twt = ns->ns_tx_data_success_twt;
    nodestats->rx_data_packets_twt  = ns->ns_rx_data_twt;
#endif
    for (i = 0;i < WME_NUM_AC; i++) {
        nodestats->tx_data_wme[i] = ns->ns_tx_wme[i];
        nodestats->rx_data_wme[i] = ns->ns_rx_wme[i];
    }

    nodestats->num_rx_mpdus = ns->ns_rx_mpdus;
    nodestats->num_rx_ppdus = ns->ns_rx_ppdus;
    nodestats->num_rx_retries = ns->ns_rx_retries;

#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    nodestats->rx_ucast_data_packets = ns->ns_rx_ucast;
    nodestats->rx_mcast_data_packets = ns->ns_rx_mcast;
    nodestats->rx_ucast_data_bytes   = ns->ns_rx_ucast_bytes;
    nodestats->rx_mcast_data_bytes   = ns->ns_rx_mcast_bytes;
#endif
    {
        int mode, mcs;

        for (mode = 0; mode < DOT11_MAX; mode++) {
            for (mcs = 0; mcs < IEEE80211_MAX_MCS; mcs++) {
                nodestats->mcs_tx[mode][mcs] = ns->mcs_tx[mode][mcs];
                nodestats->mcs_rx[mode][mcs] = ns->mcs_rx[mode][mcs];
            }
        }
    }

    {
        int ru_index;

        for (ru_index = 0; ru_index < RU_INDEX_MAX; ru_index++) {
            nodestats->ru_tx[ru_index] = ns->ru_tx[ru_index];
            nodestats->ru_rx[ru_index] = ns->ru_rx[ru_index];
        }
    }
    nodestats->tx_ucast_data_packets  = ns->ns_tx_ucast;
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    nodestats->tx_ucast_data_bytes    = ns->ns_tx_ucast_bytes;
    nodestats->tx_mcast_data_packets  = ns->ns_tx_mcast;
    nodestats->tx_mcast_data_bytes    = ns->ns_tx_mcast_bytes;
    nodestats->tx_bcast_data_packets  = ns->ns_tx_bcast;
    nodestats->tx_bcast_data_bytes    = ns->ns_tx_bcast_bytes;
#endif
    nodestats->last_per               = ns->ns_last_per;
#if ATH_PERF_PWR_OFFLOAD
    memcpy(nodestats->ack_rssi, ns->ns_rssi_chain, sizeof(ns->ns_rssi_chain));
#endif
    nodestats->packets_queued         = nodestats->tx_data_packets + ns->ns_is_tx_not_ok;
    nodestats->tx_failed         = ns->ns_is_tx_not_ok;

    /*
     * As an optimization, ieee80211req_sta_info has already
     * been copied into nodestats after the IEEE80211_IOCTL_STA_INFO
     * ioctl call in nodestats_hierarchy_init()
     */

    if (si->isi_txratekbps == 0) {
        nodestats->tx_rate = ((si->isi_rates[si->isi_txrate] &
                    IEEE80211_RATE_VAL) * 1000) / 2;
    } else {
        nodestats->tx_rate = si->isi_txratekbps;
    }

    nodestats->rx_rate       = si->isi_rxratekbps;

    nodestats->rx_micerr        = ns->ns_rx_tkipmic +
        ns->ns_rx_ccmpmic +
        ns->ns_rx_wpimic;
    nodestats->last_tx_rate     = ns->ns_last_tx_rate;
    nodestats->last_rx_rate     = ns->ns_last_rx_rate;
    nodestats->last_rx_mgmt_rate = ns->ns_last_rx_mgmt_rate;

    nodestats->rx_decrypterr    = ns->ns_rx_decryptcrc;

#if ATH_SUPPORT_EXT_STAT
    nodestats->htcap   = si->isi_htcap;
    nodestats->vhtcap  = si->isi_vhtcap;
    nodestats->chwidth = si->isi_chwidth;

    nodestats->tx_bytes_rate = ns->ns_tx_bytes_rate;
    nodestats->tx_data_rate  = ns->ns_tx_data_rate;
    nodestats->rx_bytes_rate = ns->ns_rx_bytes_rate;
    nodestats->rx_data_rate  = ns->ns_rx_data_rate;
#endif

    /*
     * There are various definitions possible for Rx error count.
     * We use the pre-existing, standard definition for VAP stats,
     * and remove some of the components which do not apply.
     */
    nodestats->rx_err           = ns->ns_rx_decap +
        ns->ns_rx_decryptcrc +
        nodestats->rx_micerr +
        ns->ns_rx_tkipicv +
        ns->ns_rx_wepfail;

    nodestats->tx_discard       = ns->ns_tx_discard + ns->ns_is_tx_nobuf;
    nodestats->rx_rssi          = si->isi_rssi;
    nodestats->rx_mgmt_rssi     = ns->ns_rx_mgmt_rssi;
    nodestats->host_discard     = ns->ns_is_tx_nobuf;
    nodestats->tx_mgmt          = ns->ns_tx_mgmt;
    nodestats->rx_mgmt          = ns->ns_rx_mgmt;

    nodestats->ppdu_tx_rate     = ns->ns_ppdu_tx_rate;
    nodestats->ppdu_rx_rate     = ns->ns_ppdu_rx_rate;
    nodestats->failed_retry_count = ns->ns_failed_retry_count;
    nodestats->retry_count = ns->ns_retry_count;
    nodestats->multiple_retry_count = ns->ns_multiple_retry_count;

    for (i = 0;i < WME_NUM_AC;i++) {
        nodestats->excretries[i] = ns->ns_excretries[i];
    }
#if WLAN_SUPPORT_TWT
    nodestats->twt_event_type = ns->ns_twt_event_type;
    nodestats->twt_flow_id = ns->ns_twt_flow_id;
    nodestats->twt_bcast = ns->ns_twt_bcast;
    nodestats->twt_trig = ns->ns_twt_trig;
    nodestats->twt_announ = ns->ns_twt_announ;
    nodestats->twt_dialog_id = ns->ns_twt_dialog_id;
    nodestats->twt_wake_dura_us = ns->ns_twt_wake_dura_us;
    nodestats->twt_wake_intvl_us = ns->ns_twt_wake_intvl_us;
    nodestats->twt_sp_offset_us = ns->ns_twt_sp_offset_us;
#endif
    return 0;
}

static char* macaddr_to_str(const struct ether_addr *addr)
{
    /*
     * Similar to ether_ntoa, but use a prettier format
     * where leading zeros are not discarded
     */
    static char string[3 * ETHER_ADDR_LEN];

    memset(string, 0, sizeof(string));

    if (addr != NULL) {

        snprintf(string,
                sizeof(string),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                addr->ether_addr_octet[0],
                addr->ether_addr_octet[1],
                addr->ether_addr_octet[2],
                addr->ether_addr_octet[3],
                addr->ether_addr_octet[4],
                addr->ether_addr_octet[5]);
    }

    return string;
}

#if ATH_SUPPORT_EXT_STAT
static void disaplay_band_width(FILE *fp, enum ieee80211_cwm_width ni_chwidth)
{
    switch(ni_chwidth)
    {
        case IEEE80211_CWM_WIDTH20:
            APSTATS_PRINT_STAT32(fp, "Band Width", 20);
            return;
        case IEEE80211_CWM_WIDTH40:
            APSTATS_PRINT_STAT32(fp, "Band Width", 40);
            return;
        case IEEE80211_CWM_WIDTH80:
            APSTATS_PRINT_STAT32(fp, "Band Width", 80);
            return;
        case IEEE80211_CWM_WIDTH160:
        case IEEE80211_CWM_WIDTH80_80:
            APSTATS_PRINT_STAT32(fp, "Band Width", 160);
            return;
        default:
            APSTATS_PRINT_GENERAL(fp, "Band Width: Unknown\n");
    }
}
#endif

#ifdef VDEV_PEER_PROTOCOL_COUNT
static void nodelevel_display_stats_peer_prot(FILE *fp, nodelevel_stats_t *nodestats)
{
    APSTATS_PRINT_GENERAL(fp, "Data Packets PROTOCOL Based:\n");
    APSTATS_PRINT_STAT16(fp, " ICMP tx ingress", nodestats->icmp_tx_ingress);
    APSTATS_PRINT_STAT16(fp, " ICMP tx egress",  nodestats->icmp_tx_egress);
    APSTATS_PRINT_STAT16(fp, " ICMP rx ingress", nodestats->icmp_rx_ingress);
    APSTATS_PRINT_STAT16(fp, " ICMP rx egress",  nodestats->icmp_rx_egress);

    APSTATS_PRINT_STAT16(fp, " ARP tx ingress", nodestats->arp_tx_ingress);
    APSTATS_PRINT_STAT16(fp, " ARP tx egress",  nodestats->arp_tx_egress);
    APSTATS_PRINT_STAT16(fp, " ARP rx ingress", nodestats->arp_rx_ingress);
    APSTATS_PRINT_STAT16(fp, " ARP rx egress",  nodestats->arp_rx_egress);

    APSTATS_PRINT_STAT16(fp, " EAP tx ingress", nodestats->eap_tx_ingress);
    APSTATS_PRINT_STAT16(fp, " EAP tx egress",  nodestats->eap_tx_egress);
    APSTATS_PRINT_STAT16(fp, " EAP rx ingress", nodestats->eap_rx_ingress);
    APSTATS_PRINT_STAT16(fp, " EAP rx egress",  nodestats->eap_rx_egress);
}
#else
static void nodelevel_display_stats_peer_prot(FILE *fp, nodelevel_stats_t *nodestats)
{
}
#endif

static int nodelevel_display_stats(FILE *fp, nodelevel_stats_t *nodestats)
{
    assert(nodestats != NULL);
    struct ieee80211req_sta_info *si = &nodestats->si;
#if WLAN_SUPPORT_TWT
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    uint32_t tx_percent;
#endif
    uint32_t rx_percent;
#endif

#if ATH_SUPPORT_EXT_STAT
    u_int8_t tx_stbc = (nodestats->htcap & IEEE80211_HTCAP_C_TXSTBC) || (nodestats->vhtcap & IEEE80211_VHTCAP_TX_STBC);
    u_int8_t rx_stbc = (nodestats->htcap & IEEE80211_HTCAP_C_RXSTBC) || (nodestats->vhtcap & IEEE80211_VHTCAP_RX_STBC);
#endif

    APSTATS_PRINT_GENERAL(fp, "Node Level Stats: %s (under VAP %s)\n",
            macaddr_to_str(&nodestats->macaddr),
            ((vaplevel_stats_t*)nodestats->obj.parent)->ifname);
    APSTATS_PRINT_STAT64(fp, "Tx Data Packets", nodestats->tx_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Data Bytes", nodestats->tx_data_bytes);
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    APSTATS_PRINT_STAT64(fp, "Tx Success Data Packets", nodestats->tx_data_packets_success);
    APSTATS_PRINT_STAT64(fp, "Tx Success Data Bytes", nodestats->tx_data_bytes_success);
#endif
    nodelevel_display_stats_peer_prot(fp, nodestats);

    APSTATS_PRINT_GENERAL(fp, "Tx Data Packets per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", nodestats->tx_data_wme[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", nodestats->tx_data_wme[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", nodestats->tx_data_wme[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", nodestats->tx_data_wme[WME_AC_VO]);

    APSTATS_PRINT_GENERAL(fp, "Rx Data Packets per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", nodestats->rx_data_wme[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", nodestats->rx_data_wme[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", nodestats->rx_data_wme[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", nodestats->rx_data_wme[WME_AC_VO]);

#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    APSTATS_PRINT_STAT64(fp, "Tx Success Unicast Data Packets", nodestats->tx_ucast_data_packets);
    APSTATS_PRINT_GENERAL(fp, "TX MCS Stats\n");
    {
        int mcs, mode;

        for (mode = 0; mode < DOT11_MAX; mode++) {
            for (mcs = 0; mcs < IEEE80211_MAX_MCS; mcs++) {
                if (cdp_rate_string[mode][mcs].valid) {
                    APSTATS_PRINT_GENERAL(fp, "%s: %d\n",
                                          cdp_rate_string[mode][mcs].mcs_type,
                                          nodestats->mcs_tx[mode][mcs]);
                }
            }
        }
    }
    APSTATS_PRINT_GENERAL(fp, "RX MCS Stats\n");
    {
        int mcs, mode;

        for (mode = 0; mode < DOT11_MAX; mode++) {
            for (mcs = 0; mcs < MAX_MCS; mcs++) {
                if (cdp_rate_string[mode][mcs].valid) {
                    APSTATS_PRINT_GENERAL(fp, "%s: %d\n",
                                          cdp_rate_string[mode][mcs].mcs_type,
                                          nodestats->mcs_rx[mode][mcs]);
                }
            }
        }
    }
    APSTATS_PRINT_GENERAL(fp, "TX OFDMA Stats\n");
    {
        int ru_index;

        for (ru_index = 0; ru_index < RU_INDEX_MAX; ru_index++) {
            APSTATS_PRINT_GENERAL(fp, "%s: %d\n", cdp_ru_string[ru_index].ru_type,
                                  nodestats->ru_tx[ru_index]);
        }
    }
    APSTATS_PRINT_STAT64(fp, "Tx Success Unicast Data Bytes",   nodestats->tx_ucast_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Tx Success Multicast Data Packets", nodestats->tx_mcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Success Multicast Data Bytes",   nodestats->tx_mcast_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Tx Success Broadcast Data Packets", nodestats->tx_bcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Tx Success Broadcast Data Bytes",   nodestats->tx_bcast_data_bytes);
#endif
    APSTATS_PRINT_STAT64(fp, "Last Packet Error Rate (PER)",       nodestats->last_per);
    APSTATS_PRINT_STAT64(fp, "Rx Data Packets",       nodestats->rx_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Data Bytes",         nodestats->rx_data_bytes);
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    APSTATS_PRINT_STAT64(fp, "Rx Unicast   Data Packets", nodestats->rx_ucast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Unicast   Data Bytes",   nodestats->rx_ucast_data_bytes);
    APSTATS_PRINT_STAT64(fp, "Rx Multicast Data Packets", nodestats->rx_mcast_data_packets);
    APSTATS_PRINT_STAT64(fp, "Rx Multicast Data Bytes",   nodestats->rx_mcast_data_bytes);
#endif
    APSTATS_PRINT_STAT32(fp, "Average Tx Rate (kbps)",nodestats->tx_rate);
    APSTATS_PRINT_STAT32(fp, "Average Rx Rate (kbps)",nodestats->rx_rate);
    APSTATS_PRINT_STAT64(fp, "Last tx rate",          nodestats->last_tx_rate);
    APSTATS_PRINT_STAT64(fp, "Last rx rate",          nodestats->last_rx_rate);
    APSTATS_PRINT_STAT64(fp, "Last mgmt rx rate",     nodestats->last_rx_mgmt_rate);
    APSTATS_PRINT_STAT64(fp, "Rx MIC Errors",         nodestats->rx_micerr);
    APSTATS_PRINT_STAT64(fp, "Rx Decryption errors",  nodestats->rx_decrypterr);
    APSTATS_PRINT_STAT64(fp, "Rx errors",             nodestats->rx_err);
    APSTATS_PRINT_STAT64(fp, "Packets Queued",        nodestats->packets_queued);
    APSTATS_PRINT_STAT64(fp, "Tx failed",             nodestats->tx_failed);
    APSTATS_PRINT_STAT64(fp, "Host Discard",          nodestats->host_discard);
    APSTATS_PRINT_STAT64(fp, "Tx Mgmt Packets",       nodestats->tx_mgmt);
    APSTATS_PRINT_STAT64(fp, "Rx Mgmt Packets",       nodestats->rx_mgmt);
    APSTATS_PRINT_STAT64(fp, "Rx mpdu count",         nodestats->num_rx_mpdus);
    APSTATS_PRINT_STAT64(fp, "Rx ppdu count",         nodestats->num_rx_ppdus);
    APSTATS_PRINT_STAT64(fp, "Rx retry count",        nodestats->num_rx_retries);
    APSTATS_PRINT_STAT64(fp, "MSDU: Tx failed retry count",   (u_int64_t) nodestats->failed_retry_count);
    APSTATS_PRINT_STAT64(fp, "MSDU: Tx retry count",          (u_int64_t) nodestats->retry_count);
    APSTATS_PRINT_STAT64(fp, "MSDU: Tx multiple retry count", (u_int64_t) nodestats->multiple_retry_count);
    if (nodestats->ol_enable) {
        APSTATS_PRINT_STAT32(fp, "Avg ppdu Tx rate(kbps)",nodestats->ppdu_tx_rate);
        APSTATS_PRINT_STAT32(fp, "Avg ppdu Rx rate(kbps)",nodestats->ppdu_rx_rate);
    }
#if UMAC_SUPPORT_TXDATAPATH_NODESTATS
    APSTATS_PRINT_STAT64(fp, "Tx failures",           nodestats->tx_discard);
#else
    APSTATS_PRINT_STAT64(fp, "Tx Dropped(valid for offload driver)    ",  nodestats->tx_discard);
#endif /* UMAC_SUPPORT_TXDATAPATH_NODESTATS */
    APSTATS_PRINT_STAT8(fp, "Rx RSSI",                nodestats->rx_rssi);
    APSTATS_PRINT_STAT8(fp, "Rx MGMT RSSI",           nodestats->rx_mgmt_rssi);
    APSTATS_PRINT_GENERAL(fp, "Excessive retries per AC:\n");
    APSTATS_PRINT_STAT64(fp, " Best effort", nodestats->excretries[WME_AC_BE]);
    APSTATS_PRINT_STAT64(fp, " Background", nodestats->excretries[WME_AC_BK]);
    APSTATS_PRINT_STAT64(fp, " Video", nodestats->excretries[WME_AC_VI]);
    APSTATS_PRINT_STAT64(fp, " Voice", nodestats->excretries[WME_AC_VO]);

#if ATH_PERF_PWR_OFFLOAD
    APSTATS_PRINT_STAT32(fp, "Ack RSSI chain 1", nodestats->ack_rssi[0]);
    APSTATS_PRINT_STAT32(fp, "Ack RSSI chain 2", nodestats->ack_rssi[1]);
    APSTATS_PRINT_STAT32(fp, "Ack RSSI chain 3", nodestats->ack_rssi[2]);
    APSTATS_PRINT_STAT32(fp, "Ack RSSI chain 4", nodestats->ack_rssi[3]);
#endif

#if ATH_SUPPORT_EXT_STAT
    disaplay_band_width(fp, nodestats->chwidth);
    APSTATS_PRINT_GENERAL(fp, "stbc                            tx(%d) rx(%d)\n", tx_stbc, rx_stbc);
    APSTATS_PRINT_GENERAL(fp, "chainmask (NSS)                 tx(%d) rx(%d)\n", (si->isi_supp_nss & 0x0f), ((si->isi_supp_nss >> 4) & 0x0f));
    APSTATS_PRINT_STAT64(fp, "Tx packets for last one second ", nodestats->tx_data_rate);
    APSTATS_PRINT_STAT64(fp, "Tx bytes for last one second",    nodestats->tx_bytes_rate);
    APSTATS_PRINT_STAT64(fp, "Rx packets for last one second ", nodestats->rx_data_rate);
    APSTATS_PRINT_STAT64(fp, "Rx bytes for last one second",    nodestats->rx_bytes_rate);
#endif

#if WLAN_SUPPORT_TWT
    APSTATS_PRINT_STAT32(fp, "TWT event type ",   nodestats->twt_event_type);
    APSTATS_PRINT_STAT32(fp, "TWT flow ID ",      nodestats->twt_flow_id);
    APSTATS_PRINT_STAT32(fp, "Broadcast TWT  ",   nodestats->twt_bcast);
    APSTATS_PRINT_STAT32(fp, "TWT Trigger ",      nodestats->twt_trig);
    APSTATS_PRINT_STAT32(fp, "TWT Announcement ", nodestats->twt_announ);
    APSTATS_PRINT_STAT32(fp, "TWT Dialog ID",          nodestats->twt_dialog_id);
    APSTATS_PRINT_STAT32(fp, "TWT Wake duration (us)", nodestats->twt_wake_dura_us);
    APSTATS_PRINT_STAT32(fp, "TWT Wake interval (us)", nodestats->twt_wake_intvl_us);
    APSTATS_PRINT_STAT32(fp, "TWT SP offset (us)",     nodestats->twt_sp_offset_us);
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    tx_percent = (nodestats->tx_data_packets_success_twt*100)/nodestats->tx_data_packets_success;
    if (tx_percent == 1)
       tx_percent = 100;
    APSTATS_PRINT_STAT32(fp,"Percentage of TX pkt in TWT session",tx_percent);
#endif
    rx_percent = (nodestats->rx_data_packets_twt*100)/nodestats->rx_data_packets;
    if (rx_percent == 1)
       rx_percent = 100;
    APSTATS_PRINT_STAT32(fp,"Percentage of RX pkt in TWT session",rx_percent);
#endif

    APSTATS_PRINT_GENERAL(fp, "\n");

    if (display_mesh_stats) {

        APSTATS_PRINT_GENERAL(fp, "\n ------ mesh stats for %s ------\n", macaddr_to_str(&nodestats->macaddr));

        APSTATS_PRINT_STAT8(fp, "associd: "  , si->isi_associd);
        APSTATS_PRINT_GENERAL(fp, "HW mode: %s \n",(si->isi_stamode < IEEE80211_MODE_MAX) ? ieee80211_phymode_str[si->isi_stamode]:"IEEE80211_MODE_11B");

        APSTATS_PRINT_GENERAL(fp, "chainmask (NSS) - tx: %d rx: %d \n", (si->isi_nss & 0x0f), ((si->isi_nss >> 4) & 0x0f));
        APSTATS_PRINT_GENERAL(fp, "256 QAM support: %s \n", si->isi_is_256qam ? "Yes" : "No");

        APSTATS_PRINT_STAT64(fp, "Last rx rate (data): ",  nodestats->last_rx_rate);
        APSTATS_PRINT_STAT8(fp, "Rx RSSI (data): ",        nodestats->rx_rssi);
        APSTATS_PRINT_STAT64(fp, "Last rx rate (mgmt): ",  nodestats->last_rx_mgmt_rate);
        APSTATS_PRINT_STAT8(fp, "Rx RSSI (mgmt): ",        nodestats->rx_mgmt_rssi);
        APSTATS_PRINT_STAT64(fp, "Rx Data Bytes: ",        nodestats->rx_data_bytes);
        APSTATS_PRINT_STAT64(fp, "Rx MIC Errors: ",        nodestats->rx_micerr);
        APSTATS_PRINT_STAT64(fp, "Rx Decryption errors: ", nodestats->rx_decrypterr);
        APSTATS_PRINT_STAT64(fp, "Rx errors: ",            nodestats->rx_err);


        APSTATS_PRINT_STAT64(fp, "Last tx rate",          nodestats->last_tx_rate);
        APSTATS_PRINT_STAT64(fp, "Tx Data Packets",       nodestats->tx_data_packets);
        APSTATS_PRINT_STAT64(fp, "Tx Data Bytes",         nodestats->tx_data_bytes);
        APSTATS_PRINT_STAT64(fp, "Tx failures",           nodestats->tx_discard);

        APSTATS_PRINT_GENERAL(fp, "--------------------------------------- \n");

    }
    return 0;
}

#ifndef APSTATS_API
static int aplevel_handler(FILE *fp, int sockfd,
        aplevel_stats_t *apstats,
        bool recursion)
{
    int ret = -1;

    ret =  aplevel_gather_stats(sockfd, apstats, recursion);

    if (ret < 0) {
        return ret;
    }

    ret =  aplevel_display_stats(fp, apstats, recursion);

    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int radiolevel_handler(FILE *fp, int sockfd,
        radiolevel_stats_t *radiostats,
        bool recursion)
{
    int ret = -1;

    ret =  radiolevel_gather_stats(sockfd, radiostats, recursion);

    if (ret < 0) {
        return ret;
    }

    ret =  radiolevel_display_stats(fp, radiostats, recursion);

    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int vaplevel_handler(FILE *fp, int sockfd,
        vaplevel_stats_t *vapstats,
        bool recursion)
{
    int ret = -1;

    ret =  vaplevel_gather_stats(sockfd, vapstats, recursion);

    if (ret < 0) {
        return ret;
    }
    ret =  vaplevel_display_stats(fp, vapstats, recursion);

    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int nodelevel_handler(FILE *fp, int sockfd,
        nodelevel_stats_t *nodestats)
{
    int ret = -1;

    ret =  nodelevel_gather_stats(sockfd, nodestats);

    if (ret < 0) {
        return ret;
    }

    ret =  nodelevel_display_stats(fp, nodestats);

    if (ret < 0) {
        return ret;
    }

    return 0;

}

static int apstats_main(apstats_config_t *config)
{
    int ret = -1;
    int sockfd;
    aplevel_stats_t apstats;
    radiolevel_stats_t *pradiostats;
    vaplevel_stats_t *pvapstats;
    nodelevel_stats_t *pnodestats;

    assert(config != NULL);

    sockfd = sock_ctx.sock_fd;

    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    /*
     * Irrespective of the level requested by the user, we
     * initiate the whole hierarchy of stats. This is because
     * there could be interdependencies among levels while
     *  calculating stats
     */
    if ((ret = stats_hierachy_init(&apstats, sockfd)) < 0) {
        /* TODO: See if we can handle this better. */
        close(sockfd);
        stats_hierachy_deinit(&apstats);
        close(sockfd);
        return ret;
    }

    switch(config->level)
    {
        case APSTATS_LEVEL_AP:
            ret = aplevel_handler(stdout, sockfd,
                    &apstats,
                    config->is_recursion);
            break;

        case APSTATS_LEVEL_RADIO:
            pradiostats = stats_hierarchy_findradio(&apstats,
                    config->ifname);
            if (!pradiostats) {
                APSTATS_ERROR("Could not find specified radio.\n");
                ret = -ENOENT;
                break;
            }

            ret= radiolevel_handler(stdout, sockfd,
                    pradiostats,
                    config->is_recursion);
            break;

        case APSTATS_LEVEL_VAP:
            pvapstats = stats_hierarchy_findvap(&apstats,
                    config->ifname);

            if (!pvapstats) {
                APSTATS_ERROR("Could not find specified VAP.\n");
                ret = -ENOENT;
                break;
            }

            ret = vaplevel_handler(stdout, sockfd,
                    pvapstats,
                    config->is_recursion);
            break;

        case APSTATS_LEVEL_NODE:
            pnodestats = stats_hierarchy_findnode(&apstats,
                    &config->stamacaddr);

            if (!pnodestats) {
                APSTATS_ERROR("Could not find specified STA.\n");
                ret = -ENOENT;
                break;
            }

            ret = nodelevel_handler(stdout, sockfd,
                    pnodestats);
            break;

        default:
            APSTATS_ERROR("Unknown statistics level.\n");
            ret = -ENOENT;
            break;
    }

    stats_hierachy_deinit(&apstats);
    close(sockfd);
    return ret;
}


int apstats_config_init(apstats_config_t *config)
{
    assert(config != NULL);

    /*
     * Do NOT change the default to APSTATS_LEVEL_NO_VAL - doesn't
     * make sense, and will break a lot of stuff
     */
    config->level           = APSTATS_LEVEL_AP;

    memset(config->ifname, 0, sizeof(config->ifname));
    memset(&config->stamacaddr, 0, sizeof(config->stamacaddr));

    return 0;
}


static int apstats_config_populate(apstats_config_t *config,
        const apstats_level_t level,
        const bool recursion,
        const char *ifname,
        const char *stamacaddr)
{
    struct ether_addr *ret_ether_addr = NULL;

    assert(config != NULL);
    assert(ifname != NULL);
    assert(stamacaddr != NULL);
    if (level != APSTATS_LEVEL_NO_VAL) {
        config->level = level;
    } /* else use defaults pre-configured by apstats_config_init() */

    switch(config->level)
    {
        case APSTATS_LEVEL_AP:
            if (ifname[0]) {
                APSTATS_WARNING("Ignoring Interface Name input for AP "
                        "Level.\n");
            }

            if (stamacaddr[0]) {
                APSTATS_WARNING("Ignoring STA MAC address input for AP "
                        "Level.\n");
            }

            break;

        case APSTATS_LEVEL_RADIO:
            if (!ifname[0]) {
                APSTATS_ERROR("Radio Interface name not configured.\n");
                return -EINVAL;
            }

            if (!is_radio_ifname_valid(ifname)) {
                APSTATS_ERROR("Radio Interface name invalid.\n");
                return -EINVAL;
            }

            memset(config->ifname, '\0', IFNAMSIZ);
            if (strlcpy(config->ifname, ifname, IFNAMSIZ) >= IFNAMSIZ) {
                APSTATS_ERROR("%s(): %d Error copying radio intf name\n",
                        __func__, __LINE__);
                return -1;
            }

            if (stamacaddr[0]) {
                APSTATS_WARNING("Ignoring STA MAC address input for Radio "
                        "Level.\n");
            }

            break;

        case APSTATS_LEVEL_VAP:
            if (!ifname[0]) {
                APSTATS_ERROR("VAP Interface name not configured.\n");
                return -EINVAL;
            }

            if (!is_vap_ifname_valid(ifname)) {
                APSTATS_ERROR("VAP Interface name invalid.\n");
                return -EINVAL;
            }

            memset(config->ifname, '\0', IFNAMSIZ);
            if (strlcpy(config->ifname, ifname, IFNAMSIZ) >= IFNAMSIZ) {
                APSTATS_ERROR("%s(): %d Error copying radio intf name\n",
                        __func__, __LINE__);
                return -1;
            }

            if (stamacaddr[0]) {
                APSTATS_WARNING("Ignoring STA MAC address input for VAP "
                        "Level.\n");
            }

            break;

        case APSTATS_LEVEL_NODE:
            if (!stamacaddr[0]) {
                APSTATS_ERROR("STA MAC address not configured.\n");
                return -EINVAL;
            }

            if ((ret_ether_addr = ether_aton_r(stamacaddr,
                            &config->stamacaddr)) == NULL) {
                APSTATS_ERROR("STA MAC address not valid.\n");
                return -EINVAL;
            }

            if (ifname[0]) {
                APSTATS_WARNING("Ignoring Interface name input for STA "
                        "Level.\n");
            }

            if (recursion) {
                APSTATS_WARNING("Ignoring recursive display configuration "
                        "for STA level.\n");
            }

            break;

        default:
            APSTATS_ERROR("Unknown statistics level.\n");
            return -EINVAL;
    }
    return 0;
}
#endif

int apstats_is_cfg80211_mode_enabled() {
    FILE *fp;
    char filename[32];
    int i;
    int ret = 0;

    for (i=0; i < 3 ; i++)
    {
        snprintf(filename, sizeof(filename), "/sys/class/net/wifi%d/phy80211/",i);
        fp = fopen(filename, "r");
        if(fp != NULL) {
            ret = 1;
        }
    }

    return ret;
}

#ifndef APSTATS_API
int main(int argc, char *argv[])
{
    int                 ret;
    apstats_config_t    config;
    int                 opt = 0;
    int                 longIndex;

    int                 is_level_set        = 0;
    int                 is_ifname_set       = 0;
    int                 is_stamacaddr_set   = 0;
    int                 is_option_selected  = 0;

    /* Temp variables to hold user input. */
    apstats_level_t     level_temp          = APSTATS_LEVEL_AP;
    bool                recursion_temp      = 0;
    char                ifname_temp[IFNAMSIZ];
    char                stamacaddr_temp[ETH_ALEN * 3];

    memset(ifname_temp, 0, sizeof(ifname_temp));
    memset(stamacaddr_temp, 0, sizeof(stamacaddr_temp));

    memset(&config, 0, sizeof(config));
    apstats_config_init(&config);

    /*
     * Based on driver config mode (cfg80211/wext), application also runs
     * in same mode (wext/cfg80211)
     */
    cfg_flag = apstats_is_cfg80211_mode_enabled();
    sock_ctx.cfg80211 = get_config_mode_type();

    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);

    /*
     * TODO: Auto detect required level from interface name/MAC
     * address input, so as to make the UI a little more
     * friendly.
     */

    while (opt != -1) {
        switch(opt) {
            case 'a':
                if (is_level_set) {
                    APSTATS_ERROR("Multiple statistics level arguments "
                            "detected.\n");
                    display_help();
                    return -1;
                }

                level_temp = APSTATS_LEVEL_AP;
                is_level_set  = 1;
                is_option_selected = 1;
                break;

            case 'r':
                if (is_level_set) {
                    APSTATS_ERROR("Multiple statistics level arguments"
                            "detected.\n");
                    display_help();
                    return -1;
                }

                level_temp = APSTATS_LEVEL_RADIO;
                is_level_set  = 1;
                is_option_selected = 1;
                break;

            case 'v':
                if (is_level_set) {
                    APSTATS_ERROR("Multiple statistics level arguments "
                            "detected.\n");
                    display_help();
                    return -1;
                }

                level_temp = APSTATS_LEVEL_VAP;
                is_level_set  = 1;
                is_option_selected = 1;
                break;

            case 's':
                if (is_level_set) {
                    APSTATS_ERROR("Multiple statistics level arguments "
                            "detected.\n");
                    display_help();
                    return -1;
                }

                level_temp = APSTATS_LEVEL_NODE;
                is_level_set  = 1;
                is_option_selected = 1;
                break;

            case 'i':
                if (is_ifname_set) {
                    APSTATS_ERROR("Multiple interface name arguments "
                            "detected.\n");
                    display_help();
                    return -1;
                }

                memset(ifname_temp, '\0', sizeof(ifname_temp));
                if (strlcpy(ifname_temp, optarg, sizeof(ifname_temp))
                        >= sizeof(ifname_temp)) {
                    APSTATS_ERROR("%s(): %d Error creating ifname \n",
                            __func__, __LINE__);
                    return -1;
                }
                is_ifname_set  = 1;
                is_option_selected = 1;
                break;

            case 'm':
                if (is_stamacaddr_set) {
                    APSTATS_ERROR("Multiple STA MAC address arguments "
                            "detected.\n");
                    display_help();
                    return -1;
                }

                memset(stamacaddr_temp, '\0', sizeof(stamacaddr_temp));
                if (strlcpy(stamacaddr_temp, optarg, sizeof(stamacaddr_temp))
                        >= sizeof(stamacaddr_temp)) {
                    APSTATS_ERROR("%s(): %d Error copying macaddr \n",
                            __func__, __LINE__);
                    return -1;
                }
                is_stamacaddr_set  = 1;
                is_option_selected = 1;
                break;

            case 'R':
                recursion_temp = 1;
                break;

            case 'M':
                display_mesh_stats = 1;
                break;
            case 'n':
                if (!cfg_flag){
                    APSTATS_ERROR("Invalid tag '-n' for current mode\n");
                    return -EINVAL;
                }
                cfg_flag = 1;
                break;
            case 'h':
            case '?':
                display_help();
                is_option_selected = 1;
                return 0;

            default:
                APSTATS_ERROR("Unrecognized option.\n");
                display_help();
                is_option_selected = 1;
                return -1;
        }

        opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    if (!is_option_selected) {
        APSTATS_MESG("No application recognized options. "
                "Using defaults: AP level, non-recursive.\n"
                "Use -h for help\n\n");
    }
    init_socket_context(&sock_ctx, APSTATS_NL80211_CMD_SOCK_ID, APSTATS_NL80211_EVENT_SOCK_ID);

    /* In apstats there were few genric IOCTLS, so we need to have sockfd */
    if (sock_ctx.cfg80211) {
        sock_ctx.sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ctx.sock_fd < 0) {
            errx(1, "socket creation failed");
            return -EIO;
        }
    }

    ret = apstats_config_populate(&config,
            level_temp,
            recursion_temp,
            ifname_temp,
            stamacaddr_temp);
    if (ret < 0) {
        display_help();
        return -1;
    }

    config.is_recursion = recursion_temp;

    apstats_main(&config);
    destroy_socket_context(&sock_ctx);
    /* close socket fd */
    if (sock_ctx.cfg80211) {
        close(sock_ctx.sock_fd);
    }

    return 0;
}

#else
static apstats_obj_t *apstats_main_api(aplevel_stats_t *apstats,
                                       apstats_config_t *config,
                                       int sockfd)
{
    int ret = -1;
    radiolevel_stats_t *pradiostats;
    vaplevel_stats_t *pvapstats;
    nodelevel_stats_t *pnodestats;
    apstats_obj_t *obj = NULL;

    assert(config != NULL);


    switch(config->level)
    {
        case APSTATS_LEVEL_AP:
            ret =  aplevel_gather_stats(sockfd, apstats, config->is_recursion);
            if (!ret)
                obj = &apstats->obj;
            break;

        case APSTATS_LEVEL_RADIO:
            pradiostats =
            stats_hierarchy_findradio(apstats,
                                      config->ifname);
            if (!pradiostats) {
                APSTATS_ERROR("Could not find specified radio.\n");
                return obj;
            }

            ret =  radiolevel_gather_stats(sockfd, pradiostats, config->is_recursion);
            if (ret == 0)
                obj = &pradiostats->obj;
            break;

        case APSTATS_LEVEL_VAP:
            pvapstats =
            stats_hierarchy_findvap(apstats,
                                    config->ifname);

            if (!pvapstats) {
                APSTATS_ERROR("Could not find specified VAP.\n");
                return obj;
            }

            ret =  vaplevel_gather_stats(sockfd, pvapstats, config->is_recursion);
            if (ret == 0)
                obj = &pvapstats->obj;

            break;

        case APSTATS_LEVEL_NODE:
            pnodestats =
            stats_hierarchy_findnode(apstats,
                                     &config->stamacaddr);

            if (!pnodestats) {
                APSTATS_ERROR("Could not find specified STA.\n");
                return obj;
            }

            ret =  nodelevel_gather_stats(sockfd, pnodestats);
            if (ret == 0)
                obj = &pnodestats->obj;
            break;

        default:
            APSTATS_ERROR("Unknown statistics level.\n");
            break;
    }
    return obj;
}


/*
 * apstats_get_service: The service callback for the collector insert
 *                      This internal function is used as the collector
 *                      callback by apstats_get API
 *                      callback with the requested apstats object will be
 *                      called if succesfull in getting the information.
 *                      Otherwise callback with a NULL pointer will be called
 *
 * @config: apstats config (which includes the callback)
 * return void
 */
static void apstats_get_service(apstats_config_t *config)
{
    aplevel_stats_t *apstats;
    apstats_obj_t *obj = NULL;

    if (!config) {
        printf("ERROR!! %s:%d  NULL config\n", __func__, __LINE__);
        return;
    }

    /* Setting recursion flag to 1 */
    config->is_recursion = true;

    cfg_flag = apstats_is_cfg80211_mode_enabled();
    head_vapstats = NULL;
    memset(&sock_ctx, 0, sizeof(sock_ctx));

    apstats = calloc(sizeof(*apstats), 1);
    if (!apstats) {
        printf("ERROR!! %s:%d ALLOC FAILURE\n", __func__, __LINE__);
        goto apstats_get_service_exit_callback;
    }

    sock_ctx.cfg80211 = get_config_mode_type();
    init_socket_context(&sock_ctx, APSTATS_NL80211_CMD_SOCK_ID,
                        APSTATS_NL80211_EVENT_SOCK_ID);
    /* In apstats there were few genric IOCTLS, so we need to have sock_ctx.sock_fd */
    if (!sock_ctx.cfg80211) {
        printf("ERROR!! API mode only supported for cfg80211 mode");
        goto apstats_get_service_exit;
    }

    sock_ctx.sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ctx.sock_fd < 0) {
        printf("ERROR!! socket creation failed");
        goto apstats_get_service_exit;
    }

    /*
     * Irrespective of the level requested by the user, we
     * initiate the whole hierarchy of stats. This is because
     * there could be interdependencies among levels while
     *  calculating stats
     */
    if (stats_hierachy_init(apstats, sock_ctx.sock_fd) < 0) {
        stats_hierachy_deinit(apstats);
        goto apstats_get_service_exit;
    }

    obj = apstats_main_api(apstats, config, sock_ctx.sock_fd);
    if (obj == NULL) {

        stats_hierachy_deinit(apstats);
        goto apstats_get_service_exit;
    } else {

        /*
         * Regardless of what level is specified, information on nodes
         * at all levels are collected.
         * We need to mark the subtree root, so that nodes outside of the level
         * is not returned
         */
        obj->subtree_root = 1;
        goto apstats_get_service_exit_destroy_sock;
    }

apstats_get_service_exit:
    free(apstats);
apstats_get_service_exit_destroy_sock:
    destroy_socket_context(&sock_ctx);
    /* close socket fd */
    if (sock_ctx.cfg80211 && (sock_ctx.sock_fd > 0)) {
        close(sock_ctx.sock_fd);
        sock_ctx.sock_fd = 0;
    }
apstats_get_service_exit_callback:
    if (config->callback_token)
        config->callback_token(obj, config->token);
    else if (config->callback)
        config->callback(obj);
    free(config);
}

/*
 * apstats_get_next: Get the next object in the object tree
 *
 * Get the next object in the tree. The order of traversal is as following
 * in a recursive way
 *     1. Self node
 *     2. all children nodes
 *     3. next node
 *
 * @obj: Current object
 * return pointer to the next object, NULL if no more objects
 */
apstats_obj_t *apstats_get_next(apstats_obj_t *obj)
{
    if (obj == NULL) {
        printf("ERROR!! %s:%d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    if (obj->firstchild) {
        return obj->firstchild;
    }
    do {
        /*
         * If we are at the subroot, that means no more nodes
         * since the subroot will be the object that is called
         * as part of apstats_get callback and we shouldn't return the subroot
         * again. Also we should not go beyond the subroot
         */
        if (obj->subtree_root)
            return NULL;
        if (obj->next) {
            obj = obj->next;
            break;
        }
        else if (obj->parent)
            /*
             * next node is not there, so go back to the parent
             * and check if the parent has any next. This will fulfil the
             * contract of returning next nodes, after all children nodes
             * are traversed.
             */
            obj = obj->parent;
    } while(obj);
    return obj;
}

/*
 * apstats_print: Print the apstats
 *
 * @fp: File where output will be printed
 * @obj: object that needs to be printed
 * @is_recursion: Whether object nodes below the object needs to be printed
 *
 * return void
 */
void apstats_print(FILE *fp, apstats_obj_t *obj,
                   bool is_recursion)
{
    if (obj == NULL) {
        printf("ERROR!! %s:%d OBJ is NULL\n", __func__, __LINE__);
        return;
    }

    switch (obj->level)
    {
        case APSTATS_LEVEL_AP:
            aplevel_display_stats(fp, (aplevel_stats_t *) obj, is_recursion);
            break;
        case APSTATS_LEVEL_RADIO:
            radiolevel_display_stats(fp, (radiolevel_stats_t *) obj, is_recursion);
            break;
        case APSTATS_LEVEL_VAP:
            vaplevel_display_stats(fp, (vaplevel_stats_t *) obj, is_recursion);
            break;
        case APSTATS_LEVEL_NODE:
            nodelevel_display_stats(fp, (nodelevel_stats_t *) obj);
            break;
        default:
            break;
    }
}

/*
 * apstats_destroy: Destroy the apstats objects, once they are used
 *
 * @obj: obj pointer that was given as part of apstats_get callback
 * return void
 */
void apstats_destroy(apstats_obj_t *obj)
{
    aplevel_stats_t *apstats_root;

    if (obj == NULL) {
        printf("ERROR!! %s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    while (obj->parent != NULL)
        obj = obj->parent;

    apstats_root = (aplevel_stats_t *)obj;
    stats_hierachy_deinit(apstats_root);
    free(obj);
}

/*
 * apstats_get: Collect the whole tree of statistics below what ever the level
 *              and interface specified
 *
 * @col: collector context
 * @config: apstats config (config includes the callback to be called)
 * return 0 on success otherwise negative value on failure
 */
int apstats_get(void *col, apstats_config_t *config)
{
    apstats_config_t *config_copy;
    if (!config) {
        printf("ERROR!! %s:%d config NULL\n", __func__, __LINE__);
        return -EINVAL;
    }

    if ((config->callback == NULL) && (config->callback_token == NULL)) {
        printf("ERROR!! %s:%d callback NULL\n", __func__, __LINE__);
        return -EINVAL;
    }

    config_copy = calloc(sizeof(*config_copy), 1);
    if (!config_copy) {
        printf("ERROR!! %s:%d FAILED TO ALLOCATE\n", __func__, __LINE__);
        return -ENOMEM;
    }

    *config_copy = *config;
    return collector_insert(col, config_copy,
                            (void (*)(void *))apstats_get_service);
}

#endif
