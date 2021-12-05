/*
 * Copyright (c) 2015-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * osif_nss_wifiol_cmn.c
 *
 * This file used for for interface   NSS WiFi Offload Radio
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         4/jan/2018              Created
 */

#include <ol_if_athvar.h>

#include <nss_api_if.h>
#include <nss_cmn.h>
#include <hif.h>
#include "osif_nss_wifiol_vdev_if.h"
#include "osif_nss_wifiol_if.h"
#include "target_type.h"
#include "qca_ol_if.h"
#include "init_deinit_lmac.h"
#include "cfg_ucfg_api.h"
#include <linux/if_bridge.h>
#if DBDC_REPEATER_SUPPORT
#include "qca_multi_link_tbl.h"
#endif

#define MAX_NUM_ETH_FDB_ENTRIES 128
#define NSS_WIFI_MAC_DB_ENTRIES_MAX 2048

int glbl_allocated_radioidx=0;
qdf_export_symbol(glbl_allocated_radioidx);
int global_device_id = 0;
int nssdevice_id = 0;

enum nss_wifi_mac_db_entries_state {
    NSS_WIFI_MACDB_ENTRIES_NOT_SENT,
    NSS_WIFI_MACDB_ENTRIES_SEND_IN_PROGRESS,
    NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE,
};

/*
 * nss_wifi_mac_db_entry
 *  Wi-Fi MAC database entries pool.
 */
struct nss_wifi_mac_db_entry {
    uint32_t entry_valid;
    struct nss_wifi_mac_db_entry_info_msg info;
};

/*
 * nss_wifi_mac_db
 *  wifi mac database object structure.
 */
struct nss_wifi_mac_db {
    qdf_spinlock_t wifi_macdb_lock;
    bool br_ntfy_register;
    bool br_update_ntfy_register;
    bool nwmdb_if_register;
    bool nwmdb_init;
    enum nss_wifi_mac_db_entries_state ent_send_state;
    qdf_atomic_t num_entry_msgs;
    struct nss_wifi_mac_db_entry *entry_pool;
}nss_wifi_mac_db_obj;

struct nss_wifi_mac_db_dev {
    struct net_device *br_dev;
}nss_wifi_mac_db_device;

static struct nss_wifi_soc_ops *nss_wifi_soc_register[OL_WIFI_TYPE_MAX];

#if DBDC_REPEATER_SUPPORT
/*
 * osif_nss_recv_wifi_mac_db_entry_create_info()
 *  Receive wifi mac database entry create information from NSS FW.
 */
static bool osif_nss_recv_wifi_mac_db_entry_create_info(struct nss_wifi_mac_db_entry_create_msg *msg)
{
    struct net_device *netdev = NULL;
    struct nss_ctx_instance *nss_contex = NULL;

    nss_contex = nss_wifi_mac_db_get_context();
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return false;
    }

    netdev = nss_cmn_get_interface_dev(nss_contex, msg->nss_if);
    if (!netdev) {
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-wifi-mac-db-nfy]: Device not found for nss_if:%d", msg->nss_if);
        return false;
    }

    if (!netdev->ieee80211_ptr) {
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-wifi-mac-db-nfy]: Not vap interface nss_if:%d", msg->nss_if);
        return false;
    }

    qca_multi_link_tbl_add_or_refresh_entry(netdev, &msg->mac_addr[0], QCA_MULTI_LINK_ENTRY_USER_ADDED);
    return true;
}

/*
 * osif_nss_recv_wifi_mac_db_entry_activity_info()
 *  Receive wifi mac database entry activity information from NSS FW.
 */
static bool osif_nss_recv_wifi_mac_db_entry_activity_info(struct nss_wifi_mac_db_entry_activity_info_msg *msg)
{
    uint32_t i;
    struct net_device *netdev = NULL;
    struct nss_ctx_instance *nss_contex = NULL;

    nss_contex = nss_wifi_mac_db_get_context();
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return false;
    }

    for (i = 0; i < msg->nentries; i++) {

        netdev = nss_cmn_get_interface_dev(nss_contex, msg->info[i].nss_if);
        if (!netdev) {
            QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                    "[nss-wifi-mac-db-nfy]: Device not found for nss_if:%d", msg->info[i].nss_if);
            continue;
        }

        if (!netdev->ieee80211_ptr) {
            continue;
        }

        qca_multi_link_tbl_add_or_refresh_entry(netdev, &msg->info[i].mac_addr[0], QCA_MULTI_LINK_ENTRY_USER_ADDED);
    }

    return true;
}

#else
static bool osif_nss_recv_wifi_mac_db_entry_create_info(struct nss_wifi_mac_db_entry_create_msg *msg)
{
    return true;
}

static bool osif_nss_recv_wifi_mac_db_entry_activity_info(struct nss_wifi_mac_db_entry_activity_info_msg *msg)
{
    return true;
}

#endif

/*
 * osif_nss_wifi_mac_db_event_receive
 *       wifi mac db event callback
 */
void osif_nss_wifi_mac_db_event_receive(void *app_data, struct nss_wifi_mac_db_msg *ntm)
{
    uint32_t msg_type = ntm->cm.type;
    enum nss_cmn_response response = ntm->cm.response;
    uint32_t error =  ntm->cm.error;
    struct nss_wifi_mac_db_dev *dev = (struct nss_wifi_mac_db_dev *)app_data;
    struct nss_wifi_mac_db_entry_info_msg *msg = &ntm->msg.nmfdbeimsg;
    struct nss_wifi_mac_db_entry_group_info_msg *gmsg = &ntm->msg.nmfdbegimsg;
    uint32_t i;
    uint32_t grp_entry_cnt = 0;

    if (!dev) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-wifi-mac-db-nfy]: net_dev %pK is NULL", dev);
        return;
    }

    /*
     * Handle the nss wifi mac db message
     */
    switch (msg_type) {
        case NSS_WIFI_MAC_DB_ADD_ENTRY_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                        "[nss-wifi-mac-db-nfy]: Add message failed with error = %u mac:%pM nss_if:%d", error, msg->mac_addr, msg->nss_if);
            }
            break;
        case NSS_WIFI_MAC_DB_DEL_ENTRY_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                        "[nss-wifi-mac-db-nfy]: Delete message failed with error = %u mac:%pM nss_if:%d", error, msg->mac_addr, msg->nss_if);
            }
            break;
        case NSS_WIFI_MAC_DB_UPDATE_ENTRY_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                        "[nss-wifi-mac-db-nfy]: Update message failed with error = %u mac:%pM nss_if:%d", error, msg->mac_addr, msg->nss_if);
            }
            break;
        case NSS_WIFI_MAC_DB_INIT_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                        "[nss-wifi-mac-db-nfy]: Init message failed with error = %u", error);
            }
            break;
        case NSS_WIFI_MAC_DB_DEINIT_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                        "[nss-wifi-mac-db-nfy]: DeInit message failed with error = %u", error);
            }
            break;
        case NSS_WIFI_MAC_DB_GROUP_ENTRIES_ADD_MSG:
            if (response == NSS_CMN_RESPONSE_EMSG) {
                for (i = 0; i < NSS_WIFI_MAC_DB_GROUP_ENTRIES_MAX; i++) {
                    if (!gmsg->entry[i].flag) {
                        continue;
                    }
                    QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                            "[nss-wifi-mac-db-nfy]: Group entries add message failed with error = %u mac:%pM nss_if:%d", gmsg->entry[i].flag, gmsg->entry[i].mac_addr, gmsg->entry[i].nss_if);
		   grp_entry_cnt++;
                }
                if (grp_entry_cnt == gmsg->num_entries) {
                    QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                            "[nss-wifi-mac-db-nfy]: Group entries add message failed for all entries :%d", gmsg->num_entries);
                }
            }

            /*
             * Decrement message counter even for ACK/NACK, as secondary mcast
             * timer depends on macdb readiness.
             */
            if (qdf_atomic_read(&nss_wifi_mac_db_obj.num_entry_msgs) > 0) {
                if (qdf_atomic_dec_and_test(&nss_wifi_mac_db_obj.num_entry_msgs)) {
                    nss_wifi_mac_db_obj.ent_send_state = NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE;
                }
            }
        case NSS_WIFI_MAC_DB_ENTRY_ACTIVITY_MSG:
            osif_nss_recv_wifi_mac_db_entry_activity_info(&ntm->msg.nmfdbeact_imsg);
            break;
        case NSS_WIFI_MAC_DB_CREATE_ENTRY_MSG:
            osif_nss_recv_wifi_mac_db_entry_create_info(&ntm->msg.nmfdbecmsg);
            break;
        default:
            QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                    "[nss-wifi-mac-db-nfy]: NSS wifi mac db configuration message failed with error = %u", error);
    }
    return;
}

/*
 * osif_nss_register_wifi_mac_db_interface()
 *  Register wifi mac database message sending interface with NSS.
 */
bool osif_nss_register_wifi_mac_db_interface(uint32_t if_num, struct net_device *dev)
{
    struct nss_ctx_instance *nss_contex;

    /*
     * add callback
     */
    nss_contex = nss_register_wifi_mac_db_if(if_num, NULL, NULL,
            (nss_wifi_mac_db_msg_callback_t)osif_nss_wifi_mac_db_event_receive, dev, 0);
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-wifi-mac-db-nfy]: registration failed");
        return false;
    }

    if (nss_cmn_get_state(nss_contex) != NSS_STATE_INITIALIZED) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-wifi-mac-db-nfy]: NSS core is not initialised");
        goto unregister;
    }

    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    nss_wifi_mac_db_obj.nwmdb_if_register = true;
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    return true;

unregister:
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    nss_wifi_mac_db_obj.nwmdb_if_register = false;
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    nss_unregister_wifi_mac_db_if(if_num);
    return false;
}

/*
 * osif_nss_unregister_wifi_mac_db_interface()
 *  Unregister wifi mac database message sending interface with NSS.
 */
void osif_nss_unregister_wifi_mac_db_interface(uint32_t if_num)
{
    nss_unregister_wifi_mac_db_if(if_num);
}

/*
 * osif_nss_wifi_mac_db_init()
 *  Initialize WiFi MAC database in NSS FW.
 */
bool osif_nss_wifi_mac_db_init(struct net_device *netdev)
{
    struct nss_wifi_mac_db_msg *nmfdbmsg = NULL;
    nss_tx_status_t status;
    struct nss_ctx_instance *nss_contex;
    nss_wifi_mac_db_msg_callback_t msg_cb = (nss_wifi_mac_db_msg_callback_t)osif_nss_wifi_mac_db_event_receive;

    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (!nss_wifi_mac_db_obj.nwmdb_if_register) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss_wifi_mac_db]: NSS Wi-Fi MAC database is not registered with NSS DRV ");
        return false;
    }

    if (nss_wifi_mac_db_obj.nwmdb_init) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return true;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    nss_contex = nss_wifi_mac_db_get_context();
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return false;
    }

    /*
     * Allocate the memory to prepare bridge notify message
     */
    nmfdbmsg = qdf_mem_malloc_atomic(sizeof(struct nss_wifi_mac_db_msg));
    if (nmfdbmsg == NULL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: message pool memory allocation failure");
        return false;
    }

    memset(nmfdbmsg, 0, sizeof(struct nss_wifi_mac_db_msg));

    /*
     *  Update messgae send through MAC FWD DB interface
     */
    nss_cmn_msg_init(&nmfdbmsg->cm, NSS_WIFI_MAC_DB_INTERFACE, NSS_WIFI_MAC_DB_INIT_MSG,
            sizeof(struct nss_wifi_mac_db_entry_info_msg), msg_cb, NULL);

    status = nss_wifi_mac_db_tx_msg(nss_contex, nmfdbmsg);
    qdf_mem_free(nmfdbmsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-br-fdb-nfy]: MAC Fwd table INIT message failed %d ", status);
        return false;
    }

    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    nss_wifi_mac_db_obj.nwmdb_init = true;
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss-br-fdb-nfy]: sent MAC forwarding database message to NSS");
    return true;
}

qdf_export_symbol(osif_nss_wifi_mac_db_init);

/*
 * osif_nss_wifi_mac_db_check_entry_pool()
 *  Check if Wi-Fi MAC DB entry pool is allocated.
 */
static bool osif_nss_wifi_mac_db_check_entry_pool(void)
{
    return nss_wifi_mac_db_obj.entry_pool ? true : false;
}

/*
 * osif_nss_wifi_mac_db_deinit()
 *  De-Initialize WiFi MAC database in NSS FW.
 */
static int osif_nss_wifi_mac_db_deinit(void)
{
    struct nss_wifi_mac_db_msg *nmfdbmsg = NULL;
    nss_tx_status_t status;
    struct nss_ctx_instance *nss_contex;
    nss_wifi_mac_db_msg_callback_t msg_cb = (nss_wifi_mac_db_msg_callback_t)osif_nss_wifi_mac_db_event_receive;

    nss_contex = nss_wifi_mac_db_get_context();
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return 1;
    }

    /*
     * Allocate the memory to prepare bridge notify message
     */
    nmfdbmsg = qdf_mem_malloc_atomic(sizeof(struct nss_wifi_mac_db_msg));
    if (nmfdbmsg == NULL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: message pool memory allocation failure");
        return 1;
    }

    memset(nmfdbmsg, 0, sizeof(struct nss_wifi_mac_db_msg));

    /*
     *  Update messgae send through MAC FWD DB interface
     */
    nss_cmn_msg_init(&nmfdbmsg->cm, NSS_WIFI_MAC_DB_INTERFACE, NSS_WIFI_MAC_DB_DEINIT_MSG,
            sizeof(struct nss_wifi_mac_db_entry_info_msg), msg_cb, NULL);

    status = nss_wifi_mac_db_tx_msg(nss_contex, nmfdbmsg);
    qdf_mem_free(nmfdbmsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-br-fdb-nfy]: MAC Fwd table INIT message failed %d ", status);
        return 1;
    }

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss-br-fdb-nfy]: sent MAC forwarding database message to NSS");
    return 0;
}

/*
 * osif_nss_wifi_mac_db_entry_find()
 *  Find the Wi-Fi MAC database entry from pool.
 */
static uint32_t osif_nss_wifi_mac_db_entry_find(unsigned char *mac_addr)
{
    uint32_t idx;

    for (idx = 0;idx < NSS_WIFI_MAC_DB_ENTRIES_MAX;idx++)
    {
        if (!nss_wifi_mac_db_obj.entry_pool[idx].entry_valid) {
            continue;
        }
        if (qdf_is_macaddr_equal((struct qdf_mac_addr *)&nss_wifi_mac_db_obj.entry_pool[idx].info.mac_addr[0],
                                    (struct qdf_mac_addr *)mac_addr)) {
            return idx;
        }
    }

    /*
     * Here pool index would be invalid or entries max.
     */
    return idx;
}

/*
 * osif_nss_wifi_macdb_pool_entry_del()
 *  Fill the wifi bridge entries to  Wi-Fi MAC database entries pool.
 */
static bool osif_nss_wifi_macdb_pool_entry_del(unsigned char *mac_addr)
{
    uint32_t idx;
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    if (nss_wifi_mac_db_obj.ent_send_state == NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return false;
    }

    idx = osif_nss_wifi_mac_db_entry_find(mac_addr);

    if (idx != NSS_WIFI_MAC_DB_ENTRIES_MAX) {
        qdf_mem_zero(&nss_wifi_mac_db_obj.entry_pool[idx], sizeof(struct nss_wifi_mac_db_entry));
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return true;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    return false;
}

/*
 * osif_nss_wifi_macdb_pool_entry_update()
 *  Fill the wifi bridge entries to  Wi-Fi MAC database entries pool.
 */
static bool osif_nss_wifi_macdb_pool_entry_update(unsigned char *mac_addr,
                                                    nss_if_num_t nss_ifnum,
                                                    nss_if_num_t nss_rifnum,
                                                    uint32_t iftype,
                                                    uint32_t opmode,
                                                    unsigned char is_local)
{
    uint32_t idx;

    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    if (nss_wifi_mac_db_obj.ent_send_state == NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return false;
    }

    idx = osif_nss_wifi_mac_db_entry_find(mac_addr);

    if (idx != NSS_WIFI_MAC_DB_ENTRIES_MAX) {
        nss_wifi_mac_db_obj.entry_pool[idx].info.nss_if = nss_ifnum;
        nss_wifi_mac_db_obj.entry_pool[idx].info.wiphy_ifnum = nss_rifnum;
        nss_wifi_mac_db_obj.entry_pool[idx].info.opmode = opmode;
        nss_wifi_mac_db_obj.entry_pool[idx].info.flag |= is_local ? NSS_WIFI_MAC_DB_ENTRY_IF_LOCAL : 0;
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return true;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    return false;
}

/*
 * osif_nss_wifi_macdb_pool_entries_fill()
 *  Fill the wifi bridge entries to  Wi-Fi MAC database entries pool.
 */
static bool osif_nss_wifi_macdb_pool_entries_fill(unsigned char *mac_addr,
                                                    nss_if_num_t nss_ifnum,
                                                    nss_if_num_t nss_rifnum,
                                                    uint32_t iftype,
                                                    uint32_t opmode,
                                                    unsigned char is_local)
{

    uint32_t idx;

    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    /*
     * Do not add entry to pool if state is in-progress or send complete, send it to NSS FW.
     */
    if (nss_wifi_mac_db_obj.ent_send_state == NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE ||
            nss_wifi_mac_db_obj.ent_send_state == NSS_WIFI_MACDB_ENTRIES_SEND_IN_PROGRESS) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return false;
    }

    for (idx = 0;idx < NSS_WIFI_MAC_DB_ENTRIES_MAX;idx++)
    {
        if (nss_wifi_mac_db_obj.entry_pool[idx].entry_valid) {
            if (!qdf_mem_cmp(nss_wifi_mac_db_obj.entry_pool[idx].info.mac_addr,
                            mac_addr,
                            QDF_MAC_ADDR_SIZE)) {
	            goto entry_present;
            }
            continue;
        }

        memcpy(nss_wifi_mac_db_obj.entry_pool[idx].info.mac_addr, mac_addr, 6);

entry_present:
        nss_wifi_mac_db_obj.entry_pool[idx].info.nss_if = nss_ifnum;
        nss_wifi_mac_db_obj.entry_pool[idx].info.wiphy_ifnum = nss_rifnum;
        nss_wifi_mac_db_obj.entry_pool[idx].info.opmode = opmode;
        nss_wifi_mac_db_obj.entry_pool[idx].info.iftype = iftype;
        nss_wifi_mac_db_obj.entry_pool[idx].info.flag |= is_local ? NSS_WIFI_MAC_DB_ENTRY_IF_LOCAL : 0;
        nss_wifi_mac_db_obj.entry_pool[idx].entry_valid = 1;
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        return true;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss_wifi_mac_db]: No available slot in entries pool for mac:%pM ", mac_addr);
    return false;
}

/*
 * osif_nss_wifi_interface_entries_send()
 *  Send the wifi bridge entries to NSS FW
 */
static int osif_nss_wifi_interface_entries_send(struct net_device *dev, unsigned char *mac_addr,
                                                unsigned char is_local, uint32_t event)
{
    nss_tx_status_t status;
    wlan_if_t vap = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    osif_dev *osifp = NULL;
    struct nss_wifi_mac_db_entry_info_msg *nmfdbeimsg;
    struct nss_wifi_mac_db_msg *nmfdbmsg = NULL;
    struct nss_ctx_instance *nss_contex = NULL;
    uint32_t opmode;
    nss_wifi_mac_db_msg_callback_t msg_cb =
        (nss_wifi_mac_db_msg_callback_t)osif_nss_wifi_mac_db_event_receive;

    nss_contex = nss_wifi_mac_db_get_context();
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return 0;
    }

    osifp = ath_netdev_priv(dev);

    /*
     * When notifier reaches for wds ext netdev, its priv structure may
     * be different to that of default(osif_dev) private structure.
     * Check the interface type and return.
     */
#ifdef QCA_SUPPORT_WDS_EXTENDED
    if (osifp->dev_type == OSIF_NETDEV_TYPE_WDS_EXT) {
        return 0;
    }
#endif

    vap = osifp->os_if;
    if (!vap) {
        return 0;
    }

    scn = (struct ol_ath_softc_net80211 *)(vap->iv_ic);

    if (!scn) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-wifi-mac-db-nfy]: Scn is invalid ");
        return 0;
    }

    /*
     * Check if entry pool is allocated.
     */
    if (!osif_nss_wifi_mac_db_check_entry_pool()) {
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-wifi-mac-db-nfy]: Entry pool memory is NULL ");
        return 0;
    }

    if (vap->iv_opmode == IEEE80211_M_STA) {
        opmode = NSS_WIFI_MAC_DB_ENTRY_IF_OPMODE_WIFI_STA;
    }else if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        opmode = NSS_WIFI_MAC_DB_ENTRY_IF_OPMODE_WIFI_AP;
    } else {
        opmode = NSS_WIFI_MAC_DB_ENTRY_IF_OPMODE_NONE;
    }

    if (osifp->nss_ifnum == -1) {
        return 0;
    }

    /*
     * Add,delete or update mac database entries into pool.
     */
    switch (event) {
    case NSS_WIFI_MAC_DB_DEL_ENTRY_MSG:
        if (osif_nss_wifi_macdb_pool_entry_del(mac_addr)) {
            return 0;
        }
        break;
    case NSS_WIFI_MAC_DB_UPDATE_ENTRY_MSG:
        if (osif_nss_wifi_macdb_pool_entry_update(mac_addr,
                                            osifp->nss_ifnum,
                                            scn->nss_radio.nss_rifnum,
                                            NSS_WIFI_MAC_DB_ENTRY_IFTYPE_VAP,
                                            opmode,
                                            is_local)) {
            return 0;
        }
        break;
    case NSS_WIFI_MAC_DB_ADD_ENTRY_MSG:
        if (osif_nss_wifi_macdb_pool_entries_fill(mac_addr,
                                            osifp->nss_ifnum,
                                            scn->nss_radio.nss_rifnum,
                                            NSS_WIFI_MAC_DB_ENTRY_IFTYPE_VAP,
                                            opmode,
                                            is_local)) {
            return 0;
        }
        break;
    }

    /*
     * Check if Wi-Fi MAC database is initialized.
     */
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (!nss_wifi_mac_db_obj.nwmdb_init) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                        "NSS Wi-Fi MAC database not initialized");
        return 0;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    /*
     * No free memory available in global pool
     */
    nmfdbmsg = qdf_mem_malloc_atomic(sizeof(struct nss_wifi_mac_db_msg));
    if (nmfdbmsg == NULL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: message pool memory allocation failure");
        return 0;
    }

    memset(nmfdbmsg, 0, sizeof(struct nss_wifi_mac_db_msg));


    nmfdbeimsg = &nmfdbmsg->msg.nmfdbeimsg;

    /*
     * Send the entry information to NSS FW
     */
    memcpy(nmfdbeimsg->mac_addr, mac_addr, 6);

    /*
     * Prepare Delete message and send
     */
    if (event == NSS_WIFI_MAC_DB_DEL_ENTRY_MSG) {
        nss_cmn_msg_init(&nmfdbmsg->cm, NSS_WIFI_MAC_DB_INTERFACE,
                event,
                sizeof(struct nss_wifi_mac_db_entry_info_msg),
                msg_cb, NULL);
        goto send_msg;
    }

    /*
     * Prepare ADD message
     */
    if (osifp->nss_ifnum == -1) {
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-wifi-mac-db-nfy]: MAC:%pM - NSS interface:%d invalid", mac_addr, osifp->nss_ifnum);
        qdf_mem_free(nmfdbmsg);
        return 0;
    }

    nmfdbeimsg->nss_if = osifp->nss_ifnum;
    nmfdbeimsg->wiphy_ifnum = scn->nss_radio.nss_rifnum;
    nmfdbeimsg->iftype = NSS_WIFI_MAC_DB_ENTRY_IFTYPE_VAP;
    nmfdbeimsg->opmode = opmode;

    if (is_local) {
        nmfdbeimsg->flag |= NSS_WIFI_MAC_DB_ENTRY_IF_LOCAL;
    }

    /*
     * Prepare and send the message to MAC FWD DB interface
     */
    nss_cmn_msg_init(&nmfdbmsg->cm, NSS_WIFI_MAC_DB_INTERFACE,
            event,
            sizeof(struct nss_wifi_mac_db_entry_info_msg),
            msg_cb, NULL);

send_msg:
    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss-br-fdb-nfy]: WiFi MAC DB VAP entry MAC:%pM IF:%d ", mac_addr,
            osifp->nss_ifnum);

    status = nss_wifi_mac_db_tx_msg(nss_contex, nmfdbmsg);
    qdf_mem_free(nmfdbmsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-br-fdb-nfy]: WiFi MAC DB entry message send fail%d ", status);

        return 1;
    }

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss-br-fdb-nfy]: sent message to NSS");
    return 0;
}

/*
 * osif_nss_eth_interface_entries_send()
 *  Send the ethernet bridge entries to NSS.
 */
static int osif_nss_eth_interface_entries_send(struct net_device *dev, unsigned char *mac_addr,
                                                unsigned char is_local, uint32_t event)
{
    struct nss_wifi_mac_db_msg *nmfdbmsg = NULL;
    struct nss_wifi_mac_db_entry_info_msg *nmfdbeimsg;
    nss_tx_status_t status;
    struct nss_ctx_instance *nss_contex;
    nss_wifi_mac_db_msg_callback_t msg_cb =
        (nss_wifi_mac_db_msg_callback_t)osif_nss_wifi_mac_db_event_receive;
    nss_if_num_t nss_ifnum = 0;

    /*
     * Check if entry pool is allocated.
     */
    if (!osif_nss_wifi_mac_db_check_entry_pool()) {
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-wifi-mac-db-nfy]: Entry pool memory is NULL ");
        return 0;
    }

    /*
     * Get NSS interface number for ethernet device.
     */
    nss_ifnum = nss_cmn_get_interface_number_by_dev(dev);
    if (!NSS_IF_IS_VALID(nss_ifnum)) {
        return 0;
    }

    /*
     * Add,delete or update mac database entries into pool.
     */
    switch (event) {
    case NSS_WIFI_MAC_DB_DEL_ENTRY_MSG:
        if (osif_nss_wifi_macdb_pool_entry_del(mac_addr)) {
            return 0;
        }
        break;
    case NSS_WIFI_MAC_DB_UPDATE_ENTRY_MSG:
        if (osif_nss_wifi_macdb_pool_entry_update(mac_addr,
                                            nss_ifnum,
                                            nss_ifnum,
                                            NSS_WIFI_MAC_DB_ENTRY_IFTYPE_NON_VAP,
                                            NSS_WIFI_MAC_DB_ENTRY_IF_OPMODE_ETH,
                                            is_local)) {
            return 0;
        }
        break;
    case NSS_WIFI_MAC_DB_ADD_ENTRY_MSG:
        if (osif_nss_wifi_macdb_pool_entries_fill(mac_addr,
                                            nss_ifnum,
                                            nss_ifnum,
                                            NSS_WIFI_MAC_DB_ENTRY_IFTYPE_NON_VAP,
                                            NSS_WIFI_MAC_DB_ENTRY_IF_OPMODE_ETH,
                                            is_local)) {
            return 0;
        }
        break;
    }

    /*
     * Check if Wi-Fi MAC database is initialized.
     */
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (!nss_wifi_mac_db_obj.nwmdb_init) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                        "NSS Wi-Fi MAC database not initialized");
        return 0;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    nss_contex = nss_wifi_mac_db_get_context();
    if (!nss_contex) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return 0;
    }

    /*
     * Allocate the memory to prepare bridge notify message
     */
    nmfdbmsg = qdf_mem_malloc_atomic(sizeof(struct nss_wifi_mac_db_msg));
    if (nmfdbmsg == NULL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: message pool memory allocation failure");
        return 0;
    }

    memset(nmfdbmsg, 0, sizeof(struct nss_wifi_mac_db_msg));

    nmfdbeimsg = &nmfdbmsg->msg.nmfdbeimsg;

    memcpy(nmfdbeimsg->mac_addr, mac_addr, 6);
    nmfdbeimsg->nss_if = nss_ifnum;
    nmfdbeimsg->wiphy_ifnum = nss_ifnum;
    nmfdbeimsg->iftype = NSS_WIFI_MAC_DB_ENTRY_IFTYPE_NON_VAP;
    nmfdbeimsg->opmode = NSS_WIFI_MAC_DB_ENTRY_IF_OPMODE_ETH;
    nmfdbeimsg->flag |= is_local ? NSS_WIFI_MAC_DB_ENTRY_IF_LOCAL : 0;

    /*
     *  Send message to WiFi MAC DB interface
     */
    nss_cmn_msg_init(&nmfdbmsg->cm, NSS_WIFI_MAC_DB_INTERFACE, event,
            sizeof(struct nss_wifi_mac_db_entry_info_msg), msg_cb, NULL);

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss-br-fdb-nfy]: WiFI MAC DB entry MAC:%pM ", mac_addr);

    status = nss_wifi_mac_db_tx_msg(nss_contex, nmfdbmsg);
    qdf_mem_free(nmfdbmsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-br-fdb-nfy]: WiFi MAC DB entry message send fail%d ", status);
        return 1;
    }

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "[nss-br-fdb-nfy]: sent message to NSS");
    return 0;
}

#if DBDC_REPEATER_SUPPORT
/*
 * osif_nss_interface_eth_entries_init()
 *  Send bridge fdb ethernet entries after boot up
 */
static int osif_nss_interface_eth_entries_init(struct net_device *dev)
{
    qca_multi_link_tbl_entry_t *qmlt_entry = NULL;
    void *fdb_entry_buff = NULL;
    int buff_size = 0;
    int num_of_entries = 0;
    int i;
    struct net_device *br_dev = qca_multi_link_tbl_get_bridge_dev(dev);

    if (!br_dev) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: Failed eth entries init - Bridge device NULL ");
        return 0;
    }

    nss_wifi_mac_db_device.br_dev = br_dev;

    if (!osif_nss_register_wifi_mac_db_interface(NSS_WIFI_MAC_DB_INTERFACE, (struct net_device *)&nss_wifi_mac_db_device)) {
        return 0;
    }

    buff_size = sizeof(struct qca_multi_link_tbl_entry) * MAX_NUM_ETH_FDB_ENTRIES;
    fdb_entry_buff = qdf_mem_malloc_atomic(buff_size);
    if (fdb_entry_buff == NULL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-wifi-mac-db-nfy]: message pool memory allocation failure");
        return 0;
    }

    num_of_entries = qca_multi_link_tbl_get_eth_entries(dev, fdb_entry_buff, buff_size);
    if (!num_of_entries) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: No entries");
        qdf_mem_free(fdb_entry_buff);
        return 0;
    }

    qmlt_entry = (qca_multi_link_tbl_entry_t *)fdb_entry_buff;
    for (i = 0; i < num_of_entries ;i++) {
        osif_nss_eth_interface_entries_send(qmlt_entry[i].qal_fdb_dev,
                &qmlt_entry[i].qal_mac_addr[0], qmlt_entry[i].qal_fdb_is_local,
                NSS_WIFI_MAC_DB_ADD_ENTRY_MSG);
    }

    qdf_mem_free(fdb_entry_buff);
    return 0;
}
#else
static int osif_nss_interface_eth_entries_init(struct net_device *dev)
{
    return 0;
}
#endif


static int osif_nss_interface_node_br_fdb_event(struct notifier_block *nb,
                                                unsigned long event,
                                                void *data)
{
    uint32_t fdb_event;
    struct br_fdb_event *fe = (struct br_fdb_event *)data;
    struct net_device *dev = fe->dev;

    if (!nss_wifi_mac_db_obj.nwmdb_if_register) {
        osif_nss_interface_eth_entries_init(dev);
    }

    /*
     * Check if the event is FDB Entry ADD or DEL
     */
    if (event != BR_FDB_EVENT_ADD && event != BR_FDB_EVENT_DEL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: Invalid Mac Fwd DB entry event :%lu", event);
        return 0;
    }

    if (event != BR_FDB_EVENT_ADD) {
        fdb_event = NSS_WIFI_MAC_DB_DEL_ENTRY_MSG;
    } else {
        fdb_event = NSS_WIFI_MAC_DB_ADD_ENTRY_MSG;
    }

    /*
     * Handling eth type interface notifier event.
     */
    if (!dev->ieee80211_ptr) {
        return osif_nss_eth_interface_entries_send(dev, fe->addr, fe->is_local, fdb_event);
    }

    /*
     * Handling vap type interface notifier event.
     */
    return osif_nss_wifi_interface_entries_send(dev, fe->addr, fe->is_local, fdb_event);
}

/*
 * osif_nss_interface_node_br_fdb_update_event()
 *      This is a callback for "bridge fdb update event. It is called
 *      When a MAC address is moved to another interface.
 *
 */
static int osif_nss_interface_node_br_fdb_update_event(struct notifier_block *nb,
                                                        unsigned long event,
                                                        void *data)
{
    struct br_fdb_event *fe = (struct br_fdb_event *)data;
    struct net_device *dev = fe->dev;
    uint32_t fdb_event = NSS_WIFI_MAC_DB_UPDATE_ENTRY_MSG;

    /*
     * Return if the notifier interface is not yet registered
     */
    if (!nss_wifi_mac_db_obj.nwmdb_if_register) {
        return NOTIFY_DONE;
    }

    /*
     * Check if original and current devs are not NULL.
     */
    if (!fe->orig_dev || !fe->dev) {
        return NOTIFY_DONE;
    }

    /*
     * If the old and new devs are the same, we don't need to handle this event.
     */
    if (fe->orig_dev == fe->dev) {
        return NOTIFY_DONE;
    }

    /*
     * Handling eth type interface for update event.
     */
    if (!dev->ieee80211_ptr) {
        return osif_nss_eth_interface_entries_send(dev, fe->addr, fe->is_local, fdb_event);
    }

    return osif_nss_wifi_interface_entries_send(dev, fe->addr, fe->is_local, fdb_event);
}

#if DBDC_REPEATER_SUPPORT
static struct notifier_block nss_interface_node_br_fdb_update_nb = {
    .notifier_call = osif_nss_interface_node_br_fdb_update_event,
};

void osif_nss_br_fdb_update_notifier_register(void)
{
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (!nss_wifi_mac_db_obj.br_update_ntfy_register) {
        qca_multi_link_tbl_register_update_notifier((void *)&nss_interface_node_br_fdb_update_nb);
        nss_wifi_mac_db_obj.br_update_ntfy_register = true;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
}
#else
void osif_nss_br_fdb_update_notifier_register(void)
{
    return;
}
#endif
qdf_export_symbol(osif_nss_br_fdb_update_notifier_register);

#if DBDC_REPEATER_SUPPORT
void osif_nss_br_fdb_update_notifier_unregister(void)
{
    if (nss_wifi_mac_db_obj.br_update_ntfy_register) {
        qca_multi_link_tbl_unregister_update_notifier((void *)&nss_interface_node_br_fdb_update_nb);
    }
}
#else
void osif_nss_br_fdb_update_notifier_unregister(void)
{
    return;
}
#endif
qdf_export_symbol(osif_nss_br_fdb_update_notifier_unregister);

#if DBDC_REPEATER_SUPPORT
static struct notifier_block nss_interface_node_br_fdb_nb = {
    .notifier_call = osif_nss_interface_node_br_fdb_event,
};

void osif_nss_br_fdb_notifier_register(void)
{
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (!nss_wifi_mac_db_obj.br_ntfy_register) {
        qca_multi_link_tbl_register_notifier((void *)&nss_interface_node_br_fdb_nb);
        nss_wifi_mac_db_obj.br_ntfy_register = true;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
}
#else
void osif_nss_br_fdb_notifier_register(void)
{
    return;
}
#endif
qdf_export_symbol(osif_nss_br_fdb_notifier_register);

#if DBDC_REPEATER_SUPPORT
void osif_nss_br_fdb_notifier_unregister(void)
{
    /*
     * Before unregistering with bridge notifier,
     * perform wifi mac db deinit and deregister wifi mac db interface with NSS
     */
    if (nss_wifi_mac_db_obj.br_ntfy_register) {
        if (nss_wifi_mac_db_obj.nwmdb_init) {
            osif_nss_wifi_mac_db_deinit();
            nss_wifi_mac_db_obj.nwmdb_init = false;
        }
        if (nss_wifi_mac_db_obj.nwmdb_if_register) {
            osif_nss_unregister_wifi_mac_db_interface(NSS_WIFI_MAC_DB_INTERFACE);
        }
        qca_multi_link_tbl_unregister_notifier((void *)&nss_interface_node_br_fdb_nb);
    }
}
#else
void osif_nss_br_fdb_notifier_unregister(void)
{
    return;
}
#endif
qdf_export_symbol(osif_nss_br_fdb_notifier_unregister);

/*
 * WiFi mac database object initialize
 */
void osif_nss_wifi_mac_db_obj_init(void)
{
    qdf_spinlock_create(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    nss_wifi_mac_db_obj.br_ntfy_register = false;
    nss_wifi_mac_db_obj.br_update_ntfy_register = false;
    nss_wifi_mac_db_obj.nwmdb_init = false;
    nss_wifi_mac_db_obj.nwmdb_if_register = false;
    nss_wifi_mac_db_obj.ent_send_state = NSS_WIFI_MACDB_ENTRIES_NOT_SENT;
    nss_wifi_mac_db_obj.entry_pool = qdf_mem_malloc_atomic(sizeof(struct nss_wifi_mac_db_entry) * NSS_WIFI_MAC_DB_ENTRIES_MAX);
    if (!nss_wifi_mac_db_obj.entry_pool) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
            "[nss_wifi_mac_db]: Memory allocation failure for entries pool");
    }
    qdf_atomic_init(&nss_wifi_mac_db_obj.num_entry_msgs);
}
qdf_export_symbol(osif_nss_wifi_mac_db_obj_init);

/*
 * WiFi mac database object deinitialize
 */
void osif_nss_wifi_mac_db_obj_deinit(void)
{
    qdf_spinlock_destroy(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    nss_wifi_mac_db_obj.br_ntfy_register = false;
    nss_wifi_mac_db_obj.br_update_ntfy_register = false;
    if (nss_wifi_mac_db_obj.entry_pool) {
        qdf_mem_free(nss_wifi_mac_db_obj.entry_pool);
    }
}
qdf_export_symbol(osif_nss_wifi_mac_db_obj_deinit);

/*
 * osif_nss_ol_assign_ifnum : Get NSS IF Num based on Radio ID
 */

int osif_nss_ol_assign_ifnum(int radio_id, ol_ath_soc_softc_t *soc, bool is_2g) {

	uint32_t i = 0;
	uint32_t found_idx = 0;
	uint32_t start_idx = 0;

	if (is_2g) {
		start_idx = 1;
	}

	for (i = start_idx; i < 3; i++) {
		if ((glbl_allocated_radioidx & (1 << i)) == 0) {
			glbl_allocated_radioidx |= (1 << i);
			found_idx = 1;
			break;
		}
	}

	if (!found_idx) {
		qdf_print("%s: Unable to allocate nss interface is_2g %d radioidx val %x startidx %x", __FUNCTION__, is_2g, glbl_allocated_radioidx, start_idx);
		soc->nss_soc.nss_sidx = -1;
		return -1;
	}

	soc->nss_soc.nss_sidx = i;

	switch (i) {
		case 0:
			return NSS_WIFI_INTERFACE0;

		case 1:
			return NSS_WIFI_INTERFACE1;

		case 2:
			return NSS_WIFI_INTERFACE2;
	}

	return -1;

}

void osif_nss_register_module(OL_WIFI_DEV_TYPE target_type,
			struct nss_wifi_soc_ops *soc_ops)
{
    if (target_type < OL_WIFI_TYPE_MAX) {
        nss_wifi_soc_register[target_type] = soc_ops;
	qdf_print("NSS wifi ops registered for target_type:%d with soc_ops:%pK",
			target_type, soc_ops);
    }

	return;
}
qdf_export_symbol(osif_nss_register_module);

/**
 * osif_nss_wifi_soc_setup() - soc setup
 * @soc : soc handle
 */
void osif_nss_wifi_soc_setup(ol_ath_soc_softc_t *soc)
{
    uint32_t target_type = lmac_get_tgt_type(soc->psoc_obj);
    uint8_t radio_cnt = 1;
    enum wmi_host_hw_mode_config_type preferred_hw_mode = lmac_get_preferred_hw_mode(soc->psoc_obj);

    soc->nss_soc.nss_wifiol_id = -1;
    soc->nss_soc.ops = NULL;
    if (nss_cmn_get_nss_enabled() == true) {
        if (cfg_get(soc->psoc_obj, CFG_NSS_WIFI_OL) & (1 << global_device_id )) {

            if ((target_type == TARGET_TYPE_AR900B)
                    || (target_type == TARGET_TYPE_QCA9984) ){

                soc->nss_soc.nss_wifiol_id = nssdevice_id;
                soc->nss_soc.nss_sifnum = osif_nss_ol_assign_ifnum(soc->nss_soc.nss_wifiol_id,
                        soc ,(cfg_get(soc->psoc_obj, CFG_NSS_WIFI_OL) >> 16 & (1 << global_device_id)));

                if (soc->nss_soc.nss_sifnum == -1) {
                    soc->nss_soc.nss_wifiol_id = -1;
                    qdf_print("Unable to assign interface number for radio %d", soc->nss_soc.nss_wifiol_id);
                    /* error = -EINVAL; */
                    goto devnotenabled;
                }

                soc->nss_soc.ops = nss_wifi_soc_register[OL_WIFI_2_0];
                if (!soc->nss_soc.ops) {
                    qdf_print("nss-wifi:nss wifi ops is NULL for WIFI2.0 target");
                    /* error = -EINVAL; */
                    goto devnotenabled;
                }

                qdf_print("nss-wifi:#1 register wifi function for soc nss id %d device id %d", nssdevice_id, global_device_id);

                nssdevice_id++;
                qdf_print("nss_wifi_olcfg value is %x", cfg_get(soc->psoc_obj, CFG_NSS_WIFI_OL));
                qdf_print("Got NSS IFNUM as %d", soc->nss_soc.nss_sifnum);

                if(cfg_get(soc->psoc_obj, CFG_NSS_NEXT_HOP) & (1 << global_device_id )) {
                    soc->nss_soc.nss_nxthop = 1;
                }

            } else if ((target_type == TARGET_TYPE_QCA8074) ||
                        (target_type == TARGET_TYPE_QCA8074V2) ||
                        (target_type == TARGET_TYPE_QCN9000) ||
                        (target_type == TARGET_TYPE_QCN6122) ||
                        (target_type == TARGET_TYPE_QCA5018) ||
                        (target_type == TARGET_TYPE_QCA6018)) {
                switch (preferred_hw_mode) {
                    case WMI_HOST_HW_MODE_DBS:
                        soc->nss_soc.nss_scfg = 0x3;
                        radio_cnt = 2;
                        break;
                    case WMI_HOST_HW_MODE_DBS_OR_SBS:
                        soc->nss_soc.nss_scfg = 0x3;
                        radio_cnt = 2;
                        break;
                    case WMI_HOST_HW_MODE_DBS_SBS:
                        soc->nss_soc.nss_scfg = 0x7;
                        radio_cnt = 3;
                        break;
                    case WMI_HOST_HW_MODE_SINGLE:
                        soc->nss_soc.nss_scfg = 0x1;
                        radio_cnt = 1;
                        break;
                    case WMI_HOST_HW_MODE_2G_PHYB:
                        soc->nss_soc.nss_scfg = 0x1;
                        radio_cnt = 1;
                        break;
                    case WMI_HOST_HW_MODE_DETECT:
                        if (cfg_get(soc->psoc_obj, CFG_OL_DYNAMIC_HW_MODE)) {
                            soc->nss_soc.nss_scfg = 0x7;
                            radio_cnt = 3;
                        } else {
                            qdf_info("nss-wifili: Could not set nss_cfg due to Invalid HW mode %d",
                                     preferred_hw_mode);
                            goto devnotenabled;
                        }
                        break;
                    default:
                        qdf_info("nss-wifili: Could not set nss_cfg due to Invalid HW mode %d", preferred_hw_mode);
                        goto devnotenabled;
                }

		soc->nss_soc.ops = nss_wifi_soc_register[OL_WIFI_3_0];
                if (!soc->nss_soc.ops) {
                    qdf_print("nss-wifi:nss wifi ops is NULL for WIFI3.0 target");
                    /* error = -EINVAL; */
                    soc->nss_soc.nss_scfg = 0x0;
                    radio_cnt = 0;
                    goto devnotenabled;
                }

                if (cfg_get(soc->psoc_obj, CFG_NSS_NEXT_HOP)) {
                    soc->nss_soc.nss_nxthop = 1;
                }

                qdf_print("nss-wifili:#1 register wifili function for soc ");
            } else {
                qdf_print("Target type not supported in NSS wifi offload %x", target_type);
            }

        }
        if (soc->nss_soc.ops) {
            soc->nss_soc.ops->nss_soc_wifi_init(soc);
        }
    }
devnotenabled:
    qdf_print("nss register id %d nss config %x Target Type %x ",
            soc->nss_soc.nss_wifiol_id, cfg_get(soc->psoc_obj, CFG_NSS_WIFI_OL), target_type);
    global_device_id+= radio_cnt;
}

/*
 * osif_nss_mac_db_entries_prepare_n_send
 *  Prepare entries to be sent to NSS FW.
 */
uint32_t osif_nss_mac_db_entries_prepare_n_send(uint32_t *cur_idx)
{
    uint32_t entries_idx = 0;
    bool status = false;
    struct nss_wifi_mac_db_msg *nmfdbmsg = NULL;
    struct nss_wifi_mac_db_entry_group_info_msg *nmfdbgimsg = NULL;
    struct nss_ctx_instance *nss_ctx;
    uint32_t buff_size = sizeof(struct nss_wifi_mac_db_msg);

    nss_ctx = nss_wifi_mac_db_get_context();
    if (!nss_ctx) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss_wifi_mac_db]: NSS context is invalid ");
        return 0;
    }
    nmfdbmsg = qdf_mem_malloc_atomic(buff_size);
    if (nmfdbmsg == NULL) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,"[nss-wifi-mac-db-nfy]: message pool memory allocation failure");
        return 0;
    }

    memset(nmfdbmsg, 0, buff_size);
    nmfdbgimsg = &nmfdbmsg->msg.nmfdbegimsg;

    /*
     * Iterate on each entry and get metadata to be sent to nss fw.
     */
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    /*
     * If station vap is down before entries are sent, we may not send entries.
     */
    if (nss_wifi_mac_db_obj.ent_send_state != NSS_WIFI_MACDB_ENTRIES_SEND_IN_PROGRESS) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        qdf_mem_free(nmfdbmsg);
        return 0;
    }

    while (entries_idx < NSS_WIFI_MAC_DB_GROUP_ENTRIES_MAX) {

        /*
         * Entries max is chosen considering smallest buffer size and entry size.
         */
        if (*cur_idx == NSS_WIFI_MAC_DB_ENTRIES_MAX) {
            break;
        }

        if (!nss_wifi_mac_db_obj.entry_pool[*cur_idx].entry_valid) {
            *cur_idx += 1;
            continue;
        }

        memcpy(&nmfdbgimsg->entry[entries_idx].mac_addr[0], &nss_wifi_mac_db_obj.entry_pool[*cur_idx].info.mac_addr[0], 6);
        nmfdbgimsg->entry[entries_idx].nss_if = nss_wifi_mac_db_obj.entry_pool[*cur_idx].info.nss_if;
        nmfdbgimsg->entry[entries_idx].wiphy_ifnum = nss_wifi_mac_db_obj.entry_pool[*cur_idx].info.wiphy_ifnum;
        nmfdbgimsg->entry[entries_idx].opmode = nss_wifi_mac_db_obj.entry_pool[*cur_idx].info.opmode;
        nmfdbgimsg->entry[entries_idx].iftype = nss_wifi_mac_db_obj.entry_pool[*cur_idx].info.iftype;
        nmfdbgimsg->entry[entries_idx].flag = nss_wifi_mac_db_obj.entry_pool[*cur_idx].info.flag;

        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_TRACE,
                "mac:%pM local:%d nss_if:%d", &nmfdbgimsg->entry[entries_idx].mac_addr[0], nmfdbgimsg->entry[entries_idx].flag, nmfdbgimsg->entry[entries_idx].nss_if);

        /*
         * Reset entry once it is captured in message.
         */
        qdf_mem_zero(&nss_wifi_mac_db_obj.entry_pool[*cur_idx], sizeof(struct nss_wifi_mac_db_entry));

        entries_idx++;
        *cur_idx += 1;
        nmfdbgimsg->num_entries++;
    }
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    if (!nmfdbgimsg->num_entries) {
        qdf_mem_free(nmfdbmsg);
        return 0;
    }

    /*
     * Prepare and send the message to MAC FWD DB interface
     */
    nss_cmn_msg_init(&nmfdbmsg->cm, NSS_WIFI_MAC_DB_INTERFACE,
            NSS_WIFI_MAC_DB_GROUP_ENTRIES_ADD_MSG,
            sizeof(struct nss_wifi_mac_db_entry_group_info_msg),
            osif_nss_wifi_mac_db_event_receive,
            NULL);

    status = nss_wifi_mac_db_tx_msg(nss_ctx, nmfdbmsg);
    qdf_mem_free(nmfdbmsg);
    if (status != NSS_TX_SUCCESS) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                "[nss-br-fdb-nfy]: WiFi MAC DB entry message send fail%d ", status);

        return 0;
    }

    /*
     * This is needed to check ACK is received for all messages.
     */
    qdf_atomic_inc(&nss_wifi_mac_db_obj.num_entry_msgs);

    return entries_idx;
}

/*
 * osif_nss_wifi_mac_db_pool_entries_send
 *  Send the entries captured in host Wi-Fi MAC database entries pool to NSS.
 */
bool osif_nss_wifi_mac_db_pool_entries_send(struct net_device *netdev)
{
    uint32_t cur_idx = 0;
    int num_of_entries = 0;

    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (!nss_wifi_mac_db_obj.nwmdb_init) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-br-fdb-nfy]: WiFi MAC DB not intialized");
        return false;
    }

    /*
     * Change the state to in-progress.
     * Add notifications received during this state will be sent directly to NSS.
     */
    nss_wifi_mac_db_obj.ent_send_state = NSS_WIFI_MACDB_ENTRIES_SEND_IN_PROGRESS;
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    while (cur_idx < NSS_WIFI_MAC_DB_ENTRIES_MAX) {
        num_of_entries = osif_nss_mac_db_entries_prepare_n_send(&cur_idx);
        if (!num_of_entries) {
            if (qdf_atomic_read(&nss_wifi_mac_db_obj.num_entry_msgs) == 0) {
                nss_wifi_mac_db_obj.ent_send_state = NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE;
            }

            QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,"[nss-wifi-mac-db-nfy]: No entries");
            return false;
        }
    }

    QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
            "NSS mac database entries sent:%d", num_of_entries);
    return true;
}

qdf_export_symbol(osif_nss_wifi_mac_db_pool_entries_send);


/*
 * osif_nss_wifi_mac_db_is_ready
 *  Check if Wi-Fi MAC database is initialized and
 *  ready to accept add,del and update events.
 */
bool osif_nss_wifi_mac_db_is_ready()
{
    if (nss_wifi_mac_db_obj.ent_send_state != NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE) {
        return false;
    }

    return true;
}

qdf_export_symbol(osif_nss_wifi_mac_db_is_ready);

/*
 * osif_nss_wifi_mac_db_reset_state
 *  Reset state and start collecting entries into pool.
 */
bool osif_nss_wifi_mac_db_reset_state()
{
    qdf_spin_lock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
    if (nss_wifi_mac_db_obj.ent_send_state != NSS_WIFI_MACDB_ENTRIES_SEND_COMPLETE) {
        qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);
        QDF_TRACE_ERROR_RL(QDF_MODULE_ID_NSS,
                "[nss-br-fdb-nfy]: Trying to reset for non complete state");
        return false;
    }
    nss_wifi_mac_db_obj.ent_send_state = NSS_WIFI_MACDB_ENTRIES_NOT_SENT;
    qdf_spin_unlock_bh(&nss_wifi_mac_db_obj.wifi_macdb_lock);

    return true;
}

qdf_export_symbol(osif_nss_wifi_mac_db_reset_state);
