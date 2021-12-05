/*
 * Copyright (c) 2014, 2017, 2019-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <qdf_nbuf.h>                       /* qdf_nbuf_t */
#include <rawmode_sim.h>
#include <mesh_util.h>

MODULE_DESCRIPTION("Support for rawmode packet simulation");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Proprietary");
#endif

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

rawsim_ctxt create_ctxt(void);
void delete_ctxt(rawsim_ctxt ctxt);
void rx_decap(rawsim_ctxt ctxt,
              qdf_nbuf_t *pdeliver_list_head,
              qdf_nbuf_t *pdeliver_list_tail,
              uint8_t *peer_mac,
              uint32_t sec_type,
              uint32_t auth_type);
int tx_encap(rawsim_ctxt ctxt,
             qdf_nbuf_t *pnbuf,
             u_int8_t *bssid,
             struct rawsim_ast_entry ast_entry);
void print_stats(rawsim_ctxt ctxt);
void clear_stats(rawsim_ctxt ctxt);
int update_config(struct rawmode_sim_cfg cfg, rawsim_ctxt ctxt);
int update_encap_frame_count(rawsim_ctxt ctxt, int frame_count, u_int8_t flag);
int update_decap_frame_count(rawsim_ctxt ctxt, int frame_count, u_int8_t flag);

extern void register_rawsim_ops(struct rawsim_ops *rs_ops);
extern void deregister_rawsim_ops(void);

static struct rawsim_ops rsim_ops = {
    .create_rawsim_ctxt = create_ctxt,
    .rx_decap = rx_decap,
    .tx_encap = tx_encap,
    .print_stats = print_stats,
    .clear_stats = clear_stats,
    .update_config = update_config,
    .update_encap_frame_count = update_encap_frame_count,
    .update_decap_frame_count = update_decap_frame_count,
    .delete_rawsim_ctxt = delete_ctxt,
};

#ifndef QCA_SINGLE_WIFI_3_0
static int __init rawsim_mod_init(void)
#else
int rawsim_mod_init(void)
#endif
{
    register_rawsim_ops(&rsim_ops);
    return 0;
}

#ifndef QCA_SINGLE_WIFI_3_0
static void __exit rawsim_mod_exit(void)
#else
void rawsim_mod_exit(void)
#endif
{
    deregister_rawsim_ops();
}

#ifndef QCA_SINGLE_WIFI_3_0
module_init(rawsim_mod_init);
module_exit(rawsim_mod_exit);
#endif

/* Raw Mode simulation - conversion between Raw 802.11 format and other
 * formats.
 */

/* Rx side helper functions */

static int is_80211amsdu(qdf_nbuf_t msdu);

static int
rx_fragstream_init(raw_rx_fragstream_ctx *sctx,
                   qdf_nbuf_t list_head,
                   u_int16_t headersize,
                   u_int16_t trailersize,
                   u_int32_t total_bytes,
                   u_int32_t preconsumed_bytes);

static int
rx_fragstream_peek(raw_rx_fragstream_ctx *sctx,
                   u_int32_t soffset,
                   u_int32_t numbytes,
                   u_int8_t *dst);

static int
rx_fragstream_consume(raw_rx_fragstream_ctx *sctx,
                      u_int32_t soffset,
                      u_int32_t numbytes,
                      u_int8_t *dst);

static int
decap_dot11withamsdu_to_8023(rawsim_ctxt ctxt,
                             qdf_nbuf_t *deliver_list_head,
                             qdf_nbuf_t *deliver_list_tail,
                             u_int32_t total_mpdu_len,
                             uint8_t *peer_mac,
                             uint32_t sec_type,
                             uint32_t auth_type,
                             bool print);

static int
decap_dot11_to_8023(qdf_nbuf_t msdu,
                    uint8_t *peer_mac,
                    rawsim_ctxt ctxt,
                    uint32_t sec_type,
                    uint32_t auth_type,
                    bool print);


/* Tx side helper functions */

static int encap_eth_to_dot11(qdf_nbuf_t nbuf,
                              enum ieee80211_opmode mode,
                              u_int8_t *bssid,
                              rawsim_ctxt ctxt,
                              struct rawsim_ast_entry ast_entry,
                              bool print);

static int encap_eth_to_dot11_amsdu(rawsim_ctxt ctxt,
                                    qdf_nbuf_t nbuf,
                                    enum ieee80211_opmode mode,
                                    u_int8_t *bssid,
                                    bool print);

static int form_amsdu_packet(rawsim_ctxt ctxt, qdf_nbuf_t nbuf, bool print);

static int check_ip_pkt(qdf_nbuf_t nbuf);

static int check_ip_more_frag(qdf_nbuf_t nbuf);

static int check_multicast(qdf_nbuf_t nbuf);

static void
txstats_inc_mpdu_noamsdu(rawsim_ctxt ctxt);

static void
txstats_inc_mpdu_withamsdu(rawsim_ctxt ctxt);

rawsim_ctxt create_ctxt()
{
    rawsim_ctxt ctxt =
            (rawsim_ctxt)qdf_mem_malloc(sizeof(struct rawmode_sim_ctxt));
    if (!ctxt)
        return NULL;

    qdf_mem_zero(ctxt, sizeof(struct rawmode_sim_ctxt));
    qdf_atomic_init(&ctxt->num_encap_frames);
    qdf_atomic_init(&ctxt->num_decap_frames);
    qdf_spinlock_create(&ctxt->tx_encap_lock);

    return ctxt;
}

void delete_ctxt(rawsim_ctxt ctxt)
{
    if (!ctxt)
        return;

    qdf_spinlock_destroy(&ctxt->tx_encap_lock);

    qdf_mem_free(ctxt);
}

/* This function to be invoked when packet simulation is enabled/disabled on a
   particular vdev. Also when any of the cfg parameter needs to be updated */
int update_config(struct rawmode_sim_cfg cfg, rawsim_ctxt ctxt)
{
    if (!ctxt) {
        rawsim_err("NULL sim ctxt");
        return 0;
    }
#if MESH_MODE_SUPPORT
    ctxt->mesh_mode = cfg.mesh_mode;
    ctxt->mhdr = cfg.mhdr;
    ctxt->mdbg = cfg.mdbg;
    ctxt->mhdr_len = cfg.mhdr_len;
    qdf_mem_copy(&ctxt->bssid_mesh, &cfg.bssid_mesh, QDF_MAC_ADDR_SIZE);
#endif /* MESH_MODE_SUPPORT */
    ctxt->vdev_id = cfg.vdev_id;
    ctxt->opmode = cfg.opmode;
    ctxt->rawmodesim_txaggr = cfg.rawmodesim_txaggr;
    ctxt->rawmodesim_debug_level = cfg.rawmodesim_debug_level;
    ctxt->privacyEnabled = cfg.privacyEnabled;
    ctxt->tx_encap_type = cfg.tx_encap_type;
    ctxt->rx_decap_type = cfg.rx_decap_type;
    ctxt->rawmode_pkt_sim = cfg.rawmode_pkt_sim;
    return 1;
}

int update_encap_frame_count(rawsim_ctxt ctxt, int count, u_int8_t flag)
{
    if (!ctxt)
        return 0;

    if (count < 0) {
        rawsim_err("Invalid (-ve) frame count");
        return 0;
    }

    qdf_atomic_set(&ctxt->num_encap_frames, (0 - count));
    ctxt->fixed_frm_cnt_flag = flag;

    return 1;
}

int update_decap_frame_count(rawsim_ctxt ctxt, int count, u_int8_t flag)
{
    if (!ctxt)
        return 0;

    if (count < 0) {
        rawsim_err("Invalid (-ve) frame count");
        return 0;
    }

    qdf_atomic_set(&ctxt->num_decap_frames, (0 - count));
    ctxt->fixed_frm_cnt_flag = flag;

    return 1;
}

/**
 * @brief Determine if nbuf contains an A-MSDU
 * @details
 *  Determine if nbuf contains the starting of a raw mode MPDU having an
 *  A-MSDU. It is the caller's responsibility to ensure that if scatter/gather
 *  is being used, it passes only the first (head) fragment to this function.
 *
 * @param mpdu - nbuf bearing the MPDU.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int is_80211amsdu(qdf_nbuf_t mpdu)
{
    struct ieee80211_frame *wh;
    uint8_t is_4addr;

    if (qdf_nbuf_len(mpdu) < sizeof(struct ieee80211_frame)) {
        rawsim_err("MPDU length invalid.");
        return -1;
    }

    wh = (struct ieee80211_frame *)qdf_nbuf_data(mpdu);

    if (((wh->i_fc[0]) & IEEE80211_FC0_SUBTYPE_MASK) !=
            IEEE80211_FC0_SUBTYPE_QOS) {
        return 0;
    }

    is_4addr = ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                    IEEE80211_FC1_DIR_DSTODS) ? 1:0;

    if (!is_4addr) {
        if (qdf_nbuf_len(mpdu) < sizeof(struct ieee80211_qosframe)) {
           rawsim_err("MPDU length invalid.");
           return -1;
        }

        return
            (((struct ieee80211_qosframe *)wh)->i_qos[0] &
             IEEE80211_QOS_AMSDU) ? 1:0;
    } else {
        if (qdf_nbuf_len(mpdu) < sizeof(struct ieee80211_qosframe_addr4)) {
           rawsim_err("MPDU length invalid.");
           return -1;
        }

        return
            (((struct ieee80211_qosframe_addr4*)wh)->i_qos[0] &
                IEEE80211_QOS_AMSDU) ? 1:0;
    }
}

/* Fragment stream processing functionality.
 * This functionality provides the ability to treat the contents of multiple
 * nbuf fragments as a continuous stream of bytes, and carry out operations
 * such as peeking at data and consuming data. The functionality provided is
 * intended only for use in simulation, and provides limited abilities just
 * sufficient for the simulation. See documentation for each function, for more
 * details.
 *
 */

/**
 * @brief Initialize fragment stream
 * @details
 *  Initialize a context corresponding to a fragment stream. The caller can
 *  specify the number the bytes in first fragment already consumed. This is to
 *  allow for use cases such as the caller processing the first MSDU in the head
 *  fragment independent of the fragment stream processing routines.
 *
 * @param sctx - Context corresponding to the fragment stream.
 * @param list_head - Head of linked list of fragments, i.e. the first fragment.
 * @param headersize - 802.11 header size (should be present in list_head).
 * @param trailersize - 802.11 trailer size.
 * @param total_bytes - Total number of bytes in MPDU.
 * @param preconsumed_bytes - Number of bytes in first fragment already
 *      consumed.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
rx_fragstream_init(raw_rx_fragstream_ctx *sctx,
                   qdf_nbuf_t list_head,
                   u_int16_t headersize,
                   u_int16_t trailersize,
                   u_int32_t total_bytes,
                   u_int32_t preconsumed_bytes)
{
    u_int32_t head_frag_size = 0;
    u_int32_t unconsumed_cnt_total = 0;

    /* Note: Some of the checks below are for completeness. Can be removed
     * during future optimization if desired, but included currently since
     * they are for use only during simulation and clarity is more important.
     */
    if (sctx == NULL) {
        rawsim_err("NULL fragment stream context passed");
        return -1;
    }

    if (sctx->is_valid == 1) {
        rawsim_err("Previously initialized stream context passed");
        return -1;
    }

    if (list_head == NULL) {
        rawsim_err("NULL list head passed");
        return -1;
    }

    /* Minimum sanity check: We need at least bare 802.11 data header size */
    if (headersize < sizeof(struct ieee80211_frame)) {
        rawsim_err("Invalid header size passed");
        return -1;
    }

    /* Minimum sanity check: We need atleast FCS */
    if (trailersize < 4) {
        rawsim_err("Invalid trailer size passed");
        return -1;
    }

    head_frag_size = qdf_nbuf_len(list_head);

    if (preconsumed_bytes > head_frag_size) {
        rawsim_err("Pre-consumed bytes exceed head fragment size");
        return -1;
    }

    unconsumed_cnt_total = total_bytes - preconsumed_bytes;

    if (unconsumed_cnt_total < trailersize) {
        rawsim_err("Unconsumed bytes less than expected trailer size");
        return -1;
    }

    sctx->list_head = list_head;
    sctx->headersize = headersize;
    sctx->trailersize = trailersize;

    /* Pre-consumption of bytes from head nbuf by caller is supported for nbuf
     * handling efficiency purposes (re-using head nbuf to carry decap output
     * for first MSDU).
     */
    if (preconsumed_bytes == head_frag_size) {
        sctx->currnbuf = qdf_nbuf_next(list_head);
        sctx->currnbuf_ptr = qdf_nbuf_data(sctx->currnbuf);
        sctx->unconsumed_cnt_curr = qdf_nbuf_len(sctx->currnbuf);
        if (qdf_nbuf_is_rx_chfrag_end(sctx->currnbuf)) {
            sctx->nextnbuf = NULL;
        } else {
            sctx->nextnbuf = qdf_nbuf_next(sctx->currnbuf);
        }
    } else {
        sctx->currnbuf = list_head;
        sctx->currnbuf_ptr = qdf_nbuf_data(list_head)+ preconsumed_bytes;
        sctx->unconsumed_cnt_curr = head_frag_size - preconsumed_bytes;
        sctx->nextnbuf = qdf_nbuf_next(list_head);
    }

    sctx->unconsumed_cnt_total = unconsumed_cnt_total;

    sctx->is_valid = 1;

    return 0;
}

/**
 * @brief Peek at contents in fragment stream
 * @details
 *  Retrieve a number of bytes of content at some offset from the current
 *  pointer in the fragment stream, without actually consuming (i.e. discarding)
 *  them after the copy. Thus the current pointer is not updated. This is useful
 *  for looking ahead at some fields such as length in order to allocate the
 *  requisite buffer prior to full-fledged consumption.  Note that some
 *  restrictions have been placed on the offset and number of bytes that can be
 *  peeked at, for simplicity. These restrictions center around the assumption
 *  that not more than one fragment boundary will need to be crossed in the
 *  process of peeking. This assumption holds true for the typical size of
 *  receive nbufs queued to hardware, and the use cases for the peek operations.
 *
 *  Note: It is the responsibility of the caller to ensure that the destination
 *  buffer has sufficient space.
 *
 * @param sctx - Context corresponding to the fragment stream.
 * @param soffset - Number of bytes to skip before starting peek. Should not be
 *      more than L_RX_FRAGSTREAM_PEEK_OFFSET_MAX.
 * @param numbytes - Number of bytes to copy. Should not be more than
 *      RAW_RX_FRAGSTREAM_PEEK_NBYTES_MAX.
 * @param dst - Destination buffer.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
rx_fragstream_peek(raw_rx_fragstream_ctx *sctx,
                   u_int32_t soffset,
                   u_int32_t numbytes,
                   u_int8_t *dst)
{
    u_int8_t *next_ptr = NULL;

    /* Note: Some of the checks below are for completeness. Can be removed
     * during future optimization if desired, but included currently since
     * they are for use only during simulation and clarity and correctness are
     * more important.
     */
    if (sctx == NULL){
        rawsim_err("NULL fragment stream context passed");
        return -1;
    }

    if (sctx->is_valid != 1) {
        rawsim_err("Invalid context passed");
        return -1;
    }

    if (dst == NULL){
        rawsim_err("NULL destination buffer passed");
        return -1;
    }

    if (soffset > RAW_RX_FRAGSTREAM_PEEK_OFFSET_MAX) {
        rawsim_err("Invalid value %u passed for offset", soffset);
        return -1;
    }

    if (numbytes > RAW_RX_FRAGSTREAM_PEEK_NBYTES_MAX) {
        rawsim_err("Invalid value %u passed for num bytes required",
                   numbytes);
        return -1;
    }

    if ((soffset + numbytes) > sctx->unconsumed_cnt_total ) {
        rawsim_err("Attempt detected to peek beyond stream boundary."
                   "offset=%u num bytes=%u unconsumed total count=%u",
                   soffset, numbytes, sctx->unconsumed_cnt_total);
        return -1;
    }

    /* It is the responsibility of the caller to ensure that dst
     * has space for numbytes.
     */

    if (sctx->unconsumed_cnt_curr <= soffset) {
        /* Offset falls into next nbuf */
        next_ptr = qdf_nbuf_data(sctx->nextnbuf) +
                   soffset -
                   sctx->unconsumed_cnt_curr;

        qdf_mem_copy(dst, next_ptr, numbytes);
    } else if (sctx->unconsumed_cnt_curr < (soffset + numbytes)) {
        /* Offset remains in current nbuf, but peek will overflow into next
         * nbuf
         */
        qdf_mem_copy(dst,
                        sctx->currnbuf_ptr + soffset,
                        sctx->unconsumed_cnt_curr - soffset);

        next_ptr = qdf_nbuf_data(sctx->nextnbuf);
        qdf_mem_copy(dst,
                        next_ptr,
                        numbytes - (sctx->unconsumed_cnt_curr - soffset));
    } else {
        /* Everything is contained in current nbuf */
        qdf_mem_copy(dst,
                        sctx->currnbuf_ptr + soffset,
                        numbytes);
    }

    return 0;
}

/**
 * @brief Copy and consume contents in fragment stream
 * @details
 *  Copy and consume a number of bytes of content at some offset from the
 *  current pointer in the fragment stream. The current pointer is updated to go
 *  past the offset and number of bytes copied . Thus the bytes at both the
 *  locations skipped by the offset and those covered by the copy are considered
 *  to have been consumed. These bytes will no longer be available through this
 *  context.
 *
 *  Note: It is the responsibility of the caller to ensure that the destination
 *  buffer has sufficient space.
 *
 * @param sctx - Context corresponding to the fragment stream.
 * @param soffset - Number of bytes to skip before starting consumption.
 * @param numbytes - Number of bytes to copy.
 * @param dst - Destination buffer.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
rx_fragstream_consume(raw_rx_fragstream_ctx *sctx,
                      u_int32_t soffset,
                      u_int32_t numbytes,
                      u_int8_t *dst)
{
    u_int32_t jmp_remaining = 0;
    u_int32_t cpy_remaining = 0;
    u_int32_t dstoffset = 0;

    /* Note: Some of the checks below are for completeness. Can be removed
     * during future optimization if desired, but included currently since
     * they are for use only during simulation and clarity is more important.
     */
    if (sctx == NULL){
        rawsim_err("NULL fragment stream context passed");
        return -1;
    }

    if (sctx->is_valid != 1) {
        rawsim_err("Invalid context passed");
        return -1;
    }

    if ((soffset + numbytes) > sctx->unconsumed_cnt_total ) {
        rawsim_err("Attempt detected to consume bytes beyond stream boundary.\n"
                   "offset=%u num bytes=%u unconsumed total count=%u",
                   soffset, numbytes, sctx->unconsumed_cnt_total);
        return -1;
    }

    /* It is the responsibility of the caller to ensure that dst
     * has space for numbytes (except if it is NULL, which indicates that the
     * caller merely wants a discard operation)..
     */

    jmp_remaining = soffset;

    while (jmp_remaining && sctx->currnbuf) {
        if (jmp_remaining >= sctx->unconsumed_cnt_curr) {
            jmp_remaining -= sctx->unconsumed_cnt_curr;
            sctx->unconsumed_cnt_total -= sctx->unconsumed_cnt_curr;
            sctx->currnbuf = sctx->nextnbuf;
            if (sctx->currnbuf) {
                if (qdf_nbuf_is_rx_chfrag_end(sctx->currnbuf)) {
                    sctx->nextnbuf = NULL;
                } else {
                    sctx->nextnbuf = qdf_nbuf_next(sctx->currnbuf);
                }
                sctx->unconsumed_cnt_curr = qdf_nbuf_len(sctx->currnbuf);
                sctx->currnbuf_ptr = qdf_nbuf_data(sctx->currnbuf);
            }
        } else {
           sctx->unconsumed_cnt_curr -= jmp_remaining;
           sctx->unconsumed_cnt_total -= jmp_remaining;
           sctx->currnbuf_ptr += jmp_remaining;
           jmp_remaining = 0;
        }
    }

    if (sctx->currnbuf == NULL) {
        /* Unexpected condition */
        rawsim_err("Ran out of fragments while fast forwarding to offset."
                   "Invalidating context.\n"
                   "offset=%u num bytes=%u unconsumed total count=%u",
                   soffset, numbytes, sctx->unconsumed_cnt_total);
        sctx->is_valid = 0;
        return -1;
    }

    cpy_remaining = numbytes;

    while (cpy_remaining && sctx->currnbuf) {
        if (cpy_remaining >= sctx->unconsumed_cnt_curr) {
            if (dst) {
                qdf_mem_copy(dst + dstoffset,
                        sctx->currnbuf_ptr,
                        sctx->unconsumed_cnt_curr);
            }
            cpy_remaining -= sctx->unconsumed_cnt_curr;
            sctx->unconsumed_cnt_total -= sctx->unconsumed_cnt_curr;
            dstoffset += sctx->unconsumed_cnt_curr;
            sctx->currnbuf = sctx->nextnbuf;
            if (sctx->currnbuf) {
                if (qdf_nbuf_is_rx_chfrag_end(sctx->currnbuf)) {
                    sctx->nextnbuf = NULL;
                } else {
                    sctx->nextnbuf = qdf_nbuf_next(sctx->currnbuf);
                }
                sctx->unconsumed_cnt_curr = qdf_nbuf_len(sctx->currnbuf);
                sctx->currnbuf_ptr = qdf_nbuf_data(sctx->currnbuf);
            }
        } else {
            if (dst) {
                qdf_mem_copy(dst + dstoffset,
                        sctx->currnbuf_ptr,
                        cpy_remaining);
            }

           sctx->unconsumed_cnt_curr -= cpy_remaining;
           sctx->unconsumed_cnt_total -= cpy_remaining;
           sctx->currnbuf_ptr += cpy_remaining;
           cpy_remaining = 0;
        }
    }

    if (sctx->currnbuf == NULL) {
        /* Unexpected condition */
        rawsim_err("Ran out of fragments while copying bytes."
                   "Invalidating context.\n"
                   "offset=%u num bytes=%u unconsumed total count=%u",
                   soffset, numbytes, sctx->unconsumed_cnt_total);
        sctx->is_valid = 0;
        return -1;
    }

    return 0;
}

/* End of fragment stream processing functionality */


/**
 * @brief Decap an 802.11 MPDU containing an A-MSDU, into Ethernet II frames.
 * @details
 *   This function generates a linked list of nbufs, each nbuf containing an
 *   Ethernet II frame bearing the payload from an MSDU.
 *
 *   If the MPDU is fragmented: The original linked list passed to the function
 *   is modified to link the above nbufs. The same head nbuf as passed in the
 *   input linked list is used as-is after decapping unwanted fields from
 *   802.11. However, the remaining nbufs if any will be newly allocated.  This
 *   is because the emphasis of the simulation is clean testability rather than
 *   performance. For similar reasons, certain minor potential optimizations
 *   have not been taken up in order to facilitate testability.
 *
 *   If the MPDU is not fragmented: Similar to above. It is the responsibility
 *   of the caller to link back the newly generated linked list into the main
 *   linked list containing the rest of the non-AMSDU nbufs. The caller should
 *   pass the single nbuf using deliver_list_head.  *deliver_list_tail can be
 *   kept NULL: deliver_list_tail will be used to point to the last Ethernet II
 *   frame at the end of the operation.
 *
 *   The function does not validate the DA and SA.
 *
 *   Workaround: In case of an error in parsing the MSDUs, the function returns
 *   the MSDUs parsed successfully so far. This is to be able to interwork with
 *   certain implementations which might send a garbage MSDU (mostly) in the
 *   end, and with valid FCS. The policy we adopt in this case is to treat each
 *   MSDU as a distinct entity and not penalize other MSDUs in case of parsing
 *   failures. It is up to higher layers to further analyze the MSDUs. A
 *   statistic is recorded to track this. Currently, the function doesn't extend
 *   the same handling to trailer parsing failures, assuming all MSDUs have been
 *   parsed successfully. Though it could be argued that the above relaxation
 *   might as well be extended here, we should avoid extending the scope of
 *   workarounds where not supported by real world requirements.
 *
 *   Assumptions:
 *   - the caller has verified that the first nbuf corresponds to the start of a
 *     raw MPDU containing an A-MSDU sequence.
 *   - all the nbufs in the list correspond to that MPDU.
 *
 *   NB: HTC not considered, since TxBF isn't involved.
 *
 * @param pdev - The data physical device receiving the data
 *      (for accessing the OS device for nbuf allocation).
 * @param vdev - The virtual device receiving the data.
 * @param deliver_list_head - If fragmentation is used: pointer to the head of
 *      the linked list containing the MPDU fragments. If fragmentation is not
 *      used: Pointer to the single nbuf containing the MPDU.
 * @param deliver_list_tail - If fragmentation is used: pointer to the tail of
 *       the linked list containing the MPDU fragments. Upon success, it will be
 *       modified to link last decapped Ethernet II frame bearing nbuf. If
 *       fragmentation is not used: pointer to location where last decapped
 *       Ethernet II bearing nbuf should be linked upon success.
 * @param total_mpdu_len - Total MPDU length.
 * @param peer_mac - mac address of the peer which has sent the frames.
 * @return Integer status value.
 *      0  -> Success
 *      1  -> Partial success (see description of workaround in details)
 *      -1 -> Failure
 */
static int
decap_dot11withamsdu_to_8023(rawsim_ctxt ctxt,
                             qdf_nbuf_t *deliver_list_head,
                             qdf_nbuf_t *deliver_list_tail,
                             u_int32_t total_mpdu_len,
                             uint8_t *peer_mac,
                             uint32_t sec_type,
                             uint32_t auth_type,
                             bool print)
{
    struct ieee80211_qosframe wh;
    uint8_t sec_idx;
    uint32_t hdrsize=0, trailersize = 4; /* Account for FCS */
    uint16_t msdulen = 0;

    qdf_nbuf_t headsrcnbuf, dstnbuf, nbuf, next;
    raw_rx_fragstream_ctx sctx;
    struct ether_header *src_eth_hdr, *dst_eth_hdr;
    uint8_t is_4addr = 0;
    qdf_nbuf_t deliver_list_head_new = NULL;
    qdf_nbuf_t deliver_list_tail_new = NULL;
    u_int32_t preconsumed_bytes = 0;
    u_int8_t msdu_padding = 0;
    u_int32_t first_ethpktsize = 0;
    u_int8_t is_frag = 0;
    u_int32_t unconsumed_cnt = 0;
    u_int32_t unconsumed_cnt_nonfrag = 0;
    u_int32_t total_msdulen = 0;
    u_int32_t adj_total_mpdu_len = 0;
    u_int8_t *headsrcnbufptr = NULL;
    int err;
    int parsing_error = 0;

    if (ctxt->rx_decap_type == pkt_type_native_wifi) {
        trailersize = 0; /* No FCS for Native WIFI */
    }

    if ((deliver_list_head == NULL) || (*deliver_list_head == NULL)) {
        rawsim_err("List head/pointer to list head is NULL");
        return -1;
    }

    if (deliver_list_tail == NULL) {
        rawsim_err("Pointer to list tail is NULL");
        return -1;
    }

    is_frag = qdf_nbuf_is_rx_chfrag_start(*deliver_list_head);

    if (is_frag && (*deliver_list_tail == NULL)) {
        rawsim_err("NULL list tail passed. List tail required since fragments are "
                   "present");
        return -1;
    }

    headsrcnbuf = *deliver_list_head;

    qdf_mem_set(&wh, sizeof(wh), 0);
    qdf_mem_copy(&wh, qdf_nbuf_data(headsrcnbuf), sizeof(wh));

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Rx wh header before decap ###");
        RAWSIM_PKT_HEXDUMP(&wh, sizeof(struct ieee80211_qosframe));
        rawsim_info("\n");
    }

    /* XXX: Potential optimization if required: Re-use these determinations from
     * check of whether the frame is an A-MSDU
     */
    is_4addr = ((wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                    IEEE80211_FC1_DIR_DSTODS) ? 1:0;

    hdrsize = sizeof(struct ieee80211_qosframe);

    if (is_4addr) {
        hdrsize += QDF_MAC_ADDR_SIZE;
    }

    /*
     * When order bit is set to 1 in frame control for QOS data frame.
     * MAC header carries additional 4 bytes corresponding to HT control
     * information. The dot112dot3 conversion logic has to take care of
     * this additional length in MAC header size.
     */
    if (wh.i_fc[1] & IEEE80211_FC1_ORDER) {
            hdrsize += 4;
    }

    if (wh.i_fc[1] & IEEE80211_FC1_WEP) {
        /* For encrypted frames offset header accordingly. Strip
         * any crypto trailers along with FCS */
        if(wh.i_addr1[0] & 0x01) {
            sec_idx = raw_sec_mcast;
        } else {
            sec_idx = raw_sec_ucast;
        }

        if (sec_type &
              ((1 << WLAN_CRYPTO_CIPHER_WAPI_SMS4) |
               (1 << WLAN_CRYPTO_CIPHER_WAPI_GCM4))) {
            static unsigned warn_once_in_1k = 1000;
            if(warn_once_in_1k == 0) {
               rawsim_err("WAPI Not supported in simulation - decap failed !!");
               warn_once_in_1k = 1000;
            }
            --warn_once_in_1k;
            return -1;
        }

        if (auth_type &
                 ((1 << WLAN_CRYPTO_AUTH_OPEN) |
                  (1 << WLAN_CRYPTO_AUTH_SHARED))) {
            hdrsize += 4;
            trailersize += 4;
        } else {
            hdrsize += 8; //TKIP or TKIP-NOMIC or AES-CCMP
            if (sec_type &  (1 << WLAN_CRYPTO_CIPHER_TKIP)) {
                trailersize += 12;
            } else { //AES-CCMP
                trailersize += 8;
            }
        }
    }

    /* Decap first nbuf so it contains just the first MSDU */

    /*
     * Move the data pointer to the beginning of the A-MSDU delimiter:
     * new-header = old-hdr + 802.11 hdrsize
     */
    qdf_nbuf_pull_head(headsrcnbuf, hdrsize);
    adj_total_mpdu_len = total_mpdu_len - hdrsize;
    unconsumed_cnt = adj_total_mpdu_len;

    /* Access A-MSDU delimiter, using an Ethernet struct for the purpose. */
    /* XXX: Check if we could use A-MSDU delimiter header instead */
    src_eth_hdr = (struct ether_header *)(qdf_nbuf_data(headsrcnbuf));
    msdulen = qdf_ntohs(src_eth_hdr->ether_type);

    if ((msdulen < sizeof(struct llc)) ||
        (msdulen > MAX_RAWSIM_80211_MSDU_LEN)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
        rawsim_err("Invalid MSDU length %hu", msdulen);
#endif
        ctxt->rxstats.num_rx_inval_len_msdu++;
        return -1;
    }

    total_msdulen = msdulen + sizeof(struct ether_header);

    if (unconsumed_cnt < (total_msdulen + trailersize)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
         rawsim_err("Error while parsing MPDU. Insufficient "
                    "bytes %u remaining. Expected at least %u",
                    unconsumed_cnt,
                    (total_msdulen + trailersize));
#endif
        ctxt->rxstats.num_rx_tooshort_mpdu++;
        return -1;
    }

    if ((unconsumed_cnt - total_msdulen) > trailersize) {
        /* This is not expected to be the last MSDU */
        msdu_padding = (msdulen + sizeof(struct ether_header)) & 0x03;
        msdu_padding = msdu_padding ? (4 - msdu_padding) : 0;
        total_msdulen += msdu_padding;

        if (unconsumed_cnt < (total_msdulen + trailersize)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
             rawsim_err("Error while parsing MPDU. Expecting %u MSDU padding "
                        "bytes but unable to parse MDPU given %u bytes "
                        "remaining in MPDU.",
                        msdu_padding,
                        unconsumed_cnt);
#endif
            ctxt->rxstats.num_rx_tooshort_mpdu++;
            return -1;
        }
    } else {
        msdu_padding = 0;
    }

    src_eth_hdr->ether_type =
        L_GET_LLC_ETHTYPE((u_int8_t*)src_eth_hdr +
                          sizeof(struct ether_header));

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Rx LLC header before decap ###");
        RAWSIM_PKT_HEXDUMP((src_eth_hdr + sizeof(struct ether_header)),
                           sizeof(struct llc));
        rawsim_info("\n");
    }

    /* Get rid of LLC */
    qdf_mem_move((u_int8_t*)src_eth_hdr + sizeof(struct llc),
                    src_eth_hdr,
                    sizeof(struct ether_header));
    qdf_nbuf_pull_head(headsrcnbuf, sizeof(struct llc));
    adj_total_mpdu_len -=  sizeof(struct llc);

    preconsumed_bytes = total_msdulen - sizeof(struct llc);
    unconsumed_cnt -= preconsumed_bytes;
    first_ethpktsize = preconsumed_bytes - msdu_padding;

    if (is_frag) {
        qdf_mem_zero(&sctx, sizeof(sctx));

        err = rx_fragstream_init(&sctx,
                                 *deliver_list_head,
                                 hdrsize,
                                 trailersize,
                                 adj_total_mpdu_len,
                                 preconsumed_bytes);

        if (err < 0) {
            goto err1;
        }
    } else {
        unconsumed_cnt_nonfrag = unconsumed_cnt;
        headsrcnbufptr = qdf_nbuf_data(headsrcnbuf) + preconsumed_bytes;
    }

    while (GET_UNCONSUMED_CNT(is_frag, &sctx, unconsumed_cnt_nonfrag) >
                trailersize)
    {
        if (is_frag) {
             err = rx_fragstream_peek(&sctx,
                                      2 * QDF_MAC_ADDR_SIZE,
                                      2,
                                      (u_int8_t*)&msdulen);

            if (err < 0) {
                parsing_error = 1;
                break;
            }

            msdulen = qdf_ntohs(msdulen);
        } else {
            src_eth_hdr = (struct ether_header *)(headsrcnbufptr);
            msdulen = qdf_ntohs(src_eth_hdr->ether_type);
        }

        if ((msdulen < sizeof(struct llc)) ||
            (msdulen > MAX_RAWSIM_80211_MSDU_LEN)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
            rawsim_err("Invalid MSDU length %hu", msdulen);
#endif
            ctxt->rxstats.num_rx_inval_len_msdu++;
            parsing_error = 1;
            break;
        }

        total_msdulen = msdulen + sizeof(struct ether_header);

        unconsumed_cnt = GET_UNCONSUMED_CNT(is_frag,
                                            &sctx,
                                            unconsumed_cnt_nonfrag);
        if (unconsumed_cnt < (total_msdulen + trailersize)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
            rawsim_err("Error while parsing MPDU. Insufficient "
                       "bytes %u remaining. Expected at least %u",
                       unconsumed_cnt,
                       (total_msdulen + trailersize));
#endif
            parsing_error = 1;
            ctxt->rxstats.num_rx_tooshort_mpdu++;
            break;
        }

        msdu_padding = 0;
        if ((unconsumed_cnt - total_msdulen) > trailersize) {
            /* This is not expected to be the last MSDU */
            msdu_padding = (msdulen + sizeof(struct ether_header)) & 0x03;
            total_msdulen += msdu_padding;

            if (unconsumed_cnt < (total_msdulen + trailersize)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
                rawsim_err("Error while parsing MPDU. Expecting %u MSDU padding "
                           "bytes but unable to parse MDPU given %u bytes "
                           "remaining in MPDU.",
                           msdu_padding,
                           unconsumed_cnt);
#endif
                parsing_error = 1;
                ctxt->rxstats.num_rx_tooshort_mpdu++;
                break;
            }
        }

        dstnbuf =
            qdf_nbuf_alloc(NULL,
                           msdulen + sizeof(struct ether_header),  /* size    */
                           0,                                      /* reserve */
                           4,                                      /* align   */
                           FALSE);                                 /* prio    */

        if (!dstnbuf) {
            rawsim_err("Unable to allocate nbuf");
            /* We treat this similar to a parsing error, so we can attempt to
             * deliver MSDUs successfully decapped so far
             */
            parsing_error = 1;
            break;
        }

        qdf_nbuf_set_pktlen(dstnbuf,
                msdulen + sizeof(struct ether_header) - sizeof(struct llc));

        dst_eth_hdr = (struct ether_header *)qdf_nbuf_data(dstnbuf);

        /* Copy addresses, populate ethter type field, and move to end of LLC */
        if (is_frag) {
            err = rx_fragstream_consume(&sctx,
                                        0,
                                        2 * QDF_MAC_ADDR_SIZE,
                                        (u_int8_t*)dst_eth_hdr);

            if (err < 0) {
                qdf_nbuf_free(dstnbuf);
                parsing_error = 1;
                break;
            }

            /* Populate the ether type field. This also has the effect of
             * skipping LLC
             */
            err = rx_fragstream_consume(&sctx,
                                        (L_ETH_ETHTYPE_SIZE +
                                         L_LLC_ETHTYPE_OFFSET),
                                        sizeof(dst_eth_hdr->ether_type),
                                        (u_int8_t*)&dst_eth_hdr->ether_type);

            if (err < 0) {
                qdf_nbuf_free(dstnbuf);
                parsing_error = 1;
                break;
            }

        } else {
            qdf_mem_copy((u_int8_t*)dst_eth_hdr,
                    headsrcnbufptr,
                    2 * QDF_MAC_ADDR_SIZE);

            /* Populate the ether type field. */
            dst_eth_hdr->ether_type =
                L_GET_LLC_ETHTYPE(headsrcnbufptr + sizeof(struct ether_header));

            /* Skip headers */
            headsrcnbufptr += (sizeof(struct ether_header) + sizeof(struct llc));
            unconsumed_cnt_nonfrag -=
                (sizeof(struct ether_header) + sizeof(struct llc));
        }

        /* Copy data */
        if (is_frag) {
            err = rx_fragstream_consume(&sctx,
                                        0,
                                        msdulen - sizeof(struct llc),
                                        (qdf_nbuf_data(dstnbuf) +
                                         sizeof(struct ether_header)));

            if (err < 0) {
                qdf_nbuf_free(dstnbuf);
                parsing_error = 1;
                break;
            }
        } else {
            qdf_mem_copy(qdf_nbuf_data(dstnbuf) + sizeof(struct ether_header),
                    headsrcnbufptr,
                    msdulen - sizeof(struct llc));

            headsrcnbufptr += (msdulen - sizeof(struct llc));
            unconsumed_cnt_nonfrag -= (msdulen - sizeof(struct llc));
        }

        if (msdu_padding) {
            /* Discard the padding */
            if (is_frag) {
                err = rx_fragstream_consume(&sctx,
                                            0,
                                            msdu_padding,
                                            NULL);

                if (err < 0) {
                    qdf_nbuf_free(dstnbuf);
                    parsing_error = 1;
                    break;
                }
            } else {
                headsrcnbufptr += msdu_padding;
                unconsumed_cnt_nonfrag -= msdu_padding;
            }
        }

        RAWSIM_TXRX_LIST_APPEND(deliver_list_head_new,
            deliver_list_tail_new,
            dstnbuf);
        qdf_nbuf_set_next(deliver_list_tail_new, NULL);
    }

    if (!parsing_error &&
        (GET_UNCONSUMED_CNT(is_frag,
                            &sctx,
                            unconsumed_cnt_nonfrag) != trailersize)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
       rawsim_err("Unexpected residue found at end of MPDU containing A-MSDU");
#endif
       ctxt->rxstats.num_rx_toolong_mpdu++;
       goto err2;
    }

    if (is_frag && (sctx.currnbuf == NULL)) {
#if RAWSIM_PRINT_TXRXLEN_ERR_CONDITION
       rawsim_err("Unable to find expected trailer/residue at end of MPDU "
                  "containing A-MSDU");
#endif
       ctxt->rxstats.num_rx_tooshort_mpdu++;
       goto err2;
    }

    qdf_nbuf_trim_tail(headsrcnbuf,
            qdf_nbuf_len(headsrcnbuf) - first_ethpktsize);

    if (is_frag) {
        /* Release expended fragments except the first one */
        qdf_nbuf_set_rx_chfrag_start(headsrcnbuf, 0);
        nbuf = qdf_nbuf_next(headsrcnbuf);
        while (nbuf && (nbuf != (*deliver_list_tail))) {
            next = qdf_nbuf_next(nbuf);
            qdf_nbuf_free(nbuf);
            nbuf = next;
        }

        if (nbuf) {
            qdf_nbuf_free(nbuf);
        }
    }

    if (!deliver_list_head_new) {
        RAWSIM_TXRX_LIST_APPEND(deliver_list_head_new,
                deliver_list_tail_new,
                headsrcnbuf);
        qdf_nbuf_set_next(deliver_list_tail_new, NULL);
    } else {
        qdf_nbuf_set_next(headsrcnbuf, deliver_list_head_new);
        deliver_list_head_new = headsrcnbuf;
    }

    *deliver_list_head = deliver_list_head_new;
    *deliver_list_tail = deliver_list_tail_new;

    if (parsing_error) {
        return 1;
    } else {
        return 0;
    }

err2:
    if (deliver_list_head_new) {
        nbuf = qdf_nbuf_next(deliver_list_head_new);
        while (nbuf) {
            next = qdf_nbuf_next(nbuf);
            qdf_nbuf_free(nbuf);
            nbuf = next;
        }
    }

err1:
    return -1;
}

/**
 * @brief Decap an 802.11 MPDU not containing an A-MSDU, into an Ethernet II
 *   frame.
 * @details
 *   This function decaps a single nbuf corresponding to an 802.11 MPDU not
 *   containing an A-MSDU, into a single Ethernet II frame in the same nbuf.
 *
 *   NB: HTC not considered, since TxBF isn't involved.
 *
 * @param mpdu - nbuf bearing the 802.11 MPDU.
 * @param peer_mac - mac address of the peer which has sent the frames.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int
decap_dot11_to_8023(qdf_nbuf_t mpdu,
                    uint8_t *peer_mac,
                    rawsim_ctxt ctxt,
                    uint32_t sec_type,
                    uint32_t auth_type,
                    bool print)
{
    struct ieee80211_qosframe_addr4 wh, *wh_ptr;
    uint8_t type,subtype,sec_idx;
    uint32_t hdrsize=0, trailersize = 4; //Account for FCS
    struct llc llchdr;
    struct ether_header *eth_hdr;
    uint8_t is_4addr = 0;

    if (ctxt->rx_decap_type == pkt_type_native_wifi) {
        trailersize = 0; /* No FCS for Native WIFI */
    }

    qdf_mem_set(&wh, sizeof(wh), 0);
    qdf_mem_copy(&wh, qdf_nbuf_data(mpdu), sizeof(struct ieee80211_frame));
    type = wh.i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh.i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    is_4addr = ((wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) ==
                    IEEE80211_FC1_DIR_DSTODS) ? 1:0;
    wh_ptr = (struct ieee80211_qosframe_addr4 *)qdf_nbuf_data(mpdu);

    if (subtype == IEEE80211_FC0_SUBTYPE_QOS) {
        hdrsize = sizeof(struct ieee80211_qosframe);
    } else {
        hdrsize = sizeof(struct ieee80211_frame);
    }

    if (is_4addr) {
        hdrsize += QDF_MAC_ADDR_SIZE;
        /* We don't need to bother about whether the frame is QoS, here.
           The QoS field occurs after the 4th address, and we don't access
           the field. */
        qdf_mem_copy(&wh.i_addr4[0], wh_ptr->i_addr4, QDF_MAC_ADDR_SIZE);
    }

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Rx wh header before decap ###");
        RAWSIM_PKT_HEXDUMP(&wh, sizeof(struct ieee80211_qosframe_addr4));
        rawsim_info("\n");
    }

    /*
     * When order bit is set to 1 in frame control for QOS data frame.
     * MAC header carries additional 4 bytes corresponding to HT control
     * information. The dot112dot3 conversion logic has to take care of
     * this additional length in MAC header size.
     */
    if ((wh.i_fc[1] & IEEE80211_FC1_ORDER) &&
        (subtype == IEEE80211_FC0_SUBTYPE_QOS)) {
            hdrsize += 4;
    }

    if (wh.i_fc[1] & IEEE80211_FC1_WEP) {

        /* For encrypted frames offset header accordingly. Strip
         * any crypto trailers along with FCS */

        if(wh.i_addr1[0] & 0x01) {
            sec_idx = raw_sec_mcast;
        } else {
            sec_idx = raw_sec_ucast;
        }

        if (sec_type &
                ((1 << WLAN_CRYPTO_CIPHER_WAPI_SMS4) |
                 (1 << WLAN_CRYPTO_CIPHER_WAPI_GCM4))) {
            static unsigned warn_once_in_1k = 1000;
            if(warn_once_in_1k == 0) {
                rawsim_err("WAPI Not supported in simulation - decap failed !!");
                warn_once_in_1k = 1000;
            }
            --warn_once_in_1k;
            return -1;
        }

        if (auth_type &
                ((1 << WLAN_CRYPTO_AUTH_OPEN) |
                 (1 << WLAN_CRYPTO_AUTH_SHARED))) {
            hdrsize += 4;
            trailersize += 4;
        } else {
            hdrsize += 8; //TKIP or TKIP-NOMIC or AES-CCMP
            if (sec_type &  (1 << WLAN_CRYPTO_CIPHER_TKIP)) {
                trailersize += 12;
            } else { //AES-CCMP
                trailersize += 8;
            }
        }
    }

    qdf_mem_copy(&llchdr, ((uint8_t *)qdf_nbuf_data(mpdu)) + hdrsize,
              sizeof(struct llc));

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Rx llc header before decap ###");
        RAWSIM_PKT_HEXDUMP(&llchdr, sizeof(struct llc));
        rawsim_info("\n");
    }

    /*
     * Now move the data pointer to the beginning of the MAC header :
     * new-header = old-hdr + (wifhdrsize + llchdrsize - ethhdrsize)
     */
    qdf_nbuf_pull_head(
        mpdu, (hdrsize + sizeof(struct llc) - sizeof(struct ether_header)));

    /* Strip out 802.11 FCS + trailers if any */
    qdf_nbuf_trim_tail(mpdu, trailersize);

    eth_hdr = (struct ether_header *)(qdf_nbuf_data(mpdu));
    switch (wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) {
        case IEEE80211_FC1_DIR_NODS:
            qdf_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr1, QDF_MAC_ADDR_SIZE);
            qdf_mem_copy(
                eth_hdr->ether_shost, wh.i_addr2, QDF_MAC_ADDR_SIZE);
            break;
        case IEEE80211_FC1_DIR_TODS:
            qdf_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr3, QDF_MAC_ADDR_SIZE);
            qdf_mem_copy(
                eth_hdr->ether_shost, wh.i_addr2, QDF_MAC_ADDR_SIZE);
            break;
        case IEEE80211_FC1_DIR_FROMDS:
            qdf_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr1, QDF_MAC_ADDR_SIZE);
            qdf_mem_copy(
                eth_hdr->ether_shost, wh.i_addr3, QDF_MAC_ADDR_SIZE);
            break;
        case IEEE80211_FC1_DIR_DSTODS:
            qdf_mem_copy(
                eth_hdr->ether_dhost, wh.i_addr3, QDF_MAC_ADDR_SIZE);
            qdf_mem_copy(
                eth_hdr->ether_shost, wh.i_addr4, QDF_MAC_ADDR_SIZE);
            break;
    }
    eth_hdr->ether_type = llchdr.llc_un.type_snap.ether_type;

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Rx eth header after decap ###");
        RAWSIM_PKT_HEXDUMP(eth_hdr, sizeof(struct ether_header));
        rawsim_info("\n");
    }
    return 0;
}

#if MESH_MODE_SUPPORT
int rawsim_add_mesh_meta_hdr(qdf_nbuf_t nbuf, rawsim_ctxt ctxt, bool print)
{
    struct mesh_params params = {0};
    int status = 0;

    if (!ctxt) {
        rawsim_err("No rsim ctxt found");
        return -1;
    }

    params.mhdr = ctxt->mhdr;
    params.mhdr_len = ctxt->mhdr_len;
    params.mdbg = ctxt->mdbg;

    status = add_mesh_meta_hdr(nbuf, &params);

    if (status)
        return -1;

    ctxt->mhdr = params.mhdr;

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Tx mesh meta header after encap ###");
        RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf), sizeof(struct meta_hdr_s));
        rawsim_info("\n");
    }
    return 0;
}
#endif

/**
 * @brief Encap an Ethernet II frame into an 802.11 MPDU
 * @details
 *   This function encaps a single nbuf corresponding to an Ethernet II frame
 *   into an 802.11 QoS MPDU frame in the same nbuf.
 *   The emphasis is on testability, hence certain potential optimizations have
 *   not been carried out.
 *
 * @param mpdu  - nbuf bearing the Ethernet II frame.
 * @param mode  - The operating mode.
 * @param bssid - The BSSID under which the MPDU is to be sent.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int encap_eth_to_dot11(qdf_nbuf_t nbuf,
                              enum ieee80211_opmode mode,
                              u_int8_t *bssid,
                              rawsim_ctxt ctxt,
                              struct rawsim_ast_entry ast_entry,
                              bool print)
{
    u_int8_t *datap;
    u_int16_t typeorlen;
    u_int32_t hdrsize;
    struct ether_header eth_hdr;
    struct llc *llcHdr;
    struct ieee80211_frame *wh;
    struct ieee80211_frame_addr4 *wh_4addr = NULL;
    u_int32_t addr4_frame = 0;
    u_int32_t send_clr_text = 0;
    u_int32_t noqos = 0;
#if MESH_MODE_SUPPORT
    u_int8_t mesh_vap_mode;
    struct ieee80211_qosframe *wh_tmp = NULL;
    u_int8_t tid = 0;
    u_int32_t dbg_mhdr = 0x000f0004;
    u_int16_t mhdr_flags = 0;

    if (!ctxt) {
        rawsim_err("decap fail: NULL raw sim ctxt");
        return -1;
    }
    mesh_vap_mode = ctxt->mesh_mode;
    dbg_mhdr = ctxt->mhdr ? ctxt->mhdr : dbg_mhdr;
    mhdr_flags = (dbg_mhdr >> MESH_DBG_FLAGS_OFFSET) & MESH_BYTE_MASK;
    if ((mhdr_flags & METAHDR_FLAG_NOENCRYPT)) {
        send_clr_text = 1;
    }
    if (mhdr_flags & METAHDR_FLAG_NOQOS) {
        noqos = 1;
    }

    if (ctxt->tx_encap_type == pkt_type_native_wifi) {
        noqos = 1;
    }
#endif

    if (!ctxt) {
        rawsim_err("decap fail: NULL raw sim ctxt");
        return -1;
    }

    qdf_assert_always(nbuf != NULL);

    if (qdf_nbuf_headroom(nbuf) <
        (sizeof(struct ieee80211_qosframe) +  sizeof(*llcHdr)))
    {
        rawsim_err("### Raw Mode simulation encap: Don't have enough "
                   "headroom");
        return -1;
    }

    datap = qdf_nbuf_data(nbuf);

    typeorlen = *(u_int16_t *)(datap + QDF_MAC_ADDR_SIZE * 2);

    /*
     * Save addresses to be inserted later. Both destination and source
     * addresses get copied in one operation.
     */
    qdf_mem_set(&eth_hdr, sizeof(eth_hdr), 0);
    qdf_mem_copy(&eth_hdr, datap, QDF_MAC_ADDR_SIZE * 2);

    qdf_nbuf_pull_head(nbuf, sizeof(eth_hdr));

    /*
     * Make room for LLC + SNAP headers
     */
    if (qdf_nbuf_push_head(nbuf, sizeof(*llcHdr)) == NULL) {
        rawsim_err("### Raw Mode simulation encap: Failed to push LLC header");
        return -1;
    }
    datap = qdf_nbuf_data(nbuf);

    llcHdr = (struct llc *)(datap);
    llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
    llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
    llcHdr->llc_un.type_snap.control     = LLC_UI;
    llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
    llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
    llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
    llcHdr->llc_un.type_snap.ether_type  = typeorlen;

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Tx LLC header after encap ###");
        RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf), sizeof(struct llc));
        rawsim_info("\n");
    }

    if (typeorlen == QDF_SWAP_U16(QDF_NBUF_TRAC_EAPOL_ETH_TYPE)) {
        send_clr_text = 1;
        if (ctxt->rawmodesim_debug_level) {
            rawsim_info("%s: eapol",__func__);
        }
    }

    if (ctxt->privacyEnabled && !send_clr_text)  {
        hdrsize = 8;
        if (qdf_nbuf_push_head(nbuf, hdrsize) == NULL) {
            rawsim_err("### Raw Mode simulation encap: No headroom for 80211 "
                       "IV header");
            return -1;
        }
        qdf_mem_set(qdf_nbuf_data(nbuf), hdrsize, 0);

        /* linearize before putting any data in tail */
        if (qdf_nbuf_is_nonlinear(nbuf)) {

            /* if unable to linearize, return */
            if (qdf_nbuf_linearize(nbuf) == -ENOMEM) {
                qdf_err("### skb not linearized");
                return -1;
            }

            nbuf = qdf_nbuf_unshare(nbuf);
            if (nbuf == NULL) {
                return -1;
            }
        }

        if (qdf_nbuf_put_tail(nbuf, hdrsize) == NULL) {
            rawsim_err("### Raw Mode simulation encap: No headroom for 80211 "
                       "MIC Tail");
            return -1;
        }
    }

#if MESH_MODE_SUPPORT
    if (mesh_vap_mode) {
        if (ast_entry.ast_found) {
            if (ctxt->rawmodesim_debug_level) {
                rawsim_info("ast %s\n",ether_sprintf(ast_entry.mac_addr));
            }
            if (!(IEEE80211_ADDR_EQ(eth_hdr.ether_dhost,ast_entry.mac_addr))) {
                addr4_frame = 1;
            }
        } else {
            if (!(IEEE80211_ADDR_EQ(eth_hdr.ether_shost,bssid))) {
                addr4_frame = 1;
            }
        }
        if (ctxt->rawmodesim_debug_level) {
            rawsim_info("dst %s ",ether_sprintf(eth_hdr.ether_dhost));
            rawsim_info("src %s ",ether_sprintf(eth_hdr.ether_shost));
            rawsim_info("bssid %s \n",ether_sprintf(bssid));
            rawsim_info("is 4addr %d\n",addr4_frame);
        }
    }
#endif

    /* Make room for 802.11 header */
    /* For now send only QoS frames in this simulation */
    if (!IEEE80211_IS_MULTICAST(eth_hdr.ether_dhost)) {

        /* Peregrine does not need IV padding for QoS frame */
        if (!noqos) {
            if (!addr4_frame) {
                hdrsize = sizeof(struct ieee80211_qosframe);
            } else {
                hdrsize = sizeof(struct ieee80211_qosframe_addr4);
            }
        } else {
            if (!addr4_frame) {
                hdrsize = sizeof(struct ieee80211_frame);
            } else {
                hdrsize = sizeof(struct ieee80211_frame_addr4);
            }
        }
        if (qdf_nbuf_push_head(nbuf, hdrsize) == NULL) {
            rawsim_err("### Raw Mode simulation encap: No headroom for 80211 "
                       "header");
            return -1;
        }
        qdf_mem_set(qdf_nbuf_data(nbuf), hdrsize, 0);
        wh = (struct ieee80211_frame *) qdf_nbuf_data(nbuf);
        if (addr4_frame) {
            wh_4addr = (struct ieee80211_frame_addr4 *) qdf_nbuf_data(nbuf);
        }
        if(!noqos) {
            wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS;
        } else {
            wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_DATA;
        }
#if MESH_MODE_SUPPORT
        wh_tmp = (struct ieee80211_qosframe *)wh;
        tid = (ctxt->mdbg >> 16) & 0x7;
        if(tid && !noqos){
            wh_tmp->i_qos[0] = tid & IEEE80211_QOS_TID;
        }
#endif
    } else {
        if (!addr4_frame) {
            hdrsize = sizeof(struct ieee80211_frame);
        } else {
            hdrsize = sizeof(struct ieee80211_frame_addr4);
        }
        if (qdf_nbuf_push_head(nbuf, hdrsize) == NULL) {
            rawsim_err("### Raw Mode simulation encap: No headroom for 80211 "
                       "header");
            return -1;
        }
        qdf_mem_set(qdf_nbuf_data(nbuf),hdrsize, 0);
        wh = (struct ieee80211_frame *) qdf_nbuf_data(nbuf);
        if (addr4_frame) {
            wh_4addr = (struct ieee80211_frame_addr4 *) qdf_nbuf_data(nbuf);
        }
        wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_DATA;
    }

    /* We don't currently support IBSS */
    qdf_assert_always(mode != IEEE80211_M_IBSS);

#if MESH_MODE_SUPPORT
    if (mesh_vap_mode) {
        if (!addr4_frame) {
            IEEE80211_ADDR_COPY(wh->i_addr1, eth_hdr.ether_dhost);
            IEEE80211_ADDR_COPY(wh->i_addr2, eth_hdr.ether_shost);
            IEEE80211_ADDR_COPY(wh->i_addr3, bssid);
        } else {
            if (!IEEE80211_IS_MULTICAST(eth_hdr.ether_dhost)) {
                if (ast_entry.ast_found) {
                    IEEE80211_ADDR_COPY(wh->i_addr1, ast_entry.mac_addr);
                } else {
                    IEEE80211_ADDR_COPY(wh->i_addr1, ctxt->bssid_mesh);
                }
            } else {
                IEEE80211_ADDR_COPY(wh->i_addr1, eth_hdr.ether_dhost);
            }
            IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_dhost);
            IEEE80211_ADDR_COPY(wh_4addr->i_addr4, eth_hdr.ether_shost);
            wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS | IEEE80211_FC1_DIR_TODS;
        }
    } else
#endif
    {
        if (mode == IEEE80211_M_STA) {
            IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr2, eth_hdr.ether_shost);
            IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_dhost);
            wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
        } else if (mode == IEEE80211_M_HOSTAP) {
            IEEE80211_ADDR_COPY(wh->i_addr1, eth_hdr.ether_dhost);
            IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
            IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_shost);
            wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
        }
    }

    wh->i_fc[0] |= (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA);
    if (ctxt->privacyEnabled && !send_clr_text) {
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("###  Tx wireless header after encap ###");
        RAWSIM_PKT_HEXDUMP(wh, sizeof(struct ieee80211_frame));
        rawsim_info("\n");
    }

    /* We let the callers maintain encap stats in case they'd like to account for
     * additional factors.
     */
#if MESH_MODE_SUPPORT
    if (mesh_vap_mode) {
        return rawsim_add_mesh_meta_hdr(nbuf, ctxt, print);
    }
#endif

    return 0;
}

/**
 * @brief Encap 802.11 AMSDU lead network buffer
 * @details
 *   This function encaps the lead network buffer in a chain of fragments
 *   into the header and initial MSDU in an 802.11 AMSDU bearing MPDU.
 *   The emphasis is on testability, hence certain potential optimizations have
 *   not been carried out.
 *
 * @param mpdu  - nbuf bearing the first Ethernet II frame.
 * @param mode  - The operating mode.
 * @param bssid - The BSSID under which the MPDU is to be sent.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int encap_eth_to_dot11_amsdu(rawsim_ctxt ctxt,
                                    qdf_nbuf_t nbuf,
                                    enum ieee80211_opmode mode,
                                    u_int8_t *bssid,
                                    bool print)
{
    u_int8_t *datap;
    u_int32_t hdrsize;
    struct ether_header eth_hdr = {{0}};
    struct ieee80211_qosframe *wh;

    qdf_assert_always(nbuf != NULL);

    datap = qdf_nbuf_data(nbuf);

    /*
     * Save addresses to be inserted later. Both destination and source
     * addresses get copied in one operation.
     */
    qdf_mem_copy(&eth_hdr, datap, QDF_MAC_ADDR_SIZE * 2);


    /* Make room for 802.11 header */
    /* For now send only QoS frames in this simulation */

    /* Peregrine does not need IV padding for QoS frame */
    hdrsize = sizeof(struct ieee80211_qosframe);
    if (qdf_nbuf_push_head(nbuf, hdrsize) == NULL) {
        rawsim_err("### Raw Mode simulation encap: No headroom for 80211 "
                   "header");
        return -1;
    }
    qdf_mem_set(qdf_nbuf_data(nbuf),hdrsize, 0);
    wh = (struct ieee80211_qosframe *) qdf_nbuf_data(nbuf);
    wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS;
    wh->i_qos[0] |= (1 << IEEE80211_QOS_AMSDU_S) & IEEE80211_QOS_AMSDU;

   /* We don't currently support IBSS */
   qdf_assert_always(mode != IEEE80211_M_IBSS);

    if (mode == IEEE80211_M_STA) {
        IEEE80211_ADDR_COPY(wh->i_addr1, bssid);
        IEEE80211_ADDR_COPY(wh->i_addr2, eth_hdr.ether_shost);
        IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_dhost);
        wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
    } else if (mode == IEEE80211_M_HOSTAP) {
        IEEE80211_ADDR_COPY(wh->i_addr1, eth_hdr.ether_dhost);
        IEEE80211_ADDR_COPY(wh->i_addr2, bssid);
        IEEE80211_ADDR_COPY(wh->i_addr3, eth_hdr.ether_shost);
        wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
    }

    wh->i_fc[0] |= (IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA);

    /* We let the callers maintain encap stats in case they'd like to account for
     * additional factors.
     */

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### Tx wireless header after encap ###");
        RAWSIM_PKT_HEXDUMP(wh, sizeof(struct ieee80211_qosframe));
        rawsim_info("\n");
    }
    return 0;
}

/**
 * @brief Encap an Ethernet II frame into an 802.11 AMSDU Subframe
 * @details
 *   This function forms a single AMSDU Subframe
 *   corresponding to an Ethernet II frame
 *
 * @param mpdu  - nbuf bearing the Ethernet II frame.
 * @return Integer status value.
 *      0  -> Success
 *      -1 -> Failure
 */
static int form_amsdu_packet(rawsim_ctxt ctxt, qdf_nbuf_t nbuf, bool print)
{
    u_int8_t *datap;
    u_int16_t typeorlen, length;
    u_int32_t padding;
    struct ether_header eth_hdr = {{0}};
    struct llc *llcHdr;

    qdf_assert_always(nbuf != NULL);

    if (qdf_nbuf_headroom(nbuf) <
         (sizeof(struct ieee80211_qosframe) +  sizeof(*llcHdr)))
    {
        rawsim_err("### Raw Mode simulation encap: Don't have enough "
                   "headroom");
        return -1;
    }
    datap = qdf_nbuf_data(nbuf);

    typeorlen = *(u_int16_t *)(datap + QDF_MAC_ADDR_SIZE * 2);

    /*
     * Save addresses to be inserted later. Both destination and source
     * addresses get copied in one operation.
     */
    qdf_mem_copy(&eth_hdr, datap, QDF_MAC_ADDR_SIZE * 2);

    /*
     * Make room for LLC + SNAP headers
     */
    if (qdf_nbuf_push_head(nbuf, sizeof(*llcHdr)) == NULL) {
        rawsim_err("### Raw Mode simulation encap: Failed to push LLC "
                   "header");
        return -1;
    }

    length = qdf_nbuf_len(nbuf);
    eth_hdr.ether_type = htons(length - 14);

    datap = qdf_nbuf_data(nbuf);
    qdf_mem_copy(datap, &eth_hdr, sizeof(eth_hdr));
    datap = qdf_nbuf_data(nbuf) + sizeof(eth_hdr);

    llcHdr = (struct llc *)(datap);
    llcHdr->llc_dsap                     = LLC_SNAP_LSAP;
    llcHdr->llc_ssap                     = LLC_SNAP_LSAP;
    llcHdr->llc_un.type_snap.control     = LLC_UI;
    llcHdr->llc_un.type_snap.org_code[0] = RFC1042_SNAP_ORGCODE_0;
    llcHdr->llc_un.type_snap.org_code[1] = RFC1042_SNAP_ORGCODE_1;
    llcHdr->llc_un.type_snap.org_code[2] = RFC1042_SNAP_ORGCODE_2;
    llcHdr->llc_un.type_snap.ether_type  = typeorlen;

    if (print && (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP)) {
        rawsim_info("### TX LLC header of fragment after encap ###");
        RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf), sizeof(struct llc));
        rawsim_info("\n");
    }

    /* Padding is not required for last msdu */
    if (nbuf->next) {
        padding = length & 0x03;
        padding = padding ? (4 - padding) : 0;
        datap = qdf_nbuf_data(nbuf);
        qdf_nbuf_put_tail(nbuf, padding);
        qdf_mem_set(datap + length , padding, 0);
    }

    return 0;
}

static int check_ip_pkt(qdf_nbuf_t nbuf)
{
    u_int16_t typeorlen;

    qdf_assert_always(nbuf != NULL);

    typeorlen = *((u_int16_t *)(qdf_nbuf_data(nbuf) + QDF_MAC_ADDR_SIZE * 2));

    if (ntohs(typeorlen) == ETHERTYPE_IP)
        return 1;
    else
        return 0;
}

static int check_ip_more_frag(qdf_nbuf_t nbuf)
{
    struct iphdr *ip = NULL;

    qdf_assert_always(nbuf != NULL);

    ip = (struct iphdr*)(qdf_nbuf_data(nbuf) + sizeof(struct ether_header));
    if (ip->frag_off & htons(IP_MF))
        return 1;
    else
        return 0;
}

static int check_multicast(qdf_nbuf_t nbuf)
{
    struct ether_header *eth_hdr;

    qdf_assert_always(nbuf != NULL);

    eth_hdr = (struct ether_header *)qdf_nbuf_data(nbuf);

    if (IEEE80211_IS_MULTICAST(eth_hdr->ether_dhost))
        return 1;
    else
        return 0;
}

static void
txstats_inc_mpdu_noamsdu(rawsim_ctxt ctxt)
{
    if (!ctxt) {
        rawsim_err("NULL rawsim_ctxt");
        return;
    }
    ctxt->txstats.num_tx_mpdu_noamsdu++;
}

static void
txstats_inc_mpdu_withamsdu(rawsim_ctxt ctxt)
{
    if (!ctxt) {
        rawsim_err("NULL rawsim_ctxt");
        return;
    }
    ctxt->txstats.num_tx_mpdu_withamsdu++;
}


/* APIs */

static qdf_nbuf_t convert_frag_list_to_nbuf_chain(qdf_nbuf_t nbuf,
                                                  rawsim_ctxt ctxt)
{
    qdf_nbuf_t tmp_nbuf = nbuf;
    if (ctxt->rawmodesim_debug_level) {
        rawsim_info("nbuf->next: %pK", nbuf->next);
    }

    tmp_nbuf->next = skb_shinfo(tmp_nbuf)->frag_list;
    skb_shinfo(tmp_nbuf)->frag_list = NULL;
    tmp_nbuf->len = tmp_nbuf->len - tmp_nbuf->data_len;
    tmp_nbuf->data_len = 0;

    while (tmp_nbuf->next) {
        if (ctxt->rawmodesim_debug_level) {
            rawsim_info("tmp_nbuf: %pK, tmp_nbuf->next: %pK, tmp_nbuf->len: %d, is_first: %d, is_cont: %d, is_end: %d",
                        tmp_nbuf, tmp_nbuf->next, tmp_nbuf->len,
                        qdf_nbuf_is_rx_chfrag_start(tmp_nbuf),
                        qdf_nbuf_is_rx_chfrag_start(tmp_nbuf),
                        qdf_nbuf_is_rx_chfrag_end(tmp_nbuf));
        }

        tmp_nbuf = tmp_nbuf->next;
     }

     return tmp_nbuf;
}

void
rx_decap(rawsim_ctxt ctxt,
         qdf_nbuf_t *pdeliver_list_head,
         qdf_nbuf_t *pdeliver_list_tail,
         uint8_t *peer_mac,
         uint32_t sec_type,
         uint32_t auth_type)
{
   int is_amsdu = 0;
   u_int8_t is_chfrag_start = 0;
   u_int8_t is_chfrag_end = 0;
   int ret;
   qdf_nbuf_t nbuf = NULL;
   qdf_nbuf_t deliver_sublist_head = NULL;
   qdf_nbuf_t deliver_sublist_tail = NULL;
   u_int32_t total_mpdu_len = 0;
   qdf_nbuf_t tmpskb = NULL;
   int index = 0;
   qdf_nbuf_t frag_list_tail = NULL;
   qdf_nbuf_t  prev = NULL;
   qdf_nbuf_t  next = NULL;

   if (ctxt == NULL) {
        rawsim_err("No rsim ctxt");
        return;
   }

   /* return if simuation is not enabled */
   if ( !ctxt->rawmode_pkt_sim ) {
       return;
   }

   if ((pdeliver_list_head == NULL) || (*pdeliver_list_head == NULL)) {
        rawsim_err("List head/pointer to list head is NULL");
        return;
   }

   if ((pdeliver_list_tail == NULL) || (*pdeliver_list_tail == NULL)) {
        rawsim_err("List tail/pointer to list tail is NULL");
        return;
   }

   nbuf = *pdeliver_list_head;

   while (nbuf) {
       if (qdf_nbuf_is_rx_chfrag_start(nbuf) && qdf_nbuf_is_rx_chfrag_end(nbuf)) {
           qdf_nbuf_set_rx_chfrag_start(nbuf, 0);
           qdf_nbuf_set_rx_chfrag_end(nbuf, 0);
       }

       if (qdf_nbuf_get_ext_list(nbuf)) {
           next = nbuf->next;
           frag_list_tail = convert_frag_list_to_nbuf_chain(nbuf, ctxt);
           frag_list_tail->next = next;
       }


       is_amsdu = is_80211amsdu(nbuf);
       is_chfrag_start = qdf_nbuf_is_rx_chfrag_start(nbuf);

       /* Note: Preferably do not change order of below if-else checks.
        * They are in order of descending probability, except for the
        * initial error check.
        *
        * Note: Due to subtle differences in the actions to be taken for
        * each of the below scenarios, we do not derive common routines
        * beyond a certain point.
        */
       if (is_amsdu < 0) {
           /* Discard the nbuf(s) */
           next = qdf_nbuf_next(nbuf);

           RAWSIM_TXRX_NODE_DELETE(*pdeliver_list_head,
                   *pdeliver_list_tail,
                   prev,
                   nbuf);

           nbuf = next;

           if (is_chfrag_start && nbuf) {
               while(nbuf) {
                    next = qdf_nbuf_next(nbuf);
                    is_chfrag_end = qdf_nbuf_is_rx_chfrag_end(nbuf);
                    RAWSIM_TXRX_NODE_DELETE(*pdeliver_list_head,
                           *pdeliver_list_tail,
                           prev,
                           nbuf);

                    nbuf = next;

                    if (is_chfrag_end) {
                        break;
                    }
               }
           }
       } else if (!is_amsdu && !is_chfrag_start) {
           bool allow_print = false;

           next = qdf_nbuf_next(nbuf);

           /* Hexdump of packets before decap */
           if (ctxt->rawmodesim_debug_level) {
               if (!(ctxt->fixed_frm_cnt_flag & FIXED_NUM_DECAP_DUMP)) {
                   allow_print = true;
               } else if(qdf_atomic_inc_not_zero(&ctxt->num_decap_frames)) {
                   allow_print = true;
               }

               if (allow_print &&
                   (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP)) {
                   rawsim_info("Rx 802.11 packet hexdump before decap");
                   RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf), qdf_nbuf_len(nbuf));
                   rawsim_info("\n");
               }
           }

           /* decapsulation */
           ret = decap_dot11_to_8023(nbuf, peer_mac, ctxt,
                                     sec_type, auth_type, allow_print);

           /* Hexdump after decap */
           if (allow_print &&
               (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP)) {
                rawsim_info("Rx Ethernet II packet hexdump after decap");
                RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf), qdf_nbuf_len(nbuf));
                rawsim_info("\n");
           }

           if (ret < 0) {
               RAWSIM_TXRX_NODE_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       nbuf);
           } else {
               ctxt->rxstats.num_rx_mpdu_noamsdu++;
               prev = nbuf;
           }

           nbuf = next;
       } else if (is_amsdu && is_chfrag_start) {
           bool allow_print = false;

           deliver_sublist_head = nbuf;
           total_mpdu_len = 0;

           while(nbuf && !qdf_nbuf_is_rx_chfrag_end(nbuf)) {
               total_mpdu_len += qdf_nbuf_len(nbuf);
               nbuf = qdf_nbuf_next(nbuf);
           }

           if (!nbuf) {
               rawsim_info(
                   "Unterminated fragment chain received!! Discarding.");

               deliver_sublist_tail = *pdeliver_list_tail;
               if (deliver_sublist_tail) {
                   RAWSIM_TXRX_SUBLIST_DELETE(*pdeliver_list_head,
                           *pdeliver_list_tail,
                           prev,
                           deliver_sublist_head,
                           deliver_sublist_tail);
               }
               break;
           }

           total_mpdu_len += qdf_nbuf_len(nbuf);
           deliver_sublist_tail = nbuf;
           next = qdf_nbuf_next(deliver_sublist_tail);

           /* Hexdump before decap */
           if (ctxt->rawmodesim_debug_level) {
               if (!(ctxt->fixed_frm_cnt_flag & FIXED_NUM_DECAP_DUMP)) {
                   allow_print = true;
               } else if (qdf_atomic_inc_not_zero(&ctxt->num_decap_frames)) {
                   allow_print = true;
               }

               if (allow_print &&
                   (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP)) {
                   rawsim_info("Rx 802.11 packet hexdump before decap");
                   for (index = 0, tmpskb = deliver_sublist_head;
                           tmpskb != deliver_sublist_tail;
                           tmpskb = qdf_nbuf_next(tmpskb)) {
                        rawsim_info("Fragment No : %d", ++index);
                        RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(tmpskb),
                                           qdf_nbuf_len(tmpskb));
                        rawsim_info("\n");
                   }
               }
           }

           /* decapsulation */
           ret = decap_dot11withamsdu_to_8023(ctxt,
                       &deliver_sublist_head,
                       &deliver_sublist_tail,
                       total_mpdu_len,
                       peer_mac,
                       sec_type,
                       auth_type,
                       allow_print);

           if (ret < 0) {
               RAWSIM_TXRX_SUBLIST_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       deliver_sublist_head,
                       deliver_sublist_tail);
           } else {
               /* hexdump after decap */
               if (allow_print) {
                   if (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP) {
                       rawsim_info("Rx Ethernet II packet hexdump after decap");
                       for (index = 0, tmpskb = deliver_sublist_head;
                               tmpskb != deliver_sublist_tail;
                               tmpskb = qdf_nbuf_next(tmpskb)) {
                            rawsim_info("Fragment No : %d\n", ++index);
                            RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(tmpskb),
                                               qdf_nbuf_len(tmpskb));
                            rawsim_info("\n");
                       }
                   } else if (ctxt->rawmodesim_debug_level ==
                                    HEADERS_ONLY_DUMP) {
                         rawsim_info("### Rx ethernat II packet's first frag eth hdr after decap ###");
                         RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(deliver_sublist_head),
                                            sizeof(struct ether_header));
                         rawsim_info("\n");
                   }
               }

               /* Stitch new nbufs back into main list */
               prev = deliver_sublist_tail;
               qdf_nbuf_set_next(deliver_sublist_tail, next);
               if (nbuf == *pdeliver_list_tail) {
                   *pdeliver_list_tail = deliver_sublist_tail;
               }

               ctxt->rxstats.num_rx_largempdu_withamsdu++;
           }

           nbuf = next;
       } else if (is_amsdu && !is_chfrag_start) {
           bool allow_print = false;

           next = qdf_nbuf_next(nbuf);
           /* This will be populated by decap_dot11withamsdu_to_8023() */
           deliver_sublist_tail = NULL;

           /* Hexdump before decap */
           if (ctxt->rawmodesim_debug_level) {
               if (!(ctxt->fixed_frm_cnt_flag & FIXED_NUM_DECAP_DUMP)) {
                   allow_print = true;
               } else if(qdf_atomic_inc_not_zero(&ctxt->num_decap_frames)) {
                   allow_print = true;
               }

               if (allow_print &&
                   (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP)) {
                   rawsim_info("Rx 802.11 packet hexdump before decap");
                   RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf), qdf_nbuf_len(nbuf));
                   rawsim_info("\n");
               }
           }

           /* decapsulation */
           ret = decap_dot11withamsdu_to_8023(ctxt,
                       &nbuf,
                       &deliver_sublist_tail,
                       qdf_nbuf_len(nbuf),
                       peer_mac,
                       sec_type,
                       auth_type,
                       allow_print);

           if (ret < 0) {
               RAWSIM_TXRX_NODE_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       nbuf);
           } else {
               /* Hexdump after decap */
               if (allow_print) {
                   if (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP) {
                       rawsim_info("Rx Ethernet II packet hexdump after decap");
                       for (index = 0, tmpskb = nbuf;
                               tmpskb != deliver_sublist_tail;
                               tmpskb = qdf_nbuf_next(tmpskb)) {
                            rawsim_info("Fragment No : %d\n", ++index);
                            RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(tmpskb),
                                               qdf_nbuf_len(tmpskb));
                            rawsim_info("\n");
                       }
                   } else if (ctxt->rawmodesim_debug_level ==
                                               HEADERS_ONLY_DUMP) {
                       qdf_nofl_print("### eth header of amsdu's 1st fragment");
                       RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(nbuf),
                                          sizeof(struct ether_header));
                       rawsim_info("\n");
                   }
               }

               /* Stitch new nbufs back into main list */
               prev = deliver_sublist_tail;
               qdf_nbuf_set_next(deliver_sublist_tail, next);
               if (nbuf == *pdeliver_list_tail) {
                   *pdeliver_list_tail = deliver_sublist_tail;
               }

               ctxt->rxstats.num_rx_smallmpdu_withamsdu++;
           }

           nbuf = next;
       } else {
           /* !is_amsdu && is_chfrag_start */
           rawsim_info(
               "Fragmented MPDU without A-MSDU not currently handled!!");

           ctxt->rxstats.num_rx_chainedmpdu_noamsdu++;

           /* Discard the entire chain */
           while(nbuf) {
               next = qdf_nbuf_next(nbuf);
               is_chfrag_end = qdf_nbuf_is_rx_chfrag_end(nbuf);
               RAWSIM_TXRX_NODE_DELETE(*pdeliver_list_head,
                       *pdeliver_list_tail,
                       prev,
                       nbuf);
               nbuf = next;

               if (is_chfrag_end) {
                   break;
               }
           }
       }
   }
}

int
tx_encap(rawsim_ctxt ctxt,
         qdf_nbuf_t *pnbuf,
         u_int8_t *bssid,
         struct rawsim_ast_entry ast_entry)
{
    int is_ip_pkt = 0, i = 0;
    u_int8_t more_frag = 0;
    struct sk_buff *tmpnbuf, *nextchnbuf; /* next chained nbuf */
    bool allow_print = false;

    if (ctxt == NULL) {
         rawsim_err("rsim ctxt is NULL");
         return -1;
    }

    qdf_spin_lock_bh(&ctxt->tx_encap_lock);

    is_ip_pkt = check_ip_pkt(*pnbuf);

    /* For Non IP packet & Multicast packet, don't chain */
    if (ctxt->rawmodesim_txaggr && is_ip_pkt && !check_multicast(*pnbuf)) {
        more_frag = check_ip_more_frag(*pnbuf);

        if (!more_frag && (ctxt->rawsim_nbuf_tx_list_head == NULL)) {
            /* Hexdump before encap */
            if (ctxt->rawmodesim_debug_level) {
                if (!(ctxt->fixed_frm_cnt_flag & FIXED_NUM_ENCAP_DUMP)) {
                    allow_print = true;
                } else if (qdf_atomic_inc_not_zero(&ctxt->num_encap_frames)) {
                    allow_print = true;
                }

                if (allow_print) {
                    if (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP) {
                        rawsim_info("Tx Ethernet II type packet hexdump before encap\n");
                        RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(*pnbuf),
                                           qdf_nbuf_len(*pnbuf));
                        rawsim_info("\n");
                    } else if (ctxt->rawmodesim_debug_level ==
                                           HEADERS_ONLY_DUMP) {
                        rawsim_info("TX ETH Header hexdump before encap");
                        RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(*pnbuf),
                                           sizeof(struct ether_header));
                        rawsim_info("\n");

                        rawsim_info("TX IP hdr before encap");
                        RAWSIM_PKT_HEXDUMP((qdf_nbuf_data(*pnbuf) +
                                            sizeof(struct ether_header)),
                                           sizeof(struct iphdr));
                        rawsim_info("\n");
                    }
                }
            }

            /* SW encapsulation */
            if(encap_eth_to_dot11(*pnbuf, ctxt->opmode, bssid,
                                  ctxt, ast_entry, allow_print)) {
                qdf_spin_unlock_bh(&ctxt->tx_encap_lock);
                return -1;
            }

            txstats_inc_mpdu_noamsdu(ctxt);
            qdf_nbuf_set_next(*pnbuf, NULL);
        } else {
            /* Arrange for chained nbufs, each nbuf corresponding to an MSDU in
             * an A-MSDU.
             */
            qdf_nbuf_set_next(*pnbuf, NULL);
            RAWSIM_TXRX_LIST_APPEND(ctxt->rawsim_nbuf_tx_list_head,
                                    ctxt->rawsim_nbuf_tx_list_tail,
                                    *pnbuf);
            ctxt->rawsim_tx_frag_count++;

            if (!more_frag ||
                (ctxt->rawsim_tx_frag_count >= ctxt->rawmodesim_txaggr)) {
                *pnbuf = ctxt->rawsim_nbuf_tx_list_head;

                if (ctxt->rawmodesim_debug_level) {
                    if (!(ctxt->fixed_frm_cnt_flag & FIXED_NUM_ENCAP_DUMP)) {
                        allow_print = true;
                    } else if(qdf_atomic_inc_not_zero
                                    (&ctxt->num_encap_frames)) {
                        allow_print = true;
                    }
                }

                while (ctxt->rawsim_nbuf_tx_list_head) {
                    struct sk_buff *next =
                            qdf_nbuf_next(ctxt->rawsim_nbuf_tx_list_head);

                    /* hexdump before encap */
                    if (allow_print) {
                        if (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP) {
                            rawsim_info("Tx Ethernet II type packet hexdump before encap\n");
                            RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(ctxt->rawsim_nbuf_tx_list_head),
                                               qdf_nbuf_len(ctxt->rawsim_nbuf_tx_list_head));
                            rawsim_info("\n");
                        } else if (ctxt->rawmodesim_debug_level ==
                                                   HEADERS_ONLY_DUMP) {
                            rawsim_info("TX ETH Header hexdump before encap\n");
                            RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(ctxt->rawsim_nbuf_tx_list_head),
                                               sizeof(struct ether_header));
                            rawsim_info("\n");

                            rawsim_info("TX IP hdr before encap");
                            RAWSIM_PKT_HEXDUMP((qdf_nbuf_data(ctxt->rawsim_nbuf_tx_list_head) +
                                                sizeof(struct ether_header)),
                                               sizeof(struct iphdr));
                            rawsim_info("\n");
                        }
                    }

                    if (form_amsdu_packet(ctxt, ctxt->rawsim_nbuf_tx_list_head, allow_print)) {
                        qdf_spin_unlock_bh(&ctxt->tx_encap_lock);
                        return -1;
                    }
                    ctxt->rawsim_nbuf_tx_list_head = next;
                }
                /* Emptying out the temporary holding area */
                ctxt->rawsim_nbuf_tx_list_head = NULL;
                ctxt->rawsim_nbuf_tx_list_tail = NULL;
                ctxt->rawsim_tx_frag_count = 0;

                /* SW encapsulation */
                if(encap_eth_to_dot11_amsdu(ctxt, *pnbuf,
                                            ctxt->opmode,
                                            bssid, allow_print)) {
                   qdf_spin_unlock_bh(&ctxt->tx_encap_lock);
                   return -1;
                }

                txstats_inc_mpdu_withamsdu(ctxt);
            } else {
                qdf_spin_unlock_bh(&ctxt->tx_encap_lock);
                return 1;
            }
        }
    } else {
        /* Hexdump before encap */
        if (ctxt->rawmodesim_debug_level) {
            if (!(ctxt->fixed_frm_cnt_flag & FIXED_NUM_ENCAP_DUMP)) {
                allow_print = true;
            } else if (qdf_atomic_inc_not_zero(&ctxt->num_encap_frames)) {
                allow_print = true;
            }

            if (allow_print) {
                if (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP) {
                    rawsim_info("Tx Ethernet II type packet hexdump before encap\n");
                    RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(*pnbuf),
                                       qdf_nbuf_len(*pnbuf));
                    rawsim_info("\n");
                } else if (ctxt->rawmodesim_debug_level == HEADERS_ONLY_DUMP) {
                    rawsim_info("TX ETH Header hexdump before encap");
                    RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(*pnbuf),
                                       sizeof(struct ether_header));
                    rawsim_info("\n");

                    rawsim_info("TX IP hdr before encap");
                    RAWSIM_PKT_HEXDUMP((qdf_nbuf_data(*pnbuf) +
                                       sizeof(struct ether_header)),
                                       sizeof(struct iphdr));
                    rawsim_info("\n");
                }
            }
        }

        /* SW encapsulation */
        if(encap_eth_to_dot11(*pnbuf, ctxt->opmode,
                              bssid, ctxt, ast_entry,
                              allow_print)) {
           qdf_spin_unlock_bh(&ctxt->tx_encap_lock);
           return -1;
        }

        txstats_inc_mpdu_noamsdu(ctxt);
        qdf_nbuf_set_next(*pnbuf, NULL);
    }

    /* Hexdump after encap */
    if (allow_print && (ctxt->rawmodesim_debug_level == ENTIRE_PKT_DUMP)) {
        tmpnbuf = *pnbuf;
        rawsim_info("Tx 802.11 packet hexdump after encap");
        while (*pnbuf) {
            nextchnbuf = qdf_nbuf_next(*pnbuf);
            if (qdf_nbuf_next(tmpnbuf) != NULL) {
                rawsim_info("Fragment No. %d", ++i);
            }

            RAWSIM_PKT_HEXDUMP(qdf_nbuf_data(*pnbuf), qdf_nbuf_len(*pnbuf));
            *pnbuf = nextchnbuf;
        }
        *pnbuf = tmpnbuf;
    }
    qdf_spin_unlock_bh(&ctxt->tx_encap_lock);
    return 0;
}

void
print_stats(rawsim_ctxt ctxt)
{
   if (!ctxt) {
       rawsim_err("\nRawmode simulation context not registered");
       return;
   }

   rawsim_info("\nRaw Mode simulation module internal statistics:\n"
               "Note: These do not cover events outside the simulation \n"
               "module, such as higher layer failure to process successfully\n"
               "decapped MPDUs, etc. \n");

   rawsim_info("Rx side:");
   rawsim_info("--------\n");

   rawsim_info("Decap successes:");
   rawsim_info("Number of non-AMSDU bearing MPDUs decapped = %llu",
               ctxt->rxstats.num_rx_mpdu_noamsdu);
   rawsim_info("Number of A-MSDU bearing MPDUs (fitting within single nbuf)"
               "decapped = %llu",
               ctxt->rxstats.num_rx_smallmpdu_withamsdu);
   rawsim_info("Number of A-MSDU bearing MPDUs (requiring multiple nbufs) "
               "decapped = %llu",
               ctxt->rxstats.num_rx_largempdu_withamsdu);

   rawsim_info("\nDecap errors");
   rawsim_info("Number of MSDUs (contained in A-MSDU) with invalid length "
               "field = %llu",
               ctxt->rxstats.num_rx_inval_len_msdu);
   rawsim_info("Number of A-MSDU bearing MPDUs which are shorter than expected "
               "from parsing A-MSDU fields = %llu",
               ctxt->rxstats.num_rx_tooshort_mpdu);
   rawsim_info("Number of A-MSDU bearing MPDUs received which are longer than "
               "expected from parsing A-MSDU fields = %llu",
               ctxt->rxstats.num_rx_toolong_mpdu);
   rawsim_info("Number of non-AMSDU bearing MPDUs (requiring multiple nbufs) "
               "seen (unhandled and discarded) = %llu",
               ctxt->rxstats.num_rx_chainedmpdu_noamsdu);

   rawsim_info("\nTx side:");
   rawsim_info("--------\n");

   rawsim_info("Number of non-AMSDU bearing MPDUs encapped = %llu",
               ctxt->txstats.num_tx_mpdu_noamsdu);

   rawsim_info("Number of A-MSDU bearing MPDUs encapped = %llu",
               ctxt->txstats.num_tx_mpdu_withamsdu);

   rawsim_info("\n");
}

void
clear_stats(rawsim_ctxt ctxt)
{
    if (!ctxt) {
        rawsim_err("\nraw sim context not registerd");
        return;
    }
    OS_MEMZERO(&ctxt->rxstats, sizeof(struct rawmode_pkt_sim_rxstats));
    OS_MEMZERO(&ctxt->txstats, sizeof(struct rawmode_pkt_sim_txstats));
}
