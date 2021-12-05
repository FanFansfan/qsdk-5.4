/*
* Copyright (c) 2011, 2020 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary. Qualcomm Innovation Center, Inc.
*
*
* Copyright (c) 2010, Atheros Communications Inc.
* All Rights Reserved.
*
*
* (c) 2011 Qualcomm Atheros, Inc.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*
*/

/*
 * Ioctl-related defintions for the Atheros Wireless LAN controller driver
 */
#ifndef _DEV_ATH_ATHIOCTL_H
#define _DEV_ATH_ATHIOCTL_H

#ifndef SIOC80211SCOMMONCMD
#define SIOC80211SCOMMONCMD    _IOWR('i', 247, struct ieee80211req)
#endif
#ifndef SIOC80211GCOMMONCMD
#define SIOC80211GCOMMONCMD    _IOWR('i', 248, struct ieee80211req)
#endif

#define ATH_STATS_VI_LOG_LEN 10
#define MAX_BB_PANICS        3
#define ATH_TX_POWER_SRM     0

/*
 * 11n tx/rx stats
 */
struct ath_11n_stats {
	uint32_t tx_pkts;            /* total tx data packets */
	uint32_t tx_checks;          /* tx drops in wrong state */
	uint32_t tx_drops;           /* tx drops due to qdepth limit */
	uint32_t tx_minqdepth;       /* tx when h/w queue depth is low */
	uint32_t tx_queue;           /* tx pkts when h/w queue is busy */
	uint32_t tx_resetq;          /* tx reset queue instances */
	uint32_t tx_comps;           /* tx completions */
	uint32_t tx_comperror;       /* tx err completions on global failure */
	uint32_t tx_unaggr_comperror; /* tx err completions of unaggr frames */
	uint32_t tx_stopfiltered;    /* tx pkts filtered for requeueing */
	uint32_t tx_qnull;           /* txq empty occurences */
	uint32_t tx_noskbs;          /* tx no skbs for encapsulations */
	uint32_t tx_nobufs;          /* tx no descriptors */
	uint32_t tx_badsetups;       /* tx key setup failures */
	uint32_t tx_normnobufs;      /* tx no desc for legacy packets */
	uint32_t tx_schednone;       /* tx schedule pkt queue empty */
	uint32_t tx_bars;            /* tx bars sent */
	uint32_t tx_legacy;          /* tx legacy frames sent */
	uint32_t txunaggr_single;    /* tx unaggregate singles sent */
	uint32_t txbar_xretry;       /* tx bars excessively retried */
	uint32_t txbar_compretries;  /* tx bars retried */
	uint32_t txbar_errlast;      /* tx bars last frame failed */
	uint32_t tx_compunaggr;      /* tx unaggregated frame completions */
	uint32_t txunaggr_xretry;    /* tx unaggregated excessive retries */
	uint32_t tx_compaggr;        /* tx aggregated completions */
	uint32_t tx_bawadv;          /* tx block ack window advanced */
	uint32_t tx_bawretries;      /* tx block ack window retries */
	uint32_t tx_bawnorm;         /* tx block ack window additions */
	uint32_t tx_bawupdates;      /* tx block ack window updates */
	uint32_t tx_bawupdtadv;      /* tx block ack window advances */
	uint32_t tx_retries;         /* tx retries of sub frames */
	uint32_t tx_xretries;        /* tx excessive retries of aggregates */
	uint32_t tx_aggregates;      /* tx aggregated pkts sent */
	uint32_t tx_sf_hw_xretries;  /* subframes excessively retried in hw */
	uint32_t tx_aggr_frames;     /* tx total frames aggregated */
	uint32_t txaggr_noskbs;      /* tx no skbs for aggr encapsualtion */
	uint32_t txaggr_nobufs;      /* tx no desc for aggr */
	uint32_t txaggr_badkeys;     /* tx enc key setup failures */
	uint32_t txaggr_schedwindow; /* tx no frame scheduled: baw limited */
	uint32_t txaggr_single;      /* tx frames not aggregated */
	uint32_t txaggr_mimo;        /* tx frames aggregated for mimo */
	uint32_t txaggr_compgood;    /* tx aggr good completions */
	uint32_t txaggr_comperror;   /* tx aggr error completions */
	uint32_t txaggr_compxretry;  /* tx aggr excessive retries */
	uint32_t txaggr_compretries; /* tx aggr unacked subframes */
	uint32_t txunaggr_compretries; /* tx non-aggr unacked subframes */
	uint32_t txaggr_prepends;    /* tx aggr old frames requeued */
	uint32_t txaggr_filtered;    /* filtered aggr packet */
	uint32_t txaggr_fifo;        /* fifo underrun of aggregate */
	uint32_t txaggr_xtxop;       /* txop exceeded for an aggregate */
	uint32_t txaggr_desc_cfgerr; /* aggregate descriptor config error */
	uint32_t txaggr_data_urun;   /* data underrun for an aggregate */
	uint32_t txaggr_delim_urun;  /* delimiter underrun for an aggr */
	uint32_t txaggr_errlast;     /* tx aggr: last sub-frame failed */
	uint32_t txunaggr_errlast;   /* tx non-aggr: last frame failed */
	uint32_t txaggr_longretries; /* tx aggr h/w long retries */
	uint32_t txaggr_shortretries; /* tx aggr h/w short retries */
	uint32_t txaggr_timer_exp;   /* tx aggr : tx timer expired */
	uint32_t txaggr_babug;       /* tx aggr : BA bug */
	uint32_t txrifs_single;      /* tx frames not bursted */
	uint32_t txrifs_babug;       /* tx rifs : BA bug */
	uint32_t txaggr_badtid;      /* tx aggr : Bad TID */
	uint32_t txrifs_compretries; /* tx rifs unacked subframes */
	uint32_t txrifs_bar_alloc;   /* tx rifs bars allocated */
	uint32_t txrifs_bar_freed;   /* tx rifs bars freed */
	uint32_t txrifs_compgood;    /* tx rifs good completions */
	uint32_t txrifs_prepends;    /* tx rifs old frames requeued */
	uint32_t tx_comprifs;        /* tx rifs completions */
	uint32_t tx_compnorifs;      /* tx not a rifs completion */
	uint32_t rx_pkts;            /* rx pkts */
	uint32_t rx_aggr;            /* rx aggregated packets */
	uint32_t rx_aggrbadver;      /* rx pkts with bad version */
	uint32_t rx_bars;            /* rx bars */
	uint32_t rx_nonqos;          /* rx non qos-data frames */
	uint32_t rx_seqreset;        /* rx sequence resets */
	uint32_t rx_oldseq;          /* rx old packets */
	uint32_t rx_bareset;         /* rx block ack window reset */
	uint32_t rx_baresetpkts;     /* rx pts indicated due to baw resets */
	uint32_t rx_dup;             /* rx duplicate pkts */
	uint32_t rx_baadvance;       /* rx block ack window advanced */
	uint32_t rx_recvcomp;        /* rx pkt completions */
	uint32_t rx_bardiscard;      /* rx bar discarded */
	uint32_t rx_barcomps;        /* rx pkts unblocked on bar reception */
	uint32_t rx_barrecvs;        /* rx pkt completion on bar reception */
	uint32_t rx_skipped;         /* rx pkt sequence skipped on timeout */
	uint32_t rx_comp_to;         /* rx indications due to timeout */
	uint32_t rx_timer_starts;    /* rx countdown timers started */
	uint32_t rx_timer_stops;     /* rx countdown timers stopped */
	uint32_t rx_timer_run;       /* rx timeout occurences */
	uint32_t rx_timer_more;      /* rx partial timeout of pending pkts */
	uint32_t wd_tx_active;       /* watchdog: tx is active */
	uint32_t wd_tx_inactive;     /* watchdog: tx is not active */
	uint32_t wd_tx_hung;         /* watchdog: tx is hung */
	uint32_t wd_spurious;        /* watchdog: spurious tx hang */
	uint32_t tx_requeue;         /* filter & requeue on 20/40 tx */
	uint32_t tx_drain_txq;       /* draining tx queue on error */
	uint32_t tx_drain_tid;       /* draining tid buf queue on error */
	uint32_t tx_cleanup_tid;     /* draining tid buf que on node cleanup */
	uint32_t tx_drain_bufs;      /* buffers drained from pending tidq */
	uint32_t tx_tidpaused;       /* pausing tx on tid */
	uint32_t tx_tidresumed;      /* resuming tx on tid */
	uint32_t tx_unaggr_filtered; /* unaggregated tx pkts filtered */
	uint32_t tx_aggr_filtered;   /* aggregated tx pkts filtered */
	uint32_t tx_filtered;        /* total sub-frames filtered */
	uint32_t rx_rb_on;           /* total rb-s on  */
	uint32_t rx_rb_off;          /* total rb-s off */
	uint32_t rx_dsstat_err;      /* rx descriptor status corrupted */
#ifdef ATH_SUPPORT_TxBF
	uint32_t bf_stream_miss;     /* beamform stream mismatch */
	uint32_t bf_bandwidth_miss;  /* beamform bandwidth mismatch */
	uint32_t bf_destination_miss; /* beamform destination mismatch */
#endif
	uint32_t tx_deducted_tokens; /* ATF txtokens deducted */
	uint32_t tx_unusable_tokens; /* ATF txtokens unusable */
};

struct ath_bb_panic_info {
	int valid;
	uint32_t status;
	uint32_t tsf;
	uint32_t phy_panic_wd_ctl1;
	uint32_t phy_panic_wd_ctl2;
	uint32_t phy_gen_ctrl;
	uint32_t rxc_pcnt;
	uint32_t rxf_pcnt;
	uint32_t txf_pcnt;
	uint32_t cycles;
	uint32_t wd;
	uint32_t det;
	uint32_t rdar;
	uint32_t r_odfm;
	uint32_t r_cck;
	uint32_t t_odfm;
	uint32_t t_cck;
	uint32_t agc;
	uint32_t src;
};

struct ath_phy_stats {
	uint64_t ast_tx_rts;        /* RTS success count */
	uint64_t ast_tx_shortretry; /* tx onchip short retries, RTSFailCnt */
	uint64_t ast_tx_longretry;  /* tx onchip long retries, DataFailCnt */
	uint64_t ast_rx_tooshort;   /* rx discarded because frame too short */
	uint64_t ast_rx_toobig;     /* rx discarded because frame too large */
	uint64_t ast_rx_err;        /* rx error */
	uint64_t ast_rx_crcerr;     /* rx failed because of bad CRC */
	uint64_t ast_rx_fifoerr;    /* rx failed because of FIFO overrun */
	uint64_t ast_rx_phyerr;     /* rx PHY error summary count */
	uint64_t ast_rx_decrypterr; /* rx decryption error */
	uint64_t ast_rx_demicerr;   /* rx demic error */
	uint64_t ast_rx_demicok;    /* rx demic ok */
	uint64_t ast_rx_delim_pre_crcerr;  /* pre-delimiter crc errors */
	uint64_t ast_rx_delim_post_crcerr; /* post-delimiter crc errors */
	uint64_t ast_rx_decrypt_busyerr;   /* decrypt busy errors */
	uint64_t ast_rx_phy[32];           /* rx PHY error per-code counts */
};

struct ath_stats {
	uint32_t ast_watchdog;     /* device reset by watchdog */
	uint32_t ast_resetOnError; /* resets on error */
	uint32_t ast_hardware;     /* fatal hardware error interrupts */
	uint32_t ast_bmiss;        /* beacon miss interrupts */
	uint32_t ast_rxorn;        /* rx overrun interrupts */
	uint32_t ast_rxorn_bmiss;  /* rx overrun and bmiss interrupts:
				      indicate descriptor corruption */
	uint32_t ast_rxeol;        /* rx eol interrupts */
	uint32_t ast_txurn;        /* tx underrun interrupts */
	uint32_t ast_txto;         /* tx timeout interrupts */
	uint32_t ast_cst;          /* carrier sense timeout interrupts */
	uint32_t ast_mib;          /* mib interrupts */
	uint32_t ast_rx;           /* rx interrupts */
	uint32_t ast_rxdesc;       /* rx descriptor interrupts */
	uint32_t ast_rxerr;        /* rx error interrupts */
	uint32_t ast_rxnofrm;      /* rx no frame interrupts */
	uint32_t ast_tx;           /* tx interrupts */
	uint32_t ast_txdesc;       /* tx descriptor interrupts */
	uint32_t ast_tim_timer;    /* tim timer interrupts */
	uint32_t ast_bbevent;      /* baseband event interrupts */
	uint32_t ast_rxphy;        /* rx phy error interrupts */
	uint32_t ast_rxkcm;        /* rx key cache miss interrupts */
	uint32_t ast_swba;         /* sw beacon alert interrupts */
	uint32_t ast_brssi;        /* beacon rssi threshold interrupts */
	uint32_t ast_bnr;          /* beacon not ready interrupts */
	uint32_t ast_tim;          /* tim interrupts */
	uint32_t ast_dtim;         /* dtim interrupts */
	uint32_t ast_dtimsync;     /* dtimsync interrupts */
	uint32_t ast_gpio;         /* general purpose IO interrupts */
	uint32_t ast_cabend;       /* cab end interrupts */
	uint32_t ast_tsfoor;       /* tsf out-of-range interrupts */
	uint32_t ast_gentimer;     /* generic timer interrupts */
	uint32_t ast_gtt;          /* global transmit timeout interrupts */
	uint32_t ast_fatal;        /* fatal interrupts */
	uint32_t ast_tx_packets;   /* packet sent on the interface */
	uint32_t ast_rx_packets;   /* packet received on the interface */
	uint32_t ast_tx_mgmt;      /* management frames transmitted */
	uint32_t ast_tx_discard;   /* frames discarded prior to assoc */
	uint32_t ast_tx_invalid;   /* frames discarded 'cuz device gone */
	uint32_t ast_tx_qstop;     /* tx queue stopped 'cuz full */
	uint32_t ast_tx_encap;     /* tx encapsulation failed */
	uint32_t ast_tx_nonode;    /* tx failed 'cuz no node */
	uint32_t ast_tx_nobuf;     /* tx failed 'cuz no tx buffer (data) */
	uint32_t ast_tx_stop;      /* number of times the netif_stop called*/
	uint32_t ast_tx_resume;    /* no of times netif_wake_queue called */
	uint32_t ast_tx_nobufmgt;  /* tx failed because no tx buffer (mgmt)*/
	uint32_t ast_tx_xretries;  /* tx failed because too many retries */
	uint64_t ast_tx_hw_retries;/* tx retries in hw, not including RTS and
				      successes, (approximation only) */
	uint64_t ast_tx_hw_success;/* tx successes indicated by hw */
	uint32_t ast_tx_fifoerr;   /* tx failed 'cuz FIFO underrun */
	uint32_t ast_tx_filtered;  /* tx failed 'cuz xmit filtered */
	uint32_t ast_tx_badrate;   /* tx failed 'cuz bogus xmit rate */
	uint32_t ast_tx_noack;     /* tx frames with no ack marked */
	uint32_t ast_tx_cts;       /* tx frames with cts enabled */
	uint32_t ast_tx_shortpre;  /* tx frames with short preamble */
	uint32_t ast_tx_altrate;   /* tx frames with alternate rate */
	uint32_t ast_tx_protect;   /* tx frames with protection */
	uint32_t ast_rx_orn;       /* rx failed 'cuz of desc overrun */
	uint32_t ast_rx_badcrypt;  /* rx failed 'cuz decryption */
	uint32_t ast_rx_badmic;    /* rx failed 'cuz MIC failure */
	uint32_t ast_rx_nobuf;     /* rx setup failed 'cuz no skbuff */
	uint32_t ast_rx_hal_in_progress;
	uint32_t ast_rx_num_data;
	uint32_t ast_rx_num_mgmt;
	uint32_t ast_rx_num_ctl;
	uint32_t ast_rx_num_unknown;
	uint32_t ast_max_pkts_per_intr;
#define ATH_STATS_MAX_INTR_BKT  512
	/* counter bucket of packets handled in a single iteration */
	uint32_t ast_pkts_per_intr[ATH_STATS_MAX_INTR_BKT+1];
	int8_t ast_tx_rssi;         /* tx rssi of last ack */
	int8_t ast_tx_rssi_ctl0;    /* tx rssi of last ack [ctl, chain 0] */
	int8_t ast_tx_rssi_ctl1;    /* tx rssi of last ack [ctl, chain 1] */
	int8_t ast_tx_rssi_ctl2;    /* tx rssi of last ack [ctl, chain 2] */
	int8_t ast_tx_rssi_ext0;    /* tx rssi of last ack [ext, chain 0] */
	int8_t ast_tx_rssi_ext1;    /* tx rssi of last ack [ext, chain 1] */
	int8_t ast_tx_rssi_ext2;    /* tx rssi of last ack [ext, chain 2] */
	int8_t ast_rx_rssi;         /* rx rssi from histogram [combined]*/
	int8_t ast_rx_rssi_ctl0;    /* rx rssi from histogram [ctl, chain 0] */
	int8_t ast_rx_rssi_ctl1;    /* rx rssi from histogram [ctl, chain 1] */
	int8_t ast_rx_rssi_ctl2;    /* rx rssi from histogram [ctl, chain 2] */
	int8_t ast_rx_rssi_ext0;    /* rx rssi from histogram [ext, chain 0] */
	int8_t ast_rx_rssi_ext1;    /* rx rssi from histogram [ext, chain 1] */
	int8_t ast_rx_rssi_ext2;    /* rx rssi from histogram [ext, chain 2] */
	uint32_t ast_be_xmit;      /* beacons transmitted */
	uint32_t ast_be_nobuf;     /* no skbuff available for beacon */
	uint32_t ast_per_cal;      /* periodic calibration calls */
	uint32_t ast_per_calfail;  /* periodic calibration failed */
	uint32_t ast_per_rfgain;   /* periodic calibration rfgain reset */
	uint32_t ast_rate_calls;   /* rate control checks */
	uint32_t ast_rate_raise;   /* rate control raised xmit rate */
	uint32_t ast_rate_drop;    /* rate control dropped xmit rate */
	uint32_t ast_ant_defswitch; /* rx/default antenna switches */
	uint32_t ast_ant_txswitch; /* tx antenna switches */
	uint32_t ast_ant_rx[8];    /* rx frames with antenna */
	uint32_t ast_ant_tx[8];    /* tx frames with antenna */
	uint64_t ast_rx_bytes;     /* total number of bytes received */
	uint64_t ast_tx_bytes;     /* total number of bytes transmitted */
	uint32_t ast_rx_num_qos_data[16]; /* per tid rx packets
					     (includes duplicates)*/
	uint32_t ast_rx_num_nonqos_data;  /* non qos rx packets    */
	uint32_t ast_txq_packets[16];  /* perq packets sent on the interface
					  for each category */
	uint32_t ast_txq_xretries[16]; /* perq tx failed 'cuz too many retry */
	uint32_t ast_txq_fifoerr[16];  /* per q tx failed 'cuz FIFO underrun */
	uint32_t ast_txq_filtered[16]; /*per q tx failed 'cuz xmit filtered */
	uint32_t ast_txq_athbuf_limit[16]; /* tx dropped 'cuz of athbuf lmt */
	uint32_t ast_txq_nobuf[16];        /* tx dropped 'cuz no athbufs */
	uint8_t  ast_num_rxchain;          /* Number of rx chains */
	uint8_t  ast_num_txchain;          /* Number of tx chains */
	struct ath_11n_stats ast_11n_stats; /* 11n statistics */
	uint32_t ast_bb_hang;              /* BB hang detected */
	uint32_t ast_mac_hang;             /* MAC hang detected */
#if ATH_WOW
	uint32_t ast_wow_wakeups; /* count of hibernate and standby wakeups */
	uint32_t ast_wow_wakeupsok;        /* count of wakeups thru WoW */
	uint32_t ast_wow_wakeupserror;     /* count of errored wakeups */
#if ATH_WOW_DEBUG
	uint32_t ast_normal_sleeps;        /* count of normal sleeps */
	uint32_t ast_normal_wakeups;       /* count of normal wakeups*/
	uint32_t ast_wow_sleeps;           /* count of wow sleeps */
	uint32_t ast_wow_sleeps_nonet;     /* w/o IP config */
#endif
#endif
#ifdef ATH_SUPPORT_UAPSD
	uint32_t ast_uapsdqnulbf_unavail;  /* no qos null buffers available */
	uint32_t ast_uapsdqnul_pkts;   /* cnt of qos null frames sent */
	uint32_t ast_uapsdtriggers;    /* cnt of UAPSD triggers received */
	uint32_t ast_uapsdnodeinvalid; /* cnt of triggers for non-UAPSD node */
	uint32_t ast_uapsdeospdata;    /* cnt of QoS Data with EOSP sent */
	uint32_t ast_uapsddata_pkts;   /* cnt of UAPSD QoS Data frames sent */
	uint32_t ast_uapsddatacomp;    /* cnt of UAPSD QoS Data frms compltd */
	uint32_t ast_uapsdqnulcomp;    /* cnt of UAPSD QoS NULL frms compltd */
	uint32_t ast_uapsddataqueued;  /* cnt of UAPSD QoS Data Queued */
#endif
#ifdef ATH_SUPPORT_VOWEXT
	/*
	 * VOWEXT stats only. Literally some of the iqueue stats can be re-used
	 * here. As part of current release, all vow stats will be added extra
	 * and re-using will be thought for next release
	 */
	/*
	 * ast_vow_ul_tx_calls : Number of frames Upper Layer ( ieee ) tried to
	 * send over each access category. For each of the AC this would denote
	 * how many frames reached ATH layer
	 * ast_vow_ath_txq_calls: Subset of ( ast_vow_ul_tx_calls ) that can be
	 * either queued or can be sent immediate, either as an aggregate or as
	 * an normal frame. This counts only frames that can be sen
	*/
	uint32_t ast_vow_ul_tx_calls[4];
	uint32_t ast_vow_ath_txq_calls[4];
	uint32_t ast_vow_ath_be_drop, ast_vow_ath_bk_drop;
#endif
#if ATH_SUPPORT_CFEND
	uint32_t ast_cfend_sched;     /* count of CF-END frames scheduled */
	uint32_t ast_cfend_sent;      /* count of CF-END frames sent */
#endif

#ifdef UMAC_SUPPORT_VI_DBG
	uint32_t vi_timestamp[ATH_STATS_VI_LOG_LEN];/* hw assigned timestamp */
	uint8_t vi_rssi_ctl0[ATH_STATS_VI_LOG_LEN]; /* rx frame RSSI
							[ctl, chain 0] */
	uint8_t vi_rssi_ctl1[ATH_STATS_VI_LOG_LEN]; /* rx frame RSSI
							[ctl, chain 1] */
	uint8_t vi_rssi_ctl2[ATH_STATS_VI_LOG_LEN]; /* rx frame RSSI
							[ctl, chain 2] */
	uint8_t vi_rssi_ext0[ATH_STATS_VI_LOG_LEN]; /* rx frame RSSI
							[ext, chain 0] */
	uint8_t vi_rssi_ext1[ATH_STATS_VI_LOG_LEN]; /* rx frame RSSI
							[ext, chain 1] */
	uint8_t vi_rssi_ext2[ATH_STATS_VI_LOG_LEN]; /* rx frame RSSI
							[ext, chain 2] */
	uint8_t vi_rssi[ATH_STATS_VI_LOG_LEN];
	uint8_t vi_evm0[ATH_STATS_VI_LOG_LEN];           /* evm - chain 0 */
	uint8_t vi_evm1[ATH_STATS_VI_LOG_LEN];           /* evm - chain 1 */
	uint8_t vi_evm2[ATH_STATS_VI_LOG_LEN];           /* evm - chain 2 */
	uint8_t vi_rs_rate[ATH_STATS_VI_LOG_LEN];        /* hw rx rate index */
	uint32_t vi_tx_frame_cnt[ATH_STATS_VI_LOG_LEN];  /* Profile count
							    tx frames */
	uint32_t vi_rx_frame_cnt[ATH_STATS_VI_LOG_LEN];  /* Profile count
							    rx frames */
	uint32_t vi_rx_clr_cnt[ATH_STATS_VI_LOG_LEN];    /* Profile count
							    receive clear */
	uint32_t vi_rx_ext_clr_cnt[ATH_STATS_VI_LOG_LEN];/* Profile count rx
							    clear on ext ch */
	uint32_t vi_cycle_cnt[ATH_STATS_VI_LOG_LEN];     /* Profile count
							    cycle counter */
	uint8_t  vi_stats_index;    /* Used to index circular buffer used
				       to hold video stats */
#endif
#ifdef ATH_SUPPORT_TxBF
#define MCS_RATE 0x1f
	uint8_t ast_txbf;
	uint8_t ast_lastratecode;
	uint32_t ast_sounding_count;
	uint32_t ast_txbf_rpt_count;
	uint32_t ast_mcs_count[MCS_RATE+1];
#endif
	struct ath_bb_panic_info ast_bb_panic[MAX_BB_PANICS];
};

/*
 * Enumeration of parameter IDs
 * This is how the external users refer to specific parameters, which is
 * why it's defined in the external interface
*/
typedef enum {
	ATH_PARAM_TXCHAINMASK                 =1,
	ATH_PARAM_RXCHAINMASK                 =2,
	ATH_PARAM_TXCHAINMASKLEGACY           =3,
	ATH_PARAM_RXCHAINMASKLEGACY           =4,
	ATH_PARAM_CHAINMASK_SEL               =5,
	ATH_PARAM_AMPDU                       =6,
	ATH_PARAM_AMPDU_LIMIT                 =7,
	ATH_PARAM_AMPDU_SUBFRAMES             =8,
	ATH_PARAM_AGGR_PROT                   =9,
	ATH_PARAM_AGGR_PROT_DUR               =10,
	ATH_PARAM_AGGR_PROT_MAX               =11,
	ATH_PARAM_TXPOWER_LIMIT2G             =12,
	ATH_PARAM_TXPOWER_LIMIT5G             =13,
	ATH_PARAM_TXPOWER_OVERRIDE            =14,
	ATH_PARAM_PCIE_DISABLE_ASPM_WK        =15,
	ATH_PARAM_PCID_ASPM                   =16,
	ATH_PARAM_BEACON_NORESET              =17,
	ATH_PARAM_CAB_CONFIG                  =18,
	ATH_PARAM_ATH_DEBUG                   =19,
	ATH_PARAM_ATH_TPSCALE                 =20,
	ATH_PARAM_ACKTIMEOUT                  =21,
	ATH_PARAM_AMSDU_ENABLE                =26,
#if ATH_SUPPORT_IQUE
	ATH_PARAM_RETRY_DURATION              =27,
	ATH_PARAM_HBR_HIGHPER                 =28,
	ATH_PARAM_HBR_LOWPER                  =29,
#endif
	ATH_PARAM_RX_STBC                     =30,
	ATH_PARAM_TX_STBC                     =31,
	ATH_PARAM_LDPC                        =32,
	ATH_PARAM_LIMIT_LEGACY_FRM            =33,
	ATH_PARAM_TOGGLE_IMMUNITY             =34,
	ATH_PARAM_WEP_TKIP_AGGR_TX_DELIM      =35,
	ATH_PARAM_WEP_TKIP_AGGR_RX_DELIM      =36,
	ATH_PARAM_GPIO_LED_CUSTOM             =37,
	ATH_PARAM_SWAP_DEFAULT_LED            =38,
#if ATH_SUPPORT_VOWEXT
	ATH_PARAM_VOWEXT                      =40,
	ATH_PARAM_RCA                         =41, /* rate ctl & aggr params */
	ATH_PARAM_VSP_ENABLE                  =42,
	ATH_PARAM_VSP_THRESHOLD               =43,
	ATH_PARAM_VSP_EVALINTERVAL            =44,
#endif
#if ATH_VOW_EXT_STATS
	ATH_PARAM_VOWEXT_STATS                =45,
#endif
	/*Thresholds for interrupt mitigation*/
	ATH_PARAM_RIMT_FIRST                  =64,
	ATH_PARAM_RIMT_LAST                   =65,
	ATH_PARAM_TIMT_FIRST                  =66,
	ATH_PARAM_TIMT_LAST                   =67,
	ATH_PARAM_TXBF_SW_TIMER               =69,
	ATH_PARAM_PHYRESTART_WAR              =70,
	ATH_PARAM_CHANNEL_SWITCHING_TIME_USEC =71,
	ATH_PARAM_KEYSEARCH_ALWAYS_WAR        =72,
#ifdef ATH_SUPPORT_DYN_TX_CHAINMASK
	ATH_PARAM_DYN_TX_CHAINMASK            =73,
#endif /* ATH_SUPPORT_DYN_TX_CHAINMASK */
#if ATH_SUPPORT_VOWEXT
	ATH_PARAM_VSP_STATS                   =74,
	ATH_PARAM_VSP_STATSCLR                =75,
#endif
#if UMAC_SUPPORT_INTERNALANTENNA
	ATH_PARAM_SMARTANTENNA                =76,
#endif
	ATH_PARAM_AGGR_BURST                  =77,
	ATH_PARAM_AGGR_BURST_DURATION         =78,
#if ATH_SUPPORT_FLOWMAC_MODULE
	ATH_PARAM_FLOWMAC                     =79,
#endif
	ATH_PARAM_BCN_BURST                   =80,
#if ATH_ANI_NOISE_SPUR_OPT
	ATH_PARAM_NOISE_SPUR_OPT              =81,
#endif
	ATH_PARAM_DCS_ENABLE                  =82,
	ATH_PARAM_TOTAL_PER                   =89,
	ATH_PARAM_AMPDU_RX_BSIZE              =90,
} ath_param_ID_t;

#endif /* _DEV_ATH_ATHIOCTL_H */

