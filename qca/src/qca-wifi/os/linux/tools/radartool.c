/*
 * Copyright (c) 2013,2017-2019 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008, Atheros Communications Inc.
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

#include <qcatools_lib.h> /* library for common headerfiles */
#include <if_athioctl.h>
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
typedef struct {
        volatile int counter;
} atomic_t;

#include <wlan_dfs_ioctl.h>

#ifndef ATH_DEFAULT
#define ATH_DEFAULT "wifi0"
#endif

#define RADAR_NL80211_CMD_SOCK_ID    DEFAULT_NL80211_CMD_SOCK_ID
#define RADAR_NL80211_EVENT_SOCK_ID  DEFAULT_NL80211_EVENT_SOCK_ID

/*
 * Device revision information.
 */
typedef struct {
    u_int16_t   ah_devid;            /* PCI device ID */
    u_int16_t   ah_subvendorid;      /* PCI subvendor ID */
    u_int32_t   ah_mac_version;      /* MAC version id */
    u_int16_t   ah_mac_rev;          /* MAC revision */
    u_int16_t   ah_phy_rev;          /* PHY revision */
    u_int16_t   ah_analog_5Ghz_rev;  /* 5GHz radio revision */
    u_int16_t   ah_analog_2Ghz_Rev;  /* 2GHz radio revision */
} HAL_REVS;

struct radarhandler {
	int	s;
	struct ath_diag atd;
    struct socket_context sock_ctx;
};

/*
 * radar_send_command; function to send the cfg command or ioctl command.
 * @radar     : pointer to radarhandler
 * @ifname    : interface name
 * @buf       : buffer
 * @buflen    : buffer length
 * return     : 0 for sucess, -1 for failure
 */
int radar_send_command (struct radarhandler *radar, const char *ifname, void *buf, size_t buflen, int ioctl_sock_fd)
{
#if UMAC_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    int nl_cmd = QCA_NL80211_VENDOR_SUBCMD_PHYERR;
    int msg;
    wifi_cfg80211_context pcfg80211_sock_ctx;
#endif /* UMAC_SUPPORT_CFG80211 */
#if UMAC_SUPPORT_WEXT
    struct ifreq ifr;
    int ioctl_cmd = SIOCGATHPHYERR;
#endif

    if (radar->sock_ctx.cfg80211) {
#if UMAC_SUPPORT_CFG80211
        pcfg80211_sock_ctx = radar->sock_ctx.cfg80211_ctxt;
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_sendcmd(&pcfg80211_sock_ctx,
                nl_cmd, ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            fprintf(stderr, "Couldn't send NL command\n");
            return -1;
        }
#endif /* UMAC_SUPPORT_CFG80211 */
    } else {
#if UMAC_SUPPORT_WEXT
        if (ifname) {
            size_t dstsize;

            memset(ifr.ifr_name, '\0', IFNAMSIZ);
            dstsize = (strlen(ifname)+1) < IFNAMSIZ ?
                (strlen(ifname)+1) : IFNAMSIZ;
            strlcpy(ifr.ifr_name, ifname, dstsize);
        } else {
            fprintf(stderr, "no such file or device\n");
            return -1;
        }
        ifr.ifr_data = buf;
        if (ioctl(ioctl_sock_fd, ioctl_cmd, &ifr) < 0) {
            perror("ioctl failed");
            return -1;
        }
#endif /* UMAC_SUPPORT_WEXT */
    }
    return 0;
}


/*
 * handle_radar : Function to handle all radar related operations.
 * @radar       : Pointer to radar handler
 * @dfs_flag    : Flag that decides the operation handled
 * @value       : value to be set/variable to get
 * @set         : 1 for set param and 0 for get param
 * returns 0 for set params and value to be get in get params
 */
static int handle_radar(struct radarhandler *radar, u_int32_t dfs_flag,
                        u_int32_t value, u_int32_t set)
{
    radar->atd.ad_id = dfs_flag;
    if (set) {
        radar->atd.ad_out_data = NULL;
        radar->atd.ad_out_size = 0;
        radar->atd.ad_in_data = (void *) &value;
        radar->atd.ad_in_size = sizeof(u_int32_t);
    } else {
        radar->atd.ad_in_data = NULL;
        radar->atd.ad_in_size = 0;
        radar->atd.ad_out_data = (void *) &value;
        radar->atd.ad_out_size = sizeof(u_int32_t);
    }

    if (radar_send_command(radar, radar->atd.ad_name,
        (caddr_t)&radar->atd, sizeof(struct ath_diag),
        radar->sock_ctx.sock_fd) < 0) {
        err(1, "%s", radar->atd.ad_name);
    }

    /* Clear references to local variables*/
    if (set) {
        radar->atd.ad_in_data = NULL;
        return 0;
    } else {
        radar->atd.ad_out_data = NULL;
        return value;
    }
}

/*
 * radarGetThresholds : collect threshold info
 * @radar             : pointer to radarhandler
 * @pe                : pointer to structure of type struct dfs_ioctl_params
 */
static void radarGetThresholds(struct radarhandler *radar,
    struct dfs_ioctl_params *pe)
{
    radar->atd.ad_id = DFS_GET_THRESH | ATH_DIAG_DYN;
    radar->atd.ad_out_data = (void *) pe;
    radar->atd.ad_out_size = sizeof(struct dfs_ioctl_params);
    if (radar_send_command(radar, radar->atd.ad_name,
        (caddr_t)&radar->atd, sizeof(struct ath_diag),
		radar->sock_ctx.sock_fd) < 0) {
            err(1, "%s", radar->atd.ad_name);
    }
}

/*
 * radarBangradar() - Handle bangradar commands.
 * @bangradar_type : Type of bangradar command issued based on number of arguments.
 * @seg_id         : Segment ID.
 * @is_chirp       : Chirp information.
 * @freq_offset    : Frequency offset.
 * @detector_id    : Detector ID.
 */
static void radarBangradar(struct radarhandler *radar,
    enum dfs_bangradar_types bangradar_type, int seg_id, int is_chirp,
    int freq_offset, uint8_t detector_id)
{
    struct dfs_bangradar_params pe;

	pe.bangradar_type = bangradar_type;
	pe.seg_id = seg_id;
	pe.is_chirp = is_chirp;
	pe.freq_offset = freq_offset;
	pe.detector_id = detector_id;

	radar->atd.ad_id = DFS_BANGRADAR | ATH_DIAG_IN;
	radar->atd.ad_out_data = NULL;
	radar->atd.ad_out_size = 0;
	radar->atd.ad_in_data = (void *) &pe;
	radar->atd.ad_in_size = sizeof(struct dfs_bangradar_params);
	if (radar_send_command(radar, radar->atd.ad_name, (caddr_t)&radar->atd, sizeof(struct ath_diag),
			radar->s) < 0) {
		err(1, "%s", radar->atd.ad_name);
	}
	radar->atd.ad_in_data = NULL;
}

/*
 * radarset  : set various parameters for radar detection
 * @radar    : pointer to radar handler
 * @op       : enum values for different options
 * @param    : param input
 */
void radarset(struct radarhandler *radar, int op, u_int32_t param)
{
    struct dfs_ioctl_params pe;

    pe.dfs_firpwr = DFS_IOCTL_PARAM_NOVAL;
    pe.dfs_rrssi = DFS_IOCTL_PARAM_NOVAL;
    pe.dfs_height = DFS_IOCTL_PARAM_NOVAL;
    pe.dfs_prssi = DFS_IOCTL_PARAM_NOVAL;
    pe.dfs_inband = DFS_IOCTL_PARAM_NOVAL;

    /* 5413 specific */
    pe.dfs_relpwr = DFS_IOCTL_PARAM_NOVAL;
    pe.dfs_relstep = DFS_IOCTL_PARAM_NOVAL;
    pe.dfs_maxlen = DFS_IOCTL_PARAM_NOVAL;

    switch(op) {
        case DFS_PARAM_FIRPWR:
            pe.dfs_firpwr = param;
            break;
        case DFS_PARAM_RRSSI:
            pe.dfs_rrssi = param;
            break;
        case DFS_PARAM_HEIGHT:
            pe.dfs_height = param;
            break;
        case DFS_PARAM_PRSSI:
            pe.dfs_prssi = param;
            break;
        case DFS_PARAM_INBAND:
            pe.dfs_inband = param;
            break;
            /* following are valid for 5413 only */
        case DFS_PARAM_RELPWR:
            pe.dfs_relpwr = param;
            break;
        case DFS_PARAM_RELSTEP:
            pe.dfs_relstep = param;
            break;
        case DFS_PARAM_MAXLEN:
            pe.dfs_maxlen = param;
            break;
    }
    radar->atd.ad_id = DFS_SET_THRESH | ATH_DIAG_IN;
    radar->atd.ad_out_data = NULL;
    radar->atd.ad_out_size = 0;
    radar->atd.ad_in_data = (void *) &pe;
    radar->atd.ad_in_size = sizeof(struct dfs_ioctl_params);
    if (radar_send_command(radar, radar->atd.ad_name,
        (caddr_t)&radar->atd, sizeof(struct ath_diag),
        radar->sock_ctx.sock_fd) < 0) {
            err(1, "%s", radar->atd.ad_name);
    }
    radar->atd.ad_in_data = NULL;
}

/*
 * radarGetNol : get NOL channel info
 * @radar      : pointer to radar handler
 * @fname      : file name
 */
void radarGetNol(struct radarhandler *radar, char *fname)
{
    struct dfsreq_nolinfo nolinfo;
    FILE *fp = NULL;
    char buf[100];

    if (fname != NULL) {
        fp = fopen(fname, "wb");
        if (!fp) {
            memset(buf, '\0', sizeof(buf));
            snprintf(buf, sizeof(buf) - 1,"%s: fopen %s error",__func__, fname);
            perror(buf);
            return;
        }
    }

    radar->atd.ad_id = DFS_GET_NOL | ATH_DIAG_DYN;
    radar->atd.ad_in_data = NULL;
    radar->atd.ad_in_size = 0;
    radar->atd.ad_out_data = (void *) &nolinfo;
    radar->atd.ad_out_size = sizeof(struct dfsreq_nolinfo);

    if (radar_send_command(radar, radar->atd.ad_name,
        (caddr_t)&radar->atd, sizeof(struct ath_diag),
        radar->sock_ctx.sock_fd) < 0) {
        err(1, "%s", radar->atd.ad_name);
    }

    /*
     * Optionally dump the contents of dfsreq_nolinfo
     */
    if (fp != NULL) {
        fwrite(&nolinfo, sizeof(struct dfsreq_nolinfo), 1, fp);
        fclose(fp);
    }

    /* clear references to local variables */
    radar->atd.ad_out_data = NULL;
}

/*
 * radarSetNOl  : set NOL channel info
 * @radar       : pointer to radar handler
 * @fname       : file name
 */
void radarSetNol(struct radarhandler *radar, char *fname)
{
    struct dfsreq_nolinfo nolinfo;
    FILE *fp;
    char buf[100];
    int i;

    fp = fopen(fname, "rb");
    if (!fp)
    {
        memset(buf, '\0', sizeof(buf));
        snprintf(buf, sizeof(buf) - 1,"%s: fopen %s error",__func__, fname);
        perror(buf);
        return;
    }

    fread(&nolinfo, sizeof(struct dfsreq_nolinfo), 1, fp);
    fclose(fp);

    for (i=0; i<nolinfo.dfs_ch_nchans; i++)
    {
        /* Modify for static analysis, prevent overrun */
        if ( i < DFS_CHAN_MAX ) {
            printf("nol:%d channel=%d startticks=%llu timeout=%d \n",
                    i, nolinfo.dfs_nol[i].nol_freq,
                    (unsigned long long)nolinfo.dfs_nol[i].nol_start_us,
                    nolinfo.dfs_nol[i].nol_timeout_ms);
        }
    }

    radar->atd.ad_id = DFS_SET_NOL | ATH_DIAG_IN;
    radar->atd.ad_out_data = NULL;
    radar->atd.ad_out_size = 0;
    radar->atd.ad_in_data = (void *) &nolinfo;
    radar->atd.ad_in_size = sizeof(struct dfsreq_nolinfo);

    if (radar_send_command(radar, radar->atd.ad_name,
        (caddr_t)&radar->atd, sizeof(struct ath_diag),
         radar->sock_ctx.sock_fd) < 0) {
        err(1, "%s", radar->atd.ad_name);
    }
    radar->atd.ad_in_data = NULL;
}

#if defined(WLAN_DFS_SYNTHETIC_RADAR)
/*
 * dfs_copy_buf_header - Typecast buffer to sequence and fill the total len
 * and num pulses.
 * @buf: Buffer to fill
 * @src_syn_seq: Pointer to the pulse that user wishes to inject
 */
static void
dfs_copy_pulse_header_to_buf (char *buf, struct synthetic_seq *src_syn_seq)
{
    struct synthetic_seq *dst_syn_seq; /*Pointer to the destn seq */

    dst_syn_seq = (struct synthetic_seq *)buf;
    dst_syn_seq->num_pulses = src_syn_seq->num_pulses;
    dst_syn_seq->total_len_seq = src_syn_seq->total_len_seq;
}

/*
 * dfs_copy_pulse_data - Fill the non-FFT  & FFT contents of the pulse
 * @tmp_dst_pulse: Buffer to fill
 * @src_syn_seq: Pointer to the pulse that user wishes to inject
 */
static void
dfs_copy_pulse_data_to_buf (struct synthetic_pulse *tmp_dst_pulse,
                            struct synthetic_seq *src_syn_seq)
{
    int j;
    struct synthetic_pulse *t_src_pulse;

    for (j=0; j < src_syn_seq->num_pulses; j++) {
        unsigned char *fft_ptr, *buf_ptr;
        int non_fft_pulse_size;

        buf_ptr = (char * ) tmp_dst_pulse;
        t_src_pulse = src_syn_seq->pulse[j];
        non_fft_pulse_size = sizeof(struct synthetic_pulse) - sizeof(char *);
        /* Copy the static contents of the pulse to dst_pulse */
        memcpy(tmp_dst_pulse, t_src_pulse, non_fft_pulse_size);
        /*fft_ptr to point to the start of FFT */
        fft_ptr = (char *)(tmp_dst_pulse) + non_fft_pulse_size;
        /* Copy the FFT contents */
        memcpy(fft_ptr, t_src_pulse->fft_buf, t_src_pulse->fft_datalen);
        /*fft_ptr to point to the end of FFT */
        fft_ptr += t_src_pulse->fft_datalen;
        tmp_dst_pulse  =  (struct synthetic_pulse *)fft_ptr;
    }
}

/*
 * dfs_copy_seq_to_buf - Function to fill the pulse contents into single buffer
 * @buf: Buffer to be filled
 * @src_syn_seq: Pointer to the pulse that user wishes to inject.
 */

/*
 * Structure of the buffer:
 * =======================
 * Header
 * ======
 * ----------|--------------|
 * num_pulses| total_len_seq|
 * ----------|--------------|
 *
 * Buffer Contents per pulse:
 * ==========================
 *
 * ------|-----------|-----------|-----------|------------|---------------|-----------
 * r_rssi| r_ext_rssi|r_rs_tstamp| r_fulltsf |fft_datalen |total_len_pulse|FFT Buffer.....
 * ------|-----------|-----------|-----------|------------|---------------|-----------
 */

static void dfs_copy_seq_to_buf (char *buf, struct synthetic_seq *src_syn_seq)
{
    struct synthetic_seq *dst_syn_seq; /*Pointer to the destn seq */
    struct synthetic_pulse *tmp_dst_pulse;

    dfs_copy_pulse_header_to_buf (buf, src_syn_seq);
    /* tmp_dst_pulse to point to the buffer's beggining from where
     * pulse structure  is to filled.
     */
    tmp_dst_pulse = (struct synthetic_pulse *)(buf +
                                               sizeof(dst_syn_seq->num_pulses) +
                                               sizeof(dst_syn_seq->total_len_seq));
    dfs_copy_pulse_data_to_buf (tmp_dst_pulse, src_syn_seq);
}

/*
 * read_synthetic_pulses - Function to read the synthetic pulses
 * @cur_seq: Pointer to the current sequence
 * @file: File location where synthetic pulses are stored.
 */
static int
read_synthetic_pulses(struct synthetic_seq *cur_seq, FILE *file,
                      unsigned int *total_pulse_len)
{
    unsigned int j, k;

    for(j=0; j < cur_seq->num_pulses; j++)
    {
        struct synthetic_pulse *cur_pulse; /* Pointer to the current pulse */

        cur_seq->pulse[j] = (struct synthetic_pulse *) malloc
            (sizeof(struct synthetic_pulse));

        cur_pulse = cur_seq->pulse[j];

        if (cur_pulse == NULL) {
            printf("[%s]: Unable to allocate memory for pulse %d\n",__func__,j);
            return -1;
        }

        fscanf(file,"%hhu %hhu %u %llu %hu", &(cur_pulse->r_rssi),
               &(cur_pulse->r_ext_rssi), &(cur_pulse->r_rs_tstamp),
               &(cur_pulse->r_fulltsf), &(cur_pulse->fft_datalen));

        cur_pulse->fft_buf = (char *) malloc(sizeof(char) * cur_pulse->fft_datalen);
        cur_pulse->total_len_pulse = sizeof(struct synthetic_pulse) +
            (sizeof(char) * (cur_pulse->fft_datalen)) - sizeof(char *);
        (*total_pulse_len) += cur_pulse->total_len_pulse;

        if (cur_pulse->fft_buf == NULL) {
            printf("[%s]Unable to allocate memory for buffer\n",__func__);
            return -1;
        }

        for(k=0; k < (cur_pulse->fft_datalen); k++) {
            fscanf(file,"%hhx",&(cur_pulse->fft_buf[k]));
        }
    }
    return 0;
}

/*
 * read_synthetic_sequences : Function to read the synthetic sequences of pulses.
 * @store: Pointer to seq_store structure
 * @file: file location  where pulses are stored
 */

static int
read_synthetic_sequences(struct seq_store *store, FILE *file)
{
    uint8_t i, num_pulses = 0;
    unsigned int total_pulse_len;
    int error = 0;

    for (i=0; i < store->num_sequence; i++)
    {
        struct synthetic_seq *cur_seq; /* Pointer to the current sequence*/

        total_pulse_len = 0;
        fscanf(file, "%d",&num_pulses); /* No of pulses in the current seq */
        if (num_pulses == 0) {
            printf("[%s].. There are no pulses in the sequence %d\n",__func__,i);
            return -1;
        }
        /* Malloc Size: num_pulses  + "num_pulses" number of pointers to  struct synthetic_pulse */
        store->seq_arr[i] = (struct synthetic_seq *) malloc
            (sizeof(struct synthetic_seq) +
             (num_pulses * sizeof(struct synthetic_pulse *)));

        if (store->seq_arr[i] == NULL) {
            printf("[%s]Unable to allocate memory for seq_arr\n",__func__);
            return -1;
        }
        cur_seq = store->seq_arr[i];
        cur_seq->num_pulses = num_pulses;

        error = read_synthetic_pulses(cur_seq, file, &total_pulse_len);
        /* Total length of the sequence is sizeof(struct synthetic_seq) + size of each pulse in the sequence */
        /* Size of each pulse is sizeof(struct synthetic_pulse ) + [sizeof(char) * datalen of buffer ] - sizeof(char buffer pointer) */
        cur_seq->total_len_seq = total_pulse_len + sizeof(struct synthetic_seq);
    }
    return error;
}

/*
 * dfs_send_pulses_to_driver - Pass the pulse buffer to the driver using an
 * ioctl.
 * @radar: pointer to radarhandler
 * @in_size: Size of the buffer to be sent
 * @buf: Pointer to the buffer to be sent
 */
    static int
dfs_send_pulses_to_driver (struct radarhandler *radar, unsigned int in_size,
                           unsigned char *buf)
{
    struct ifreq ifr;

    radar->atd.ad_id = DFS_INJECT_SEQUENCE | ATH_DIAG_IN;
    radar->atd.ad_out_data = NULL;
    radar->atd.ad_out_size = 0;
    radar->atd.ad_in_data = (void *)buf;
    radar->atd.ad_in_size = in_size;

    if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >=
       sizeof(ifr.ifr_name)) {
        printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
        return -1;
    }

    ifr.ifr_data = (caddr_t)&radar->atd;
    if (radar_send_command(radar,
                           radar->atd.ad_name,
                           (caddr_t)&radar->atd,
                           sizeof(struct ath_diag),
                           radar->s) < 0) {
            err(1, radar->atd.ad_name);
    }
    radar->atd.ad_in_data = NULL;
   return 0;
}

/*
 * Algorithm for Synthetic Pulse injection using Radartool
 * *******************************************************
 * User File Format
 * ===============
 * Total num of sequences
 * #Sequence 1#
 * num_pulses of sequence 1
 * #Pulse 1#
 * rssi ext_rssi rs_tstamp fulltsf fft_datalen FFT_Buff
 * #Pulse 2#
 * rssi ext_rssi rs_tstamp fulltsf fft_datalen FFT_Buff
 * .......
 * #Pulse N#
 * #Sequence 2#
 * num_pulses of sequence 2
 * Pulse 1 ..... Pulse N
 * .....
 * # Sequence N #
 *
 * Radartool:
 * ===========
 * 1) Read all the sequences of pulses from the user file, calcuate the size of
 * each sequence and pulse, allocate memory  and store them.
 * 2) For the user configured "radar sequence to inject", allocate a single
 * buffer of required size (computed in step 1).
 * 3) Fill the destination buffer with the pulse contents  and send it to the
 * driver.
 *
 * Driver:
 * ======
 * 1. Use copy_from_user to copy the buffer to kernel. The buffer contains the
 * entire sequence of pulses.
 * 2. Inject one pulse at a time to the Radar Detection Algorithm
 * (dfs_process_phyerr).
 */

/*
 * radarInjectSequence - Function to read the sequence of pulses from the file
 * and pass the pulse buffer to the driver.
 * @radar: pointer to radarhandler
 * @fname: filename where the synthetic pulses are stored
 * @sequence_idx_to_inject: Sequence index of the pulse to be injected. This
 * index begins with 0.
 */

static int
radarInjectSequence(struct radarhandler *radar, char *fname,
                    u_int8_t sequence_idx_to_inject)
{
    uint8_t j, i, num_seq;
    FILE *file;
    unsigned int in_size = 0;
    unsigned char *buf = NULL;
    struct seq_store *store = NULL; /* Pointer to the store of sequences */
    struct synthetic_seq *src_syn_seq; /* Pointer to the sequence index to inject */
    int error = 0;

    file = fopen(fname, "r");
    if (file == NULL) {
        err(1, "%s", fname);
        exit(-1);
    } else {
        fscanf(file,"%d", &num_seq);
    }

    if (num_seq == 0) {
        printf("[%s].. There are no pulse sequence in the file\n",__func__);
        goto out;
    }

    store = (struct seq_store *) malloc (sizeof(struct seq_store) +
                                           (sizeof(struct synthetic_seq *) *
                                            num_seq));

    if (store == NULL) {
        printf("Unable to allocate memory for store\n",__func__);
        goto out;
    }
    store->num_sequence = num_seq;
    error = read_synthetic_sequences(store, file);
    if (error)
        goto out;
    fclose(file);

    if (sequence_idx_to_inject < num_seq) {
        src_syn_seq = store->seq_arr[sequence_idx_to_inject];
        if (src_syn_seq!= NULL && src_syn_seq->num_pulses > 0)
            in_size = src_syn_seq->total_len_seq;
        else
            goto out;
    } else {
        printf("%s..The sequence to inject is greater than the sequence available..Max sequence=%d\n",__func__,(num_seq-1));
        goto out;
    }

    buf = (unsigned char *) malloc(in_size * sizeof(unsigned char));
    if (buf) {
        memset(buf, '\0', in_size);
    } else {
        printf("%s: Malloc failed\n",__func__);
        goto out;
    }
    dfs_copy_seq_to_buf(buf, src_syn_seq);

    dfs_send_pulses_to_driver (radar, in_size, buf);

out:
    /* Free Dynamically Allocated Memory */
    if(store) {
        for(i=0; i <(store->num_sequence); i++)
        {
            if(store->seq_arr[i]) {
                for(j=0; j <(store->seq_arr[i]->num_pulses); j++)
                {
                    if(store->seq_arr[i]->pulse[j]) {
                        if (store->seq_arr[i]->pulse[j]->fft_buf) {
                            free(store->seq_arr[i]->pulse[j]->fft_buf);
                        }
                        free(store->seq_arr[i]->pulse[j]);
                    }
                }
                free(store->seq_arr[i]);
            }
        }
        free(store);
    }
    if (buf) {
        free(buf);
    }
    if (file)
        fclose(file);
    return 0;

}

static int
radarAllowHWPulses(struct radarhandler *radar, bool value)
{
        struct ifreq ifr;

        radar->atd.ad_id = DFS_ALLOW_HW_PULSES | ATH_DIAG_IN;
        radar->atd.ad_out_data = NULL;
        radar->atd.ad_out_size = 0;
        radar->atd.ad_in_data = (void *) &value;
        radar->atd.ad_in_size = sizeof(u_int8_t);

        if(strlcpy(ifr.ifr_name, radar->atd.ad_name,sizeof(ifr.ifr_name)) >= sizeof(ifr.ifr_name))
        {
                printf("%s..Arg too long %s\n",__func__,radar->atd.ad_name);
                exit(-1);
        }

        ifr.ifr_data = (caddr_t)&radar->atd;
        if (radar_send_command(radar,
                               radar->atd.ad_name,
                               (caddr_t)&radar->atd,
                               sizeof(struct ath_diag),
                               radar->s) < 0) {
                err(1, radar->atd.ad_name);
        }
        radar->atd.ad_in_data = NULL;
        return 0;
}
#else
static int
radarInjectSequence(struct radarhandler *radar, char *fname,
                    u_int8_t sequence_idx_to_inject)
{
	printf("Feature not implemented\n");
	return 0;
}

static int
radarAllowHWPulses(struct radarhandler *radar, bool value)
{
	printf("Feature not implemented\n");
	return 0;
}
#endif /* WLAN_DFS_SYNTHETIC_RADAR */

/*
 * usage: prints radartool usage message
 */
static void usage(void)
{
    const char *msg = "\
Usage: radartool (-i <interface>) [cmd]\n\
       for cfg : radartool -n (-i <interface>) [cmd]\n\
firpwr X            set firpwr (thresh to check radar sig is gone) to X (int32)\n\
rrssi X             set radar rssi (start det) to X dB (u_int32)\n\
height X            set threshold for pulse height to X dB (u_int32)\n\
prssi               set threshold to checkif pulse is gone to X dB (u_int32)\n\
inband X            set threshold to check if pulse is inband to X (0.5 dB) (u_int32)\n\
dfstime X           set dfs test time to X secs\n\
en_relpwr_check X   enable/disable radar relative power check (AR5413 only)\n\
relpwr X            set threshold to check the relative power of radar (AR5413 only)\n\
usefir128 X         en/dis using in-band pwr measurement over 128 cycles(AR5413 only)\n\
en_block_check X    en/dis to block OFDM weak sig as radar det(AR5413 only)\n\
en_max_rrssi X      en/dis to use max rssi instead of last rssi (AR5413 only)\n\
en_relstep X        en/dis to check pulse relative step (AR5413 only)\n\
relstep X           set threshold to check relative step for pulse det(AR5413 only)\n\
maxlen X            set max length of radar signal(in 0.8us step) (AR5413 only)\n\
numdetects          get number of radar detects\n\
getnol              get NOL channel information\n\
setnol              set NOL channel information\n\
dfsdebug            set the DFS debug mask\n\
dfs_disable_radar_marking X\n\
                    set this flag so that after radar detection on a DFS chan,\n\
                    the channel is not marked as radar and is not blocked from\n\
                    being set as AP's channel. However,the radar hit chan will\n\
                    be added to NOL list.\n\
g_dfs_disable_radar_marking\n\
                    Retrieve the value of disable_radar_marking flag.\n\
usenol X            set nol to X, where X is:\n\
                    1 (default) make CSA and switch to a new channel on radar detect\n\
                    0, make CSA with next channel same as current on radar detect\n\
                    2, make CSA with next channel, switch to a new channel on radar detect\n\
                    and add the radar hit channels to NOL.\n\
                    In case of FO chipset, NOL resides in FW as well and the NOL timeout of the FW\n\
                    cannot be modified. With usenol 2 option (used only for internal testing)\n\
                    the nol timeout of the host can be configured and the channels are not\n\
                    added to FW NOL.\n\
ignorecac X         enable (X=0) or disable (X=1) CAC\n\
setnoltimeout X     set nol timeout for X secs (Default value = 1800 sec)\n\
injectSequence      Inject a synthetic sequence of pulses from a user file to DFS Module \n\
allowHWPulses       Disable/Enable HW pulses and then inject the synthetic sequence \n\
bangradar           simulate radar on entire current channel\n\
bangradar X         simulate radar at the given segment ID, where\n\
                    X is segment id(0, 1) or 0 in Pine\n\
bangradar X Y Z     simulate radar at particular frequency, where\n\
                    X is segment id(0, 1) or 0 in Pine\n\
                    Y is chirp information(0 - Non chirp, 1 - Chirp)\n\
                    Z is frequency offset(-40MHz <= Z <= 40MHz in HK,\n\
		    -80MHz <= Z <= 80MHz in Pine)\n\
                    Example:\n\
                    To simulate chirp radar on segment 1 with frequency offset -10Mhz in HK:\n\
                    radartool -i wifi0 bangradar 1 1 -10\n\
bangradar X Y Z D   simulate radar at detector ID D, where\n\
                    X is segment id(0, 1) or 0 in Pine\n\
                    Y is chirp information(0 - Non chirp, 1 - Chirp)\n\
                    Z is frequency offset(-40MHz <= Z <= 40MHz in HK,\n\
		    -80MHz <= Z <= 80MHz in Pine)\n\
                    D is detector ID (2 - Agile Detector in HK, 1 in pine)\n\
                    Example:\n\
                    To simulate radar on Agile Detector,\n\
                    radartool -i wifi0 bangradar 0 0 0 2\n\
showPreCACLists     show preCAC forest structure with current NOL and CAC status\n\
resetPreCACLists    reset pre CAC list\n\
shownol             show NOL channels\n\
shownolhistory      show NOL channel history\n\
disable             disable radar detection\n\
enable              enable radar detection in software\n\
false_rssi_thr X    set false rssi threshold to X (Default is 50)\n\
rfsat_peak_mag X    set peak magnitude to X (Default is 40)\n\
setcacvalidtime X   set CAC validity time to X secs\n\
getcacvalidtime     get CAC validity time in secs\n";

    fprintf(stderr, "%s", msg);
}

int main(int argc, char *argv[])
{
    struct radarhandler radar;
    u_int32_t temp_result = 0;
    int err;

    memset(&radar, 0, sizeof(radar));

    /*
     * Based on driver config mode (cfg80211/wext), application also runs
     * in same mode (wext/cfg80211)
     */
    radar.sock_ctx.cfg80211 = get_config_mode_type();

#if UMAC_SUPPORT_CFG80211
    /* figure out whether cfg80211 is enabled */
    if (argc > 1 && (strcmp(argv[1], "-n") == 0)) {
        if (!radar.sock_ctx.cfg80211){
            fprintf(stderr, "Invalid tag '-n' for current mode.\n");
            return -EINVAL;
        }
        radar.sock_ctx.cfg80211 = CONFIG_CFG80211;
        argc -= 1;
        argv += 1;
    }
#endif /* UMAC_SUPPORT_CFG80211 */

    err = init_socket_context(&radar.sock_ctx, RADAR_NL80211_CMD_SOCK_ID,
            RADAR_NL80211_CMD_SOCK_ID);
    if (err < 0) {
        return -1;
    }

    if (argc > 1 && strcmp(argv[1], "-i") == 0) {
        if (argc < 2) {
            fprintf(stderr, "%s: missing interface name for -i\n",
                    argv[0]);
            exit(-1);
        }
        if (strlcpy(radar.atd.ad_name, argv[2], sizeof(radar.atd.ad_name)) >=
                sizeof(radar.atd.ad_name)) {
            printf("%s..Arg too long %s\n",__func__,argv[2]);
            exit(-1);
        }
        argc -= 2;
        argv += 2;
    } else
        if (strlcpy(radar.atd.ad_name, ATH_DEFAULT, sizeof(radar.atd.ad_name)) >=
                sizeof (radar.atd.ad_name)) {
            printf("%s..Arg too long %s\n",__func__,ATH_DEFAULT);
            exit(-1);
        }

    /*
     * For strtoul():
     * A base of '0' means "interpret as either base 10 or
     * base 16, depending upon the string prefix".
     */
    if (argc >= 2) {
        if(streq(argv[1], "firpwr")) {
            radarset(&radar, DFS_PARAM_FIRPWR, (u_int32_t) atoi(argv[2]));
        } else if (streq(argv[1], "rrssi")) {
            radarset(&radar, DFS_PARAM_RRSSI, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "height")) {
            radarset(&radar, DFS_PARAM_HEIGHT, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "prssi")) {
            radarset(&radar, DFS_PARAM_PRSSI, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "inband")) {
            radarset(&radar, DFS_PARAM_INBAND, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "dfstime")) {
            handle_radar(&radar, DFS_MUTE_TIME | ATH_DIAG_IN,
                    strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "usenol")) {
            handle_radar(&radar, DFS_SET_USENOL | ATH_DIAG_IN,
                    atoi(argv[2]), 1);
        } else if (streq(argv[1], "dfsdebug")) {
            handle_radar(&radar, DFS_SET_DEBUG_LEVEL | ATH_DIAG_IN,
                    (u_int32_t) strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "ignorecac")) {
            handle_radar(&radar, DFS_IGNORE_CAC | ATH_DIAG_IN,
                    (u_int32_t) strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "setnoltimeout")) {
            handle_radar(&radar, DFS_SET_NOL_TIMEOUT | ATH_DIAG_IN,
                    (u_int32_t) strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "fft")) {
            handle_radar(&radar, DFS_ENABLE_FFT | ATH_DIAG_DYN,
                    temp_result, 0);
        } else if (streq(argv[1], "nofft")) {
            handle_radar(&radar, DFS_DISABLE_FFT | ATH_DIAG_DYN,
                    temp_result, 0);
        } else if (streq(argv[1], "allowHWPulses")) {
                radarAllowHWPulses(&radar,atoi(argv[2]));
        } else if (streq(argv[1], "injectSequence")) {
                radarInjectSequence(&radar, argv[2], (u_int8_t) strtoul(argv[3], NULL, 0));
        } else if (streq(argv[1], "bangradar")) {
            if (argc == 2)
            {
                /* This is without any argument "bangradar"
                 * This will add all the subchannels of the current channel
                 */
                radarBangradar(&radar, DFS_BANGRADAR_FOR_ALL_SUBCHANS, 0, 0, 0, 0);
            } else if (argc == 3) {
                /* This is with segid argument "bangradar <segid>"
                 * This will add all subchannels of the given segment
                 */
                radarBangradar(&radar, DFS_BANGRADAR_FOR_ALL_SUBCHANS_OF_SEGID,
                    strtoul(argv[2], NULL, 0), 0, 0, 0);
            } else if (argc == 5) {
                /* This is with segid, chirp/nonChirp and freq offset argument
                 * "bangradar <segid> <chirp/nonChirp> <freq_offset>"
                 * This will add specific subchannels based on the arguments
                 */
                radarBangradar(&radar, DFS_BANGRADAR_FOR_SPECIFIC_SUBCHANS,
                    strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0),
                    strtol(argv[4], NULL, 0), 0);
            } else if (argc == 6) {
                /* This is with segid, chirp/nonChirp freq offset and
                 * detector ID argument.
                 * "bangradar <segid><chirp/nonChirp><freq_offset><detectorID>"
                 * This will add channels configured on given detector ID.
                 */
	    	radarBangradar(&radar, DFS_BANGRADAR_FOR_SPECIFIC_SUBCHANS,
		    strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0),
		    strtol(argv[4], NULL, 0), strtoul(argv[5], NULL, 0));
	    } else {
                fprintf(stderr, "Invalid Number of arguments for Bangradar\n");
		return -EINVAL;
            }
#if ATH_SUPPORT_ZERO_CAC_DFS
        } else if (streq(argv[1], "showPreCACLists")) {
            handle_radar(&radar, DFS_SHOW_PRECAC_LISTS | ATH_DIAG_DYN,
                    temp_result, 0);
        } else if (streq(argv[1], "resetPreCACLists")) {
            handle_radar(&radar, DFS_RESET_PRECAC_LISTS | ATH_DIAG_DYN,
                    temp_result, 0);
#endif
        } else if (streq(argv[1], "shownol")) {
            handle_radar(&radar, DFS_SHOW_NOL | ATH_DIAG_DYN,
                    temp_result, 0);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        } else if (streq(argv[1], "shownolhistory")) {
            handle_radar(&radar, DFS_SHOW_NOLHISTORY | ATH_DIAG_DYN,
                    temp_result, 0);
#endif
        } else if (streq(argv[1], "disable")) {
            handle_radar(&radar, DFS_DISABLE_DETECT | ATH_DIAG_DYN,
                    temp_result, 0);
        } else if (streq(argv[1], "enable")) {
            handle_radar(&radar, DFS_ENABLE_DETECT | ATH_DIAG_DYN,
                    temp_result, 0);
        } else if (streq(argv[1], "dfs_disable_radar_marking")) {
            handle_radar(&radar, DFS_SET_DISABLE_RADAR_MARKING | ATH_DIAG_IN,
                         (uint32_t) strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "g_dfs_disable_radar_marking")) {
            printf("Disable Radar Marking : %d\n",
                   handle_radar(&radar, DFS_GET_DISABLE_RADAR_MARKING |
                                ATH_DIAG_DYN, temp_result, 0));
        } else if (streq(argv[1], "numdetects")) {
            printf("Radar: detected %d radars\n",
                    handle_radar(&radar, DFS_RADARDETECTS | ATH_DIAG_DYN,
                        temp_result, 0));
        } else if (streq(argv[1], "getnol")){
            radarGetNol(&radar, argv[2]);
        } else if (streq(argv[1], "setnol")) {
            radarSetNol(&radar, argv[2]);
        } else if (streq(argv[1],"-h")) {
            usage();
        /* Following are valid for 5413 only */
        } else if (streq(argv[1], "relpwr")) {
            radarset(&radar, DFS_PARAM_RELPWR, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "relstep")) {
            radarset(&radar, DFS_PARAM_RELSTEP, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "maxlen")) {
            radarset(&radar, DFS_PARAM_MAXLEN, strtoul(argv[2], NULL, 0));
        } else if (streq(argv[1], "false_rssi_thr")) {
            handle_radar(&radar, DFS_SET_FALSE_RSSI_THRES | ATH_DIAG_IN,
                    (u_int32_t) strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "rfsat_peak_mag")) {
            handle_radar(&radar, DFS_SET_PEAK_MAG | ATH_DIAG_IN,
                    (u_int32_t) strtoul(argv[2], NULL, 0), 1);
        } else if (streq(argv[1], "getcacvalidtime")) {
            printf(" dfstime : %d\n", handle_radar(&radar,
                        DFS_GET_CAC_VALID_TIME | ATH_DIAG_DYN, temp_result, 0));
        } else if (streq(argv[1], "setcacvalidtime")) {
            handle_radar(&radar, DFS_SET_CAC_VALID_TIME | ATH_DIAG_IN,
                    (u_int32_t) strtoul(argv[2], NULL, 0), 1);
        }
    } else if (argc == 1) {
        struct dfs_ioctl_params pe = {0};
        u_int32_t nol;
        nol = handle_radar(&radar, DFS_GET_USENOL | ATH_DIAG_DYN,
                temp_result, 0);

        /*
         *      channel switch announcement (CSA). The AP does
         *      the following on radar detect:
         *      nol = 0, use CSA, but new channel is same as old channel
         *      nol = 1, use CSA and switch to new channel (default)
	 *      nol = 2, make CSA with next channel, switch to a new channel
	 *      on radar detect and add the radar hit channels to NOL.
	 *      In case of FO chipset, NOL resides in FW as well and the NOL
	 *      timeout of the FW cannot be modified. With usenol 2 option
	 *      (used only for internal testing) the nol timeout of the host
	 *      can be configured and the channels are not added to FW NOL.
	 */

        printf ("Radar;\nUse NOL: %s\n",(nol==1) ? "yes" : "no");
        if (nol >= 2)
            printf ("No Channel Switch announcement\n");


        radarGetThresholds(&radar, &pe);
        printf ("Firpwr (thresh to see if radar sig is gone):  %d\n",pe.dfs_firpwr);
        printf ("Radar Rssi (thresh to start radar det in dB): %u\n",pe.dfs_rrssi);
        printf ("Height (thresh for pulse height (dB):         %u\n",pe.dfs_height);
        printf ("Pulse rssi (thresh if pulse is gone in dB):   %u\n",pe.dfs_prssi);
        printf ("Inband (thresh if pulse is inband (in 0.5dB): %u\n",pe.dfs_inband);
        /* Following are valid for 5413 only */
        if (pe.dfs_relpwr & DFS_IOCTL_PARAM_ENABLE)
            printf ("Relative power check, thresh in 0.5dB steps: %u\n", pe.dfs_relpwr & ~DFS_IOCTL_PARAM_ENABLE);
        else
            printf ("Relative power check disabled\n");
        if (pe.dfs_relstep & DFS_IOCTL_PARAM_ENABLE)
            printf ("Relative step thresh in 0.5dB steps: %u\n", pe.dfs_relstep & ~DFS_IOCTL_PARAM_ENABLE);
        else
            printf ("Relative step for pulse detection disabled\n");                
            printf ("Max length of radar sig in 0.8us units: %u\n",pe.dfs_maxlen);
    } else {
        usage ();
    }
    destroy_socket_context(&radar.sock_ctx);
    return 0;
}
