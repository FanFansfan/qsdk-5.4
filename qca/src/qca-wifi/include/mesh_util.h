/*
 * Copyright (c) 2014, 2017, 2019-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __MESH_UTIL_H__
#define __MESH_UTIL_H__
#if MESH_MODE_SUPPORT
#define MESH_BYTE_MASK 0xFF
#define MESH_NIBBLE_MASK 0xF
#define MESH_DBG_MCS_OFFSET 0
#define MESH_DBG_NSS_OFFSET 8
#define MESH_DBG_PRAMBLE_OFFSET 12
#define MESH_DBG_RETRIES_OFFSET 16
#define MESH_DBG_KEYIX_OFFSET 20
#define MESH_DBG_FLAGS_OFFSET 24

#define MESH_DBG_HDR 0x000f0004

struct mesh_params {
	u_int32_t mhdr;
	u_int32_t mdbg;
	u_int8_t mhdr_len;
};

static inline int
add_mesh_meta_hdr(qdf_nbuf_t nbuf, struct mesh_params *params)
{
	struct meta_hdr_s *mhdr;
	u_int32_t hdrsize;
	u_int32_t dbg_mhdr;

	dbg_mhdr = params->mhdr ? params->mhdr : MESH_DBG_HDR;
	hdrsize = params->mhdr_len;
	nbuf->priority = (params->mdbg >> 16) & 0x7;

	if (qdf_nbuf_push_head(nbuf, hdrsize) == NULL) {
		return -1;
	}
	qdf_mem_set(qdf_nbuf_data(nbuf), hdrsize, 0);
	mhdr = (struct meta_hdr_s *) qdf_nbuf_data(nbuf);

	mhdr->power = 0xff;
	mhdr->rate_info[0].mcs = (dbg_mhdr >> MESH_DBG_MCS_OFFSET) & MESH_BYTE_MASK;
	mhdr->rate_info[0].nss = (dbg_mhdr >> MESH_DBG_NSS_OFFSET) & MESH_NIBBLE_MASK;
	mhdr->rate_info[0].preamble_type = (dbg_mhdr >> MESH_DBG_PRAMBLE_OFFSET) & MESH_NIBBLE_MASK;
	mhdr->rate_info[0].max_tries = (dbg_mhdr >> MESH_DBG_RETRIES_OFFSET) & MESH_NIBBLE_MASK;
	mhdr->retries = (dbg_mhdr >> MESH_DBG_RETRIES_OFFSET) & MESH_NIBBLE_MASK;
	mhdr->keyix = (dbg_mhdr >> MESH_DBG_KEYIX_OFFSET) & MESH_NIBBLE_MASK;
	mhdr->flags = (dbg_mhdr >> MESH_DBG_FLAGS_OFFSET) & MESH_BYTE_MASK;
	params->mhdr &= ~(METAHDR_FLAG_INFO_UPDATED << MESH_DBG_FLAGS_OFFSET);

	return 0;
}
#endif /* MESH_MODE_SUPPORT */
#endif /* __MESH_UTIL_H__ */
