/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * @@-COPYRIGHT-END-@@
 */
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <netinet/ether.h>
#include <string.h>
#include "apac_map.h"
#include "wlanif_cmn.h"
#include "apac_priv.h"
#ifdef SON_MEMORY_DEBUG

#include "qca-son-mem-debug.h"
#undef QCA_MOD_INPUT
#define QCA_MOD_INPUT QCA_MOD_WSPLCD
#include "son-mem-debug.h"

#endif /* SON_MEMORY_DEBUG */
extern struct wlanif_config *wlanIfWd;

/**
 * @brief Convert a string to an unsigned integer, performing proper error
 *        checking.
 *
 * @param [in] buf  the string to convert
 * @param [in] base  the base to use for the conversion
 * @param [in] paramName  the name of the parameter to use in any error logs
 * @param [in] line  the line number to use in any error logs
 * @param [out] val  the converted value on success
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseInt(const char *buf, int base, const char *paramName,
                                      int line, unsigned long *val) {
    char *endptr;

    errno = 0;
    *val = strtoul(buf, &endptr, base);
    if (errno != 0 || *endptr != '\0') {
        dprintf(MSG_ERROR, "%s: Failed to parse %s '%s' on line %d\n",
                __func__, paramName, buf, line);
        return APAC_FALSE;
    }

    return APAC_TRUE;
}

/**
 * @brief Parse and store the settings for a single SSID.
 *
 * This captures the security settings for the SSID, along with whether it is
 * acting as backhaul, fronthaul, or both.
 *
 * @param [in] buf  the portion of the line to parse
 * @param [in] line  the line number (for use in error messages)
 * @param [out] eProfile  the entry to populate
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseAndStoreEProfile(const char *buf, int line,
                                                   apacMapEProfile_t *eProfile) {
    char tag[MAX_SSID_LEN];
    char psk[MAX_PASSPHRASE_LEN+1];
    int len = 0;
    const char *pos = buf;
    unsigned long val;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract SSID on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    eProfile->ssid = strdup(tag);
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract auth mode on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 16, "auth mode", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->auth = val;
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract encryption mode on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 16, "encryption mode", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->encr = val;
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', psk, MAX_PASSPHRASE_LEN);
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract PSK on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    eProfile->nw_key = strdup(psk);
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract backhaul flag on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "backhaul flag", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->isBackhaul = val;
    pos += len + 1;

    if (strlen(pos) == 1) {
        len = apac_atf_config_line_getparam(pos, 0, tag, sizeof(tag));
    } else {
        len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    }
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract fronthaul flag on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "fronthaul flag", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->isFronthaul = val;
    pos += len + 1;
    /// Return when profile is extracted for mapR1
    if (strlen(pos) == 0) {
        return APAC_TRUE;
    }

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (!strncasecmp(tag, "b5", strlen("b5"))) {
        goto parseTLV;
    }

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract MAP profile 1 bSTAAssocDisallowed on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "Profile-1 STA Assoc DisAllowed", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->map1bSTAAssocDisallowed = val;
    pos += len + 1;

    if (strlen(pos) == 1) {
        len = apac_atf_config_line_getparam(pos, 0, tag, sizeof(tag));
    } else {
        len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    }
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract MAP profile 2 bSTAAssocDisallowed on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "Profile-2 STA Assoc DisAllowed", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->map2bSTAAssocDisallowed = val;
    pos += len + 1;
    /// Return when profile is extracted for mapR1
    if (strlen(pos) == 0) {
        return APAC_TRUE;
    }

parseTLV:
    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (strncasecmp(tag, "b5", strlen("b5"))) {
        dprintf(MSG_ERROR, "%s: Could not extract TLV Type B5 on line %d\n", __func__, line);
        return APAC_FALSE;
    }
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract TLV Value for B5 on line %d\n", __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "Primary VLAN ID", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->primaryVlanID = val;
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract TLV Value for B5 on line %d\n", __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "PCP", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->pcp = val;
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (strncasecmp(tag, "b6", strlen("b5"))) {
        dprintf(MSG_ERROR, "%s: Could not extract TLV Type B6 on line %d\n", __func__, line);
        return APAC_FALSE;
    }
    pos += len + 1;

    len = apac_atf_config_line_getparam(pos, 0, tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract TLV Value for B6 on line %d\n", __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "VLAN ID", line, &val)) {
        return APAC_FALSE;
    }

    eProfile->vlanID = val;
    pos += len + 1;

    return APAC_TRUE;
}

/**
 * @brief Handle a line for the AL-specific encryption profile file format.
 *
 * @param [in] buf  the line read from the config file
 * @param [in] line  the line number (for use in error messages)
 * @param [out] eProfileMatcher  the entry to populate
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseAndStoreALSpecificEProfile(
    const char *buf, int line, apacMapEProfileMatcher_t *eProfileMatcher) {
    apacMapEProfile_t *eProfile = NULL;
    char tag[MAX_SSID_LEN];
    int len = 0;
    const char *pos = buf;

    eProfileMatcher->matcherType = APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC;
    eProfileMatcher->terminateMatching = APAC_FALSE;

    eProfile = &eProfileMatcher->typeParams.alParams.eprofile;

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract AL ID on line %d\n",
                __func__, line);
        return APAC_FALSE;
    } else {
        eProfileMatcher->typeParams.alParams.alId = strdup(tag);
        pos += len + 1;
    }

    len = apac_atf_config_line_getparam(pos,',',tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract operating class on line %d\n",
                __func__, line);
        return APAC_FALSE;
    } else {
        eProfileMatcher->typeParams.alParams.opclass = strdup(tag);
        pos += len + 1;
    }

    return apacHyfiMapParseAndStoreEProfile(pos, line, eProfile);
}

/**
 * @brief Parse a line that specifies the settings for a single SSID.
 *
 * @param [inout] map  the structure into which to place the associated data
 * @param [in] buf  the line read from the config file
 * @param [in] line  the line number (for use in error messages)
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseAndStoreGenericEProfileSSID(apacMapData_t *map,
                                                              const char *buf, int line) {
    char tag[MAX_SSID_LEN];
    size_t len;
    const char *pos = buf;
    const char *ssidKey = NULL;

    apacMapEProfile_t *eProfile = NULL;

    while (isspace(*pos)) {
        pos++;
    }

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR, "%s: Could not extract SSID key on line %d\n", __func__, line);
        return APAC_FALSE;
    }

    ssidKey = strdup(tag);
    if (!ssidKey) {
        dprintf(MSG_ERROR, "%s: Failed to copy SSID key\n", __func__);
        return APAC_FALSE;
    }

    pos += len + 1;

    do {
        // Place this into the SSID table. We assume the file contains no
        // duplicates.
        if (map->ssidCnt == sizeof(map->eProfileSSID) / sizeof(map->eProfileSSID[0])) {
            dprintf(MSG_ERROR, "%s: Too many SSIDs specified (max=%u)\n", __func__,
                   map->ssidCnt);
            break;
        }

        eProfile = &map->eProfileSSID[map->ssidCnt].eprofile;
        if (apacHyfiMapParseAndStoreEProfile(pos, line, eProfile)) {
            dprintf(MSG_DEBUG, "%s: Storing SSID key '%s' at index %u\n", __func__,
                    ssidKey, map->ssidCnt);

            map->eProfileSSID[map->ssidCnt].ssidKey = ssidKey;
            map->ssidCnt++;
            return APAC_TRUE;
        }

    } while (0);

    // If we reach here, there was an error. Perform cleanup.
    free((char *)ssidKey);
    return APAC_FALSE;
}

/**
 * @brief Search for the SSID key in the table, returning its index if found.
 *
 * @param [in] map  the structure storing the SSIDs
 * @param [in] key  the SSID key to lookup
 *
 * @return the index at which the SSID key is stored, or -1 if not found
 */
static ssize_t apacHyfiMapLookupSSIDKey(apacMapData_t *map, const char *key) {
    u8 i;
    for (i = 0; i < map->ssidCnt; ++i) {
        if (strcmp(map->eProfileSSID[i].ssidKey, key) == 0) {
            return i;
        }
    }

    // not found
    return -1;
}

/**
 * @brief Create a single generic encryption profile policy from the template.
 *
 * @param [in] map  the structure storing the encryption profiles
 * @param [in] ssidKey  the key of the SSID to use for the profile to be stored
 * @param [in] matcherTemplate  the template matching parameters to use for
 *                              this profile matcher
 * @param [in] terminateMatching  whether to mark this entry as terminating the
 *                                matches
 * @param [inout] index  the next index to store
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapStoreGenericEProfilePolicy(
    apacMapData_t *map, const char *ssidKey,
    struct apacMapEProfileMatcherGenericParams_t *matcherTemplate,
    apacBool_e terminateMatching, int *index) {
    int RadioIdx;
    // Find the matching SSID entry
    int ssidIndex = apacHyfiMapLookupSSIDKey(map, ssidKey);
    if (ssidIndex < 0) {
        dprintf(MSG_ERROR, "%s: Unknown SSID key '%s' specified\n", __func__, ssidKey);
        return APAC_FALSE;
    }

    if (*index == APAC_MAXNUM_NTWK_NODES) {
        dprintf(MSG_ERROR,
                "%s: Cannot store all encryption profiles; only %d supported\n", __func__,
                APAC_MAXNUM_NTWK_NODES);
        return APAC_FALSE;
    }

    // Finalize the matcher entry and store it in the complete array
    matcherTemplate->ssidIndex = ssidIndex;
    map->eProfileMatcher[*index].matcherType = APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC;
    map->eProfileMatcher[*index].terminateMatching = terminateMatching;

    RadioIdx = apacMapGetRadioIdxByOpclass(map, matcherTemplate->numOpClassRanges,
            matcherTemplate->opClassRanges[0].minOpClass, matcherTemplate->opClassRanges[0].maxOpClass);
    matcherTemplate->mibVAPIndex = apacMibGetVapIdxbySSID(RadioIdx,
            map->eProfileSSID[ssidIndex].eprofile.ssid);

    map->eProfileMatcher[*index].typeParams.genericParams = *matcherTemplate;

    (*index)++;
    return APAC_TRUE;
}

/**
 * @brief Parse a line that specifies the matching parameters for SSIDs
 *        to instantiate.
 * @param [inout] map  the structure into which to place the associated data
 * @param [in] buf  the line read from the config file
 * @param [in] line  the line number (for use in error messages)
 * @param [inout] index  the next available encryption profile matcher index;
 *                       this will be updated for each profile stored
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseAndStoreGenericEProfilePolicy(apacMapData_t *map,
                                                                const char *buf, int line,
                                                                int *index) {
    char tag[MAX_SSID_LEN];
    int len;
    const char *pos = buf;
    unsigned long val;
    u8 i;

    struct apacMapEProfileMatcherGenericParams_t matcherTemplate;

    while (isspace(*pos)) {
        pos++;
    }

    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    if (len <= 0) {
        dprintf(MSG_ERROR,
                "%s: Could not extract number of operating class ranges on line %d\n",
                __func__, line);
        return APAC_FALSE;
    }

    if (!apacHyfiMapParseInt(tag, 0, "number of operating class ranges", line, &val)) {
        return APAC_FALSE;
    }

    matcherTemplate.numOpClassRanges = val;
    pos += len + 1;

    for (i = 0; i < matcherTemplate.numOpClassRanges; ++i) {
        // Min operating class parameter
        len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
        if (len <= 0) {
            dprintf(MSG_ERROR,
                    "%s: Could not extract min operating class on line %d\n",
                    __func__, line);
            return APAC_FALSE;
        }

        if (!apacHyfiMapParseInt(tag, 0, "min operating class", line, &val)) {
            return APAC_FALSE;
        }

        matcherTemplate.opClassRanges[i].minOpClass = val;
        pos += len + 1;

        // Max operating class parameter
        len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
        if (len <= 0) {
            dprintf(MSG_ERROR,
                    "%s: Could not extract max operating class on line %d\n",
                    __func__, line);
            return APAC_FALSE;
        }

        if (!apacHyfiMapParseInt(tag, 0, "max operating class", line, &val)) {
            return APAC_FALSE;
        }

        matcherTemplate.opClassRanges[i].maxOpClass = val;
        pos += len + 1;
    }

    // Now keep extracting SSIDs until we run out of space or find a
    // non-matching one
    len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    while (len > 0) {  // more to follow
        if (!apacHyfiMapStoreGenericEProfilePolicy(
                map, tag, &matcherTemplate, APAC_FALSE /* terminateMatching */, index)) {
            return APAC_FALSE;
        }

        pos += len + 1;
        len = apac_atf_config_line_getparam(pos, ',', tag, sizeof(tag));
    }

    // Last entry
    return apacHyfiMapStoreGenericEProfilePolicy(
        map, pos, &matcherTemplate, APAC_TRUE /* terminateMatching */, index);
}

/**
 * @brief Handle a line for the generic encryption profile file format.
 *
 * @param [inout] map  the structure into which to place the associated data
 * @param [in] buf  the line read from the config file
 * @param [in] line  the line number (for use in error messages)
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseAndStoreGenericEProfile(apacMapData_t *map,
                                                          const char *buf, int line,
                                                          int *index) {
    // First determine the type of the line
    const char *ssidTag = "SSID:";
    const char *policyTag = "Generic-Policy:";
    if (strncmp(buf, ssidTag, strlen(ssidTag)) == 0) {
        return apacHyfiMapParseAndStoreGenericEProfileSSID(map, buf + strlen(ssidTag),
                                                           line);
    } else if (strncmp(buf, policyTag, strlen(policyTag)) == 0) {
        return apacHyfiMapParseAndStoreGenericEProfilePolicy(map, buf + strlen(policyTag),
                                                             line, index);
    } else {
        dprintf(MSG_ERROR, "%s: Unexpected line: '%s'\n", __func__, buf);
        return APAC_FALSE;
    }
}

int apacHyfiMapStoreRadioChannel(apacMapData_t *map)
{
    apacHyfi20Data_t *hyfi20;
    apacHyfi20IF_t  *hif;
    int i=0,len;

    apacHyfi20TRACE();
    hyfi20 = MAPToHYFI20(map);
    hif=hyfi20->hyif;
    len=strlen("wifi0");

    while(i < APAC_MAXNUM_HYIF && hif[i].valid) {
        if(strncmp("wifi0",hif[i].radioName,len)==0 && hif[i].channel!=0) {
            map->CurrentRadioOpChannel[0] = hif[i].channel;
        } else if (strncmp("wifi1",hif[i].radioName,len)==0 && hif[i].channel!=0) {
            map->CurrentRadioOpChannel[1] = hif[i].channel;
        } else if (strncmp("wifi2",hif[i].radioName,len)==0 && hif[i].channel!=0) {
            map->CurrentRadioOpChannel[2] = hif[i].channel;
        }
        i++;
    }
    dprintf(MSG_DEBUG,"%s: CurrentRadioOpChannel: wifi0:%d wifi1:%d wifi2:%d\n",__func__,
            map->CurrentRadioOpChannel[0],
            map->CurrentRadioOpChannel[1],
            map->CurrentRadioOpChannel[2]);
    return 0;
}

/**
 * @brief Resolve the encryption profiles from the config file.
 *
 * @param [inout] map  the structure into which to place the encryption profiles
 * @param [in] matcherType  the format of the profiles within the file
 * @param [in] fname  the name of the file to read
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
static apacBool_e apacHyfiMapParseAndStoreConfig(apacMapData_t *map,
                                                 apacMapEProfileMatcherType_e matcherType,
                                                 const char *fname) {
    FILE *f = NULL;
    char buf[256] = {0};
    int index = 0;
    int line = 1;
    int errors = 0;
    apacMapEProfileMatcher_t *eProfileMatcher = NULL;

    apacHyfi20TRACE();

    apacHyfiMapStoreRadioChannel(map); //Store the current op-channel of each radio
    int lock_fd = open(APAC_LOCK_FILE_PATH, O_RDONLY);
    if (lock_fd < 0) {
        dprintf(MSG_ERROR, "Failed to open lock file %s\n", APAC_LOCK_FILE_PATH);
        return APAC_FALSE;
    }

    if (flock(lock_fd, LOCK_EX) == -1) {
        dprintf(MSG_ERROR, "Failed to flock lock file %s\n", APAC_LOCK_FILE_PATH);
        close(lock_fd);
        return APAC_FALSE;
    }

    dprintf(MSG_DEBUG, "Reading Map 1.0 configuration file %s ...\n", fname);

    f = fopen(fname, "r");

    if (f == NULL) {
        dprintf(MSG_ERROR,
                "Could not open configuration file '%s' for reading.\n",
                fname);
        return APAC_FALSE;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
        // remove the trailing carriage return and/or newline
        buf[strcspn(buf, "\r\n")] = '\0';

        if (strlen(buf) == 0) {
            continue;
        }
        eProfileMatcher = &map->eProfileMatcher[index];

        if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC == g_map_cfg_file_format) {
            if (!apacHyfiMapParseAndStoreALSpecificEProfile(buf, line, eProfileMatcher)) {
                errors++;
                break;
            }

            index++;
        } else if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC == g_map_cfg_file_format) {
            if (!apacHyfiMapParseAndStoreGenericEProfile(map, buf, line, &index)) {
                errors++;
                break;
            }
        } else {
            dprintf(MSG_ERROR, "%s: Unexpected encryption profile matcher type: %d\n",
                    __func__, g_map_cfg_file_format);
            return APAC_FALSE;
        }

        if (index >= APAC_MAXNUM_NTWK_NODES) {
            dprintf(MSG_ERROR,
                    "%s: Cannot store all encryption profiles; only %d supported\n",
                    __func__, APAC_MAXNUM_NTWK_NODES);
            break;
        }

        line++;
        memset(buf, 0x00, sizeof(buf));
    }

    if (flock(lock_fd, LOCK_UN) == 1) {
        dprintf(MSG_ERROR, "Failed to unlock file %s\n", APAC_LOCK_FILE_PATH);
        errors++;
    }

    map->eProfileCnt = index;
    dprintf(MSG_INFO, "%s: Read %u MAP encryption profiles\n", __func__,
            map->eProfileCnt);
    close(lock_fd);
    fclose(f);

    if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC == g_map_cfg_file_format) {
        if (map->eProfileCnt == 0 && errors == 0) {
            dprintf(MSG_INFO, "%s: No Profiles found in configuration file '%s', Tear Down \n ",
                    __func__, fname);
            return APAC_TRUE;
        }
    }

    if (errors) {
        dprintf(MSG_ERROR,
                "%s: %d errors found in configuration file '%s'\n",
                __func__, errors, fname);
    }

    return (errors == 0);
}

apacBool_e apacHyfiMapDInit(apacMapData_t *map) {
    u8 i = 0;
    apacMapEProfileMatcher_t *eProfileMatcher = NULL;
    apacMapEProfile_t *eProfile = NULL;

    apacHyfi20TRACE();

    for (i = 0; i < map->eProfileCnt; i++) {
        eProfileMatcher = &map->eProfileMatcher[i];
        if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC ==
            eProfileMatcher->matcherType) {
            eProfile = &eProfileMatcher->typeParams.alParams.eprofile;

            free((char *)eProfileMatcher->typeParams.alParams.alId);
            free((char *)eProfileMatcher->typeParams.alParams.opclass);

            free((char *)eProfile->ssid);
            free((char *)eProfile->nw_key);
        }
    }
    map->eProfileCnt = 0;

    for (i = 0; i < map->ssidCnt; i++) {
        free((char *) map->eProfileSSID[i].ssidKey);
        free((char *) map->eProfileSSID[i].eprofile.ssid);
        free((char *) map->eProfileSSID[i].eprofile.nw_key);
    }
    map->ssidCnt = 0;

    return APAC_TRUE;
}

int convertStrToArray(char *str, char *array, int length)
{
    int i = 0;
    char *token;

    if (!str || !array)
       return 0;

    char *rest = (char *)str;
    while ((token = strtok_r(rest, " ", &rest))) {
        token[strcspn(token, "\r\n")] = 0;
        if( i < length ) {
            int num = (int)strtol(token, NULL, 16);
            array[i++] = num;
        }
    }
    return i;
}

/**
 * @brief read Basic capability from conf file that matches key and
 * returns the length of array which contains hex bytes
 *
 * @param [in] filename name of conf file [wsplcd-lan.conf]
 *
 * @param [out] lineptr poniter to array of hex bytes. Caller off this
 *              function needs to release this memeory.
 *
 * @param [in] key name of key in conf file (key=value)
 *
 * @return length of the bytes array
 */
int readLineFromFile(char *filename, char **lineptr, char *key)
{
    FILE * fp = fopen(filename, "r");
    char *line = NULL;
    char  *linerslt = NULL;
    size_t length = 0;
    ssize_t read = 0;
    int bytesCnt = 0;

    if (!fp) {
        perror("basic capability file: ");
        return -1;
    }
    fseek(fp, 0L, SEEK_SET);
    while ((read = getline(&line, &length, fp)) != -1) {
        if(!strncmp(key, line, strlen(key))) {
            linerslt = line + strlen(key)+1;
            break;
        }
    }
    char *basic = malloc(read);
    bytesCnt = convertStrToArray(linerslt, basic, read);
    *lineptr = basic;

    if(line)
        free(line);
    fclose(fp);
    return bytesCnt;
}

int apacGetPIFMapCap(apacHyfi20Data_t *pData) {
    apacPifMap_t *pIFMapData = NULL;
    int32_t Sock;
    struct iwreq iwr;
    struct ifreq ifr;
    struct ieee80211req_athdbg req = {0};
    struct mesh_dbg_req_t mesh_req = {0};
    int j, i = 0, k = 0;
    apacHyfi20AP_t *pAP = &pData->ap[0];
    struct ether_addr radioAddr;

    apacHyfi20TRACE();

    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {

        if (!pAP[i].valid) {
            continue;
        }

        if (!pAP[i].ifName) {
            dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
            goto out;
        }

        dprintf(MSG_ERROR, "%s  %s \n", __func__, pAP[i].ifName);

        if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
            goto out;
        }

        if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
            dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
            goto err;
        }

        pIFMapData = &pAP[i].pIFMapData;
        strlcpy(iwr.ifr_name, pAP[i].ifName, IFNAMSIZ);
        strlcpy(ifr.ifr_name, pAP[i].radioName, IFNAMSIZ);
        iwr.u.data.pointer = (void *)&req;
        iwr.u.data.length = (sizeof(struct ieee80211req_athdbg));
        req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
        req.data.mesh_dbg_req.mesh_cmd =  MESH_MAP_RADIO_HWCAP;
        req.needs_reply = DBGREQ_REPLY_IS_REQUIRED;

        if (!wlanIfWd) {
            dprintf(MSG_ERROR, "%s - wlanif nl init failed\n", __func__);
            goto err;
        }

        if (strlen(pAP[i].ifName) &&
            getDbgreq_cfg80211(wlanIfWd->ctx, pAP[i].ifName, (void *)&req, (sizeof(struct ieee80211req_athdbg))) < 0)  {
            dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s\n", __func__, pAP[i].ifName);
            goto err;
        }
        mesh_req = (struct mesh_dbg_req_t)(req.data.mesh_dbg_req);

        if (ioctl(Sock, SIOCGIFHWADDR, &ifr) < 0) {
            goto err;
        }

        os_memcpy(radioAddr.ether_addr_octet, ifr.ifr_hwaddr.sa_data, 6);
        os_memcpy(pAP[i].radio_mac, radioAddr.ether_addr_octet, 6);

        if (pAP[i].radioName && !strlen(pAP[i].ifName)) {
            int read=0;
            char *basic = NULL; // use it for pointing to array of hex bytes
            int x = 0;
            int y = 0;
            int offset = 0;

            if(APAC_WIFI_FREQ_2 == pAP[i].freq)
                read = readLineFromFile(g_cfg_file, &basic, "2GBasic");
            else if(APAC_WIFI_FREQ_5 == pAP[i].freq || APAC_WIFI_FREQ_5_OTHER == pAP[i].freq)
                read = readLineFromFile(g_cfg_file, &basic, "5GBasic");
            if (!read || !basic) {
                if(basic)
                   free(basic); // free it if read is zero
                continue;
            }

            dprintf(MSG_INFO, "Length of basic cap bytes = %d\n", read);
            pIFMapData->apcap.hwcap.max_supported_bss = (u_int8_t)basic[0];
            pIFMapData->apcap.hwcap.num_supported_op_classes = (u_int8_t)basic[1];
            dprintf(MSG_INFO, "max_supported_bss = %02x, num_supported_op_classes = %02x\n", basic[0], basic[1]);
            offset = 2; // max_supported_bss+num_supported_op_classes

            for (x = 0; x < basic[1]; x++) {
                pIFMapData->apcap.hwcap.opclasses[x].opclass = (u_int8_t)basic[offset+0];

                pIFMapData->apcap.hwcap.opclasses[x].max_tx_pwr_dbm = (int8_t)basic[offset+1];

                pIFMapData->apcap.hwcap.opclasses[x].num_non_oper_chan = (u_int8_t)basic[offset+2];
                dprintf(MSG_INFO, "%d opclass = %02x, max_tx_pwr_dbm = %d, num_non_oper_chan = %02x\n",
                            x, basic[offset+0], (int8_t)basic[offset+1], basic[offset+2]);

                for(y = 0; y < basic[offset+2]; y++) {
                    dprintf(MSG_INFO, "non_oper_chan_num[%d] = %02x\n", y, basic[offset+3+y]);
                    pIFMapData->apcap.hwcap.opclasses[x].non_oper_chan_num[y] = (u_int8_t)basic[offset+3+y];
                }
                offset += 3+basic[offset+2];  // 3 for opclass+max_tx_pwr_dbm+num_non_oper_chan
                dprintf(MSG_INFO, "offset = %d\n", offset);
            }
            if (basic) // our responsibility to free the memory
                free(basic);
        }
        else {
            pIFMapData->apcap.hwcap.max_supported_bss = mesh_req.mesh_data.mapapcap.hwcap.max_supported_bss;
            pIFMapData->apcap.hwcap.num_supported_op_classes =
                mesh_req.mesh_data.mapapcap.hwcap.num_supported_op_classes;

	    /// Very rarely we saw this case driver is returning back
	    /// ioctl as success but operating classe as Zero
	    /// making more stringent error checks now
            if (!mesh_req.mesh_data.mapapcap.hwcap.num_supported_op_classes) goto err;

            for (k = 0; k < mesh_req.mesh_data.mapapcap.hwcap.num_supported_op_classes; k++) {
                pIFMapData->apcap.hwcap.opclasses[k].opclass =
                    mesh_req.mesh_data.mapapcap.hwcap.opclasses[k].opclass;
                pIFMapData->apcap.hwcap.opclasses[k].max_tx_pwr_dbm =
                    mesh_req.mesh_data.mapapcap.hwcap.opclasses[k].max_tx_pwr_dbm;
                pIFMapData->apcap.hwcap.opclasses[k].num_non_oper_chan =
                    mesh_req.mesh_data.mapapcap.hwcap.opclasses[k].num_non_oper_chan;

                dprintf(MSG_INFO, "Operating class  %d Txpwer %x Number of unoperable channel %d\n",
                        pIFMapData->apcap.hwcap.opclasses[k].opclass,
                        pIFMapData->apcap.hwcap.opclasses[k].max_tx_pwr_dbm,
                pIFMapData->apcap.hwcap.opclasses[k].num_non_oper_chan);

                for (j = 0; j < pIFMapData->apcap.hwcap.opclasses[k].num_non_oper_chan; j++) {
                    pIFMapData->apcap.hwcap.opclasses[k].non_oper_chan_num[j] =
                        mesh_req.mesh_data.mapapcap.hwcap.opclasses[k].non_oper_chan_num[j];
                    dprintf(MSG_INFO, "Unoperable channel list %d \n",
                            pIFMapData->apcap.hwcap.opclasses[k].non_oper_chan_num[j]);
                }
            }
        }
        close(Sock);
    }

    return 0;
err:
    close(Sock);
out:
    return -1;
}

apacBool_e apacHyfiMapInit(apacMapData_t *map) {
    apacHyfi20Data_t *hyfi20;
    apacHyfi20MapVersion_e vEnabled;

    apacHyfi20TRACE();

    hyfi20 = MAPToHYFI20(map);

    if (hyfi20->config.role != APAC_REGISTRAR) {
        dprintf(MSG_DEBUG, "%s: not registrar! nothing to do\n", __func__);
        return APAC_TRUE;
    }

    vEnabled = apacHyfiMapIsEnabled(map);

    if (vEnabled)
        return apacHyfiMapParseAndStoreConfig(map, g_map_cfg_file_format, g_map_cfg_file);
    else
        return APAC_TRUE;  // to bail out init process without MAP
}

/**
 * @brief Dump the parameters for an encryption profile.
 *
 * @param [in] prefix  the string prefix to use prior to the encryption
 *                     profile parameters
 * @param [in] eProfile  the encryption profile to dump
 */
static void apacHyfiMapConfigDumpEProfile(const char *prefix,
                                          const apacMapEProfile_t *eProfile) {
    dprintf(MSG_MSGDUMP, "%s%s,0x%04x,0x%04x,%s,%d,%d,%d,%d,%d,%d,%d\n", prefix, eProfile->ssid,
            eProfile->auth, eProfile->encr, eProfile->nw_key, eProfile->isBackhaul,
            eProfile->isFronthaul, eProfile->map1bSTAAssocDisallowed,
            eProfile->map2bSTAAssocDisallowed, eProfile->primaryVlanID, eProfile->pcp,
            eProfile->vlanID);
}

void apacHyfiMapConfigDump(const apacMapData_t *map) {
    u8 i = 0, j = 0;
    const apacMapEProfileMatcher_t *eProfileMatcher = NULL;
    const apacMapEProfile_t *eProfile = NULL;
    const struct apacMapEProfileMatcherGenericParams_t *genericParams = NULL;
    apacHyfi20Data_t *hyfi20;
    apacHyfi20TRACE();

    hyfi20 = MAPToHYFI20(map);

    if (hyfi20->config.role != APAC_REGISTRAR) {
        dprintf(MSG_ERROR, "%s, not registrar!\n", __func__);
        return;
    }

    for (i = 0; i < map->eProfileCnt; i++) {
        eProfileMatcher = &map->eProfileMatcher[i];
        dprintf(MSG_MSGDUMP, "Profile #%u type = %u terminate = %u\n", i,
                eProfileMatcher->matcherType, eProfileMatcher->terminateMatching);

        if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC ==
            eProfileMatcher->matcherType) {
            eProfile = &eProfileMatcher->typeParams.alParams.eprofile;

            dprintf(MSG_MSGDUMP, "AL-specific EProfile: %s,%s\n",
                    eProfileMatcher->typeParams.alParams.alId,
                    eProfileMatcher->typeParams.alParams.opclass);
            apacHyfiMapConfigDumpEProfile("  ", eProfile);
        } else if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC ==
                   eProfileMatcher->matcherType) {
            genericParams = &eProfileMatcher->typeParams.genericParams;
            dprintf(MSG_MSGDUMP,
                    "Generic Profile #%u: numOpClassRanges=%u terminateMatching=%u\n", i,
                    genericParams->numOpClassRanges, eProfileMatcher->terminateMatching);

            for (j = 0; j < genericParams->numOpClassRanges; ++j) {
                dprintf(
                    MSG_MSGDUMP, "  OpClassRange #%u: MinOpClass=%u MaxOpClass=%u\n", j,
                    genericParams->opClassRanges[j].minOpClass,
                    genericParams->opClassRanges[j].maxOpClass);
            }

            dprintf(MSG_MSGDUMP, "  SSID Index=%u mibVAP_index:%d\n",
                    genericParams->ssidIndex, genericParams->mibVAPIndex);
            eProfile = &map->eProfileSSID[genericParams->ssidIndex].eprofile;
            apacHyfiMapConfigDumpEProfile("  ", eProfile);
        }
    }
}

int apacMapGetRadioIdxByOpclass(apacMapData_t *map, int numOpClassRanges, int minOpClass, int maxOpClass)
{
    int i,RadioIdx=0;

    for(i=0; i < MAX_RADIO_CONFIGURATION; i++) {
        if (numOpClassRanges > 1 && map->CurrentRadioOpChannel[i] >= 36 ) { //5G Full Band
            RadioIdx = i+1;
        } else if(minOpClass >= 80 && maxOpClass <= 89) { //2G Bang
            if( map->CurrentRadioOpChannel[i] >= 1 && map->CurrentRadioOpChannel[i] <= 13 ) {
                RadioIdx = i+1;
            }
        } else if(minOpClass >= 115 && maxOpClass <= 120) { //5G low
            if( map->CurrentRadioOpChannel[i] >= 36 && map->CurrentRadioOpChannel[i] <= 64 ) {
                RadioIdx = i+1;
            }
        } else { //5G High
            if( map->CurrentRadioOpChannel[i] >= 100 ) {
                RadioIdx = i+1;
            }
        }

        if(RadioIdx > 0)
            break;
    }
    return RadioIdx;
}

int apac_map_get_mib_vap_index(apacMapData_t *map, int idx)
{
    if(!map || idx == 0xff) {
        return -1;
    }

    return map->eProfileMatcher[idx].typeParams.genericParams.mibVAPIndex;
}

apacHyfi20MapVersion_e apacHyfiMapIsEnabled(apacMapData_t *map)
{
    return map->vEnabled;
}

apacBool_e apacHyfiMapPfComplianceEnabled(apacMapData_t *map)
{
    return map->mapPfCompliant;
}

apacBool_e apacHyfiMapIsTrafficSeparationEnabled(apacMapData_t *map)
{
    return map->map2TrafficSepEnabled;
}

apacBool_e apacHyfiMapConfigServiceEnabled(apacMapData_t *map)
{
    return map->mapConfigServiceEnabled;
}

ieee1905TLV_t *ieee1905MapAddBasicRadioTLV(ieee1905TLV_t *TLV, u_int32_t *Len, u8 band,
                                           apacHyfi20Data_t *pData) {
    u_int16_t tlvLen = 0;
    u_int8_t *ptr = NULL;
    u_int16_t i = 0, j = 0;
    apacPifMap_t *pIFMapData = NULL;
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    map = HYFI20ToMAP(pData);

    TLV = ieee1905TLVGetNext(TLV);
    ieee1905TLVTypeSet(TLV, IEEE1905_TLV_TYPE_AP_RADIO_BASIC_CAP);
    ptr = ieee1905TLVValGet(TLV);

    pIFMapData = &pData->ap[band].pIFMapData;

    if (!pIFMapData) return TLV;

    os_memcpy(ptr, pData->ap[band].radio_mac, ETH_ALEN);
    tlvLen += ETH_ALEN; /* MAC addr len */
    ptr += ETH_ALEN;

    *ptr++ = map->MapConfMaxBss;  // configured value
    tlvLen++;
    *ptr++ = pIFMapData->apcap.hwcap.num_supported_op_classes;
    tlvLen++;

    for (i = 0; i < pIFMapData->apcap.hwcap.num_supported_op_classes; i++) {
        *ptr++ = pIFMapData->apcap.hwcap.opclasses[i].opclass;
        tlvLen++;
        *ptr++ = pIFMapData->apcap.hwcap.opclasses[i].max_tx_pwr_dbm;
        tlvLen++;
        *ptr++ = pIFMapData->apcap.hwcap.opclasses[i].num_non_oper_chan;
        tlvLen++;

        for (j = 0; j < pIFMapData->apcap.hwcap.opclasses[i].num_non_oper_chan; j++) {
            *ptr++ = pIFMapData->apcap.hwcap.opclasses[i].non_oper_chan_num[j];
            tlvLen++;
        }
    }

    ieee1905TLVLenSet(TLV, tlvLen, *Len);
    dprintf(MSG_INFO, "Added basic radio TLV(Enrollee) framelen %d tlvlen %d \n", *Len, tlvLen);

    printMsg((u8 *)TLV, tlvLen, MSG_DEBUG);
    return TLV;
}

ieee1905TLV_t *ieee1905MapAddRadioIdTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        struct apac_wps_session *sess)
{

    u_int8_t *ptr = NULL;
    u8 *Data = NULL;

    apacHyfi20TRACE();

    if(sess->basicRadioCapLen)
        Data = sess->basicRadioCap;
    else
        return TLV;

    ieee1905TLVTypeSet( TLV, IEEE1905_TLV_TYPE_RADIO_IDENTIFIER);
    ptr = ieee1905TLVValGet(TLV);
    os_memcpy(ptr, Data, ETH_ALEN);

    ieee1905TLVLenSet(TLV, ETH_ALEN, *Len);
    printMsg((u8 *)TLV, ETH_ALEN,MSG_MSGDUMP);

    return ieee1905TLVGetNext(TLV);
}

ieee1905TLV_t *ieee1905MapAddTrafficSeparationPolicyTLV(ieee1905TLV_t *TLV, u_int32_t *Len,
                                                        struct apac_wps_session *sess) {
    u8 i = 0, mapEprofileList[MAX_WLAN_CONFIGURATION] = {0};
    u8 eMaxBss = 0, matchCnt = 0, numSSID = 0;
    u16 primaryVlanID, pcp;
    apacHyfi20Data_t *pApacData = sess->pData;
    apacMapData_t *mapData = HYFI20ToMAP(pApacData);
    apacBool_e add8021QTLV = APAC_FALSE;
    apacBool_e addTrafficSepTLV = APAC_FALSE;
    const apacMapEProfile_t *eProfile = NULL;
    const struct apacMapEProfileMatcherGenericParams_t *genericParams = NULL;
    apacMapEProfileMatcher_t *eProfileMatcher = NULL;
    u_int8_t *ptr = NULL;
    u_int16_t tlvLen = 0;

    apacHyfi20TRACE();
    matchCnt = apac_map_get_eprofile(sess, mapEprofileList, &eMaxBss);

    for (i = 0; i < matchCnt; i++) {
        eProfileMatcher = &mapData->eProfileMatcher[mapEprofileList[i]];
        if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC == eProfileMatcher->matcherType) {
            eProfile = &eProfileMatcher->typeParams.alParams.eprofile;
        } else if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC == eProfileMatcher->matcherType) {
            genericParams = &eProfileMatcher->typeParams.genericParams;
            if (genericParams) {
                eProfile = &mapData->eProfileSSID[genericParams->ssidIndex].eprofile;
            }
        }

        if (eProfile->primaryVlanID > 0) {
            primaryVlanID = eProfile->primaryVlanID;
            pcp = eProfile->pcp;
            add8021QTLV = APAC_TRUE;
        }
        if (eProfile->vlanID > 0) {
            numSSID++;
            addTrafficSepTLV = APAC_TRUE;
        }
        if (eProfile->vlanID == 0) {
            addTrafficSepTLV = APAC_TRUE;
        }
    }

    if (add8021QTLV) {
        ieee1905TLVTypeSet(TLV, IEEE1905_TLV_TYPE_8021Q_RULES);
        ptr = ieee1905TLVValGet(TLV);
        tlvLen = 0;

        u_int16_t pVlanID = htons(primaryVlanID);
        memcpy(ptr, &pVlanID, sizeof(pVlanID));
        ptr += sizeof(pVlanID);
        tlvLen += sizeof(pVlanID);

        *ptr++ = pcp << 5;
        tlvLen++;

        ieee1905TLVLenSet(TLV, tlvLen, *Len);
        TLV = ieee1905TLVGetNext(TLV);
    }

    if (addTrafficSepTLV) {
        tlvLen = 0;
        ieee1905TLVTypeSet(TLV, IEEE1905_TLV_TRAFFIC_SEPARATON_POLICY);
        ptr = ieee1905TLVValGet(TLV);

        *ptr++ = numSSID;
        tlvLen++;

        for (i = 0; i < matchCnt; i++) {
            eProfileMatcher = &mapData->eProfileMatcher[mapEprofileList[i]];
            if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC == eProfileMatcher->matcherType) {
                eProfile = &eProfileMatcher->typeParams.alParams.eprofile;
            } else if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC == eProfileMatcher->matcherType) {
                genericParams = &eProfileMatcher->typeParams.genericParams;
                if (genericParams) {
                    eProfile = &mapData->eProfileSSID[genericParams->ssidIndex].eprofile;
                }
            }

            if (eProfile->vlanID && eProfile->vlanID != -1) {
                *ptr++ = strlen(eProfile->ssid);
                tlvLen++;

                memcpy(ptr, eProfile->ssid, strlen(eProfile->ssid));
                ptr += strlen(eProfile->ssid);
                tlvLen += strlen(eProfile->ssid);

                u_int16_t vlanID = htons(eProfile->vlanID);
                memcpy(ptr, &vlanID, sizeof(vlanID));
                ptr += sizeof(vlanID);
                tlvLen += sizeof(vlanID);
            }
        }

        ieee1905TLVLenSet(TLV, tlvLen, *Len);
        TLV = ieee1905TLVGetNext(TLV);
    }

    return TLV;
}

ieee1905TLV_t *ieee1905Map2AddApCapTLV(ieee1905TLV_t *TLV, u_int32_t *Len, u8 band,
                                       apacHyfi20Data_t *pData) {
    u_int16_t tlvLen = 0;
    u_int8_t *ptr = NULL;
    apacPifMap_t *pIFMapData = NULL;
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    map = HYFI20ToMAP(pData);

    TLV = ieee1905TLVGetNext(TLV);
    ieee1905TLVTypeSet(TLV, IEEE1905_TLV_TYPE_R2_APCAP);
    ptr = ieee1905TLVValGet(TLV);

    pIFMapData = &pData->ap[band].pIFMapData;

    if (!pIFMapData) {
        return TLV;
    }

    u_int16_t maxNumSerPriorRules = htons(map->mapMaxServicePRules);
    u_int8_t byteCounterUnits =  map->mapAgentCounterUnits;
    u_int8_t maxTotalNumVID = map->numVlanSupported;

    os_memcpy(ptr, &maxNumSerPriorRules, sizeof(maxNumSerPriorRules));
    tlvLen += sizeof(maxNumSerPriorRules);
    ptr += sizeof(maxNumSerPriorRules);

    *ptr++ = byteCounterUnits;
    tlvLen++;

    *ptr++ = maxTotalNumVID;
    tlvLen++;

    ieee1905TLVLenSet(TLV, tlvLen, *Len);
    dprintf(MSG_INFO, "Added MAPv2 AP Capability TLV(Enrollee) framelen %d tlvlen %d \n", *Len,
            tlvLen);

    printMsg((u8 *)TLV, tlvLen, MSG_DEBUG);
    return TLV;
}

ieee1905TLV_t *ieee1905Map2AddApRadioAdvancedCapTLV(ieee1905TLV_t *TLV, u_int32_t *Len, u8 band,
                                                    apacHyfi20Data_t *pData) {
    u_int16_t tlvLen = 0;
    u_int8_t *ptr = NULL;
    apacPifMap_t *pIFMapData = NULL;
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    map = HYFI20ToMAP(pData);

    TLV = ieee1905TLVGetNext(TLV);
    ieee1905TLVTypeSet(TLV, IEEE1905_TLV_TYPE_AP_RADIO_ADVANCED_CAP);
    ptr = ieee1905TLVValGet(TLV);

    pIFMapData = &pData->ap[band].pIFMapData;

    if (!pIFMapData) {
        return TLV;
    }

    os_memcpy(ptr, pData->ap[band].radio_mac, ETH_ALEN);
    tlvLen += ETH_ALEN; /* MAC addr len */
    ptr += ETH_ALEN;

    u_int8_t mapMixNotSupported = map->mapR1R2MixNotSupported;
    *ptr++ = mapMixNotSupported ? 1 << 7 : 0 << 7;
    tlvLen++;

    ieee1905TLVLenSet(TLV, tlvLen, *Len);
    dprintf(MSG_INFO, "Added MAPv2 Advanced Radio Cap TLV(Enrollee) framelen %d tlvlen %d \n", *Len,
            tlvLen);

    printMsg((u8 *)TLV, tlvLen, MSG_DEBUG);
    return TLV;
}

u8 ieee1905MapParseBasicRadioTLV(u8 *val, u_int32_t Len, u8 *maxBss, u8 minop, u8 maxop,
                                 apacBool_e checkAllOpClasses) {
    u8 *ptr = NULL;
    u_int16_t i = 0, j = 0, unoperable = 0;
    u8 opclassCnt = 0, opclass = 0;
    apacBool_e retv = APAC_FALSE;

    apacHyfi20TRACE();

    ptr = val;
    ptr += ETH_ALEN;  // skipping radio mac address.

    *maxBss = *ptr++;
    opclassCnt = *ptr++;

    dprintf(MSG_INFO, "Received M1 maxbss %d opclasscnt %d  \n", *maxBss, opclassCnt);
    dprintf(MSG_INFO, "Checking match against minop %u maxop %u checkAllOpClasses %u\n", minop,
            maxop, checkAllOpClasses);

    for (i = 0; i < opclassCnt; i++) {
        opclass = *ptr++;
        ptr++;  // skipping tx power
        unoperable = *ptr++;

        for (j = 0; j < unoperable; j++) {
            ptr++;
        }

        // Does this operating class fall within the range?
        if (opclass >= minop && opclass <= maxop) {
            retv = APAC_TRUE;
        } else {
            retv = APAC_FALSE;
        }

        if (retv || !checkAllOpClasses) {
            break;
        }
    }

    return retv;
}

u8 ieee1905MapParseTrafficSepTLV(struct apac_wps_session *sess,
                                 mapServiceTrafficSepPolicy_t *trafficSepPolicy) {
    u_int8_t *content = NULL;
    content = sess->trafficSepPolicy;

    trafficSepPolicy->numOfSSIDs = *content;
    content++;

    size_t k = 0;
    for (k = 0; k < trafficSepPolicy->numOfSSIDs; k++) {
        trafficSepPolicy->interfaceConf[k].ssidLen = *content;
        content++;

        memcpy(trafficSepPolicy->interfaceConf[k].ssid, content,
               trafficSepPolicy->interfaceConf[k].ssidLen);
        content += trafficSepPolicy->interfaceConf[k].ssidLen;

        u_int16_t vlanID;
        memcpy(&vlanID, content, sizeof(vlanID));
        trafficSepPolicy->interfaceConf[k].vlanID = ntohs(vlanID);
        content += sizeof(vlanID);
    }

    return APAC_TRUE;
}

u8 apac_map_get_configured_maxbss(struct apac_wps_session *sess)
{
    apacHyfi20Data_t *hyfi20 = NULL;
    apacMapData_t *map = NULL;

    apacHyfi20TRACE();

    hyfi20 = sess->pData;

    map = HYFI20ToMAP(hyfi20);

    return map->MapConfMaxBss;
}

/**
 * @brief Populate the parameters for instantiating a BSS from an encryption
 *        profile.
 *
 * @param [in] eProfile  the encryption profile to copy from
 * @param [out] ap  the structure into which to copy the data
 */
static void apac_map_copy_apinfo_from_eprofile(const apacMapEProfile_t *eProfile,
                                               apacHyfi20AP_t *ap) {
    ap->ssid_len = os_strlen((const char *)eProfile->ssid);
    memcpy(ap->ssid, eProfile->ssid, ap->ssid_len);
    ap->ssid[ap->ssid_len] = '\0';  // only for logging

    ap->auth = eProfile->auth;
    ap->encr = eProfile->encr;

    if (eProfile->isFronthaul) {
        ap->mapBssType = MAP_BSS_TYPE_FRONTHAUL;
    }
    if (eProfile->isBackhaul) {
        ap->mapBssType |= MAP_BSS_TYPE_BACKHAUL;
    }
    if (eProfile->map1bSTAAssocDisallowed) {
        ap->mapBssType |= MAP2_R1_BSTA_ASSOC_DISALLOW;
    }
    if (eProfile->map2bSTAAssocDisallowed) {
        ap->mapBssType |= MAP2_R2_ABOVE_BSTA_ASSOC_DISALLOW;
    }

    ap->nw_key_len = os_strlen(eProfile->nw_key);
    os_memcpy(ap->nw_key, eProfile->nw_key, ap->nw_key_len);
    ap->nw_key[ap->nw_key_len] = '\0';  // only for logging

    dprintf(MSG_MSGDUMP, "MAP SSID %s ssid len %d  \n", ap->ssid, ap->ssid_len);
    dprintf(MSG_MSGDUMP, "MAP AUTH %x  \n", ap->auth);
    dprintf(MSG_MSGDUMP, "MAP ENCR  %x \n", ap->encr);
    dprintf(MSG_MSGDUMP, "MAP nw_key %s \n", ap->nw_key);
    dprintf(MSG_MSGDUMP, "MAP nw_key len %d \n", ap->nw_key_len);
    dprintf(MSG_MSGDUMP, "MAP Fronthaul  %d  \n", ap->mapBssType & MAP_BSS_TYPE_FRONTHAUL);
    dprintf(MSG_MSGDUMP, "MAP Backhaul  %d  \n", ap->mapBssType & MAP_BSS_TYPE_BACKHAUL);
    dprintf(MSG_MSGDUMP, "MAP R1 STA Assoc DisAllowed  %d  \n",
            ap->mapBssType & MAP2_R1_BSTA_ASSOC_DISALLOW);
    dprintf(MSG_MSGDUMP, "MAP R2 STA Assoc DisAllowed  %d  \n",
            ap->mapBssType & MAP2_R2_ABOVE_BSTA_ASSOC_DISALLOW);
}

/**
 * @brief Populate the parameters for instantiating a BSS from the AL-specific
 *        encryption profile.
 *
 * @param [in] eProfileMatcher  the encryption profile to copy from
 * @param [out] ap  the structure into which to copy the data
 */
static void apac_map_copy_apinfo_al_specific(
    const apacMapEProfileMatcher_t *eProfileMatcher, apacHyfi20AP_t *ap) {
    const apacMapEProfile_t *eProfile = &eProfileMatcher->typeParams.alParams.eprofile;

    apac_map_copy_apinfo_from_eprofile(eProfile, ap);
}

/**
 * @brief Populate the parameters for instantiating a BSS from a generic
 *        encryption profile.
 *
 * @param [in] map  the overall structure for Multi-AP state
 * @param [in] eProfileMatcher  the generic encryption profile to copy from
 * @param [out] ap  the structure into which to copy the data
 */
static void apac_map_copy_apinfo_generic(
    const apacMapData_t *map, const apacMapEProfileMatcher_t *eProfileMatcher,
    apacHyfi20AP_t *ap) {
    const apacMapEProfile_t *eProfile =
        &map->eProfileSSID[eProfileMatcher->typeParams.genericParams.ssidIndex].eprofile;

    apac_map_copy_apinfo_from_eprofile(eProfile, ap);
}

apacBool_e apac_map_copy_apinfo(apacMapData_t *map, u8 index, apacHyfi20AP_t *ap) {
    apacMapEProfileMatcher_t *eProfileMatcher = NULL;

    apacHyfi20TRACE();

    if (index >= APAC_MAXNUM_NTWK_NODES && (index != 0xff)) return APAC_FALSE;

    /// Default Profile for Teardown
    if (index == 0xff) {
        ap->ssid_len = os_strlen("teardown");
        memcpy(ap->ssid, "teardown", ap->ssid_len);
        ap->ssid[ap->ssid_len] = '\0';

        ap->auth = WPS_AUTHTYPE_WPA2PSK;
        ap->encr = WPS_ENCRTYPE_AES;

        ap->mapBssType = 0;

        ap->nw_key_len = os_strlen("teardown");
        os_memcpy(ap->nw_key, "teardown", ap->nw_key_len);
        ap->nw_key[ap->nw_key_len] = '\0';
        return APAC_TRUE;
    }

    eProfileMatcher = &map->eProfileMatcher[index];
    if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC == eProfileMatcher->matcherType) {
        apac_map_copy_apinfo_al_specific(eProfileMatcher, ap);
        return APAC_TRUE;
    } else if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC == eProfileMatcher->matcherType) {
        apac_map_copy_apinfo_generic(map, eProfileMatcher, ap);
        return APAC_TRUE;
    } else {
        dprintf(MSG_ERROR, "%s: Invalid profile matcher type %u for index %u\n",
                __func__, eProfileMatcher->matcherType, index);
        return APAC_FALSE;
    }
}

static apacBool_e apac_map_match_eprofile_al_specific(
    struct apac_wps_session *sess, const apacMapEProfileMatcher_t *eProfileMatcher,
    u8 *maxBSS) {
    char buf[1024] = { 0 };
    u8 minop = 0 , maxop = 0;
    const apacMapEProfile_t *eProfile = NULL;

    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x ", sess->dest_addr[0], sess->dest_addr[1],
            sess->dest_addr[2], sess->dest_addr[3], sess->dest_addr[4], sess->dest_addr[5]);

    if (!strncasecmp(buf, eProfileMatcher->typeParams.alParams.alId,
                     IEEE80211_ADDR_LEN * 2)) {
        eProfile = &eProfileMatcher->typeParams.alParams.eprofile;

        dprintf(MSG_MSGDUMP,
                "Checking AL-specific EProfile for %s: "
                "%s,%s,%s,0x%04x,0x%04x,%s,%d,%d \n",
                buf, eProfileMatcher->typeParams.alParams.alId,
                eProfileMatcher->typeParams.alParams.opclass, eProfile->ssid,
                eProfile->auth, eProfile->encr, eProfile->nw_key,
                eProfile->isBackhaul, eProfile->isFronthaul);

        if (!strncasecmp(eProfileMatcher->typeParams.alParams.opclass, "11x",
                         3)) {
            minop = 110;
            maxop = 120;
        } else if (!strncasecmp(eProfileMatcher->typeParams.alParams.opclass,
                                "12x", 3)) {
            minop = 121;
            maxop = 130;//to compliant with WFA , ideally it should be 129
        } else if (!strncasecmp(eProfileMatcher->typeParams.alParams.opclass,
                                "8x", 2)) {
            minop = 80;
            maxop = 89;
        } else { //opclass not there
            dprintf(MSG_ERROR, "Unexpected op class %s\n",
                    eProfileMatcher->typeParams.alParams.opclass);
            return APAC_FALSE;
        }

        dprintf(MSG_DEBUG, "%s Profile based MinOp %d Maxop %d \n",__func__,
                minop, maxop);

        if (ieee1905MapParseBasicRadioTLV(sess->basicRadioCap, sess->basicRadioCapLen,
                                          maxBSS, minop, maxop,
                                          APAC_FALSE /* checkAllOperatingClasses */)) {
            return APAC_TRUE;
        }
    }

    return APAC_FALSE;
}

/**
 * @brief Attempt to match the radio capabilities against this generic
 *        encryption profile matcher.
 *
 * @param [in] sess  the information for the WPS session (where the radio
 *                   capabilities can be found)
 * @param [in] eProfileMatcher  the matcher to evaluate against the radio
 *                              capabilities
 * @param [out] maxBSS  the number of BSSes the agent indicates it can support
 *                      on the radio
 *
 * @return APAC_TRUE if there was a match; otherwise APAC_FALSE
 */
static apacBool_e apac_map_match_eprofile_generic(
    struct apac_wps_session *sess, const apacMapEProfileMatcher_t *eProfileMatcher,
    u8 *maxBSS) {
    apacBool_e match = APAC_TRUE;

    // Only is a match if all of the operating class ranges specified match
    u8 i;
    for (i = 0; i < eProfileMatcher->typeParams.genericParams.numOpClassRanges; ++i) {
        match &= ieee1905MapParseBasicRadioTLV(
            sess->basicRadioCap, sess->basicRadioCapLen, maxBSS,
            eProfileMatcher->typeParams.genericParams.opClassRanges[i].minOpClass,
            eProfileMatcher->typeParams.genericParams.opClassRanges[i].maxOpClass,
            APAC_TRUE /* checkAllOperatingClasses */);
    }

    return match;
}

/**
 * @brief Find the matching encryption profiles for the given radio based on
 *        its capabilities.
 *
 * @param [in] sess  the information for the WPS session (where the radio
 *                   capabilities can be found)
 * @param [out] list  array into which the matching encryption profiles will
 *                    be placed; must be at least APAC_MAXNUM_NTRK_NODES in
 *                    length
 * @param [out] requested_m2  the number of M2 messages (and thus the number of
 *                            BSSes) that the agent can support on the radio
 *
 * @return the number of profile matches (equivalently, the number of elements
 *         in list that are valid)
 */
u8 apac_map_get_eprofile(struct apac_wps_session *sess, u8 *list, u8 *requested_m2) {
    u8  maxBSS = 0, *listptr = NULL;
    u8 i = 0, profilecnt = 0;
    apacMapEProfileMatcher_t *eProfileMatcher = NULL;
    apacHyfi20Data_t *hyfi20 = NULL;
    apacMapData_t *map = NULL;
    apacBool_e match;

    apacHyfi20TRACE();

    hyfi20 = sess->pData;

    map = HYFI20ToMAP(hyfi20);

    listptr = list;
    *listptr = 0xff; //default value used in teardown
    *requested_m2 = 1; // max bss to send one teardown

    ieee1905MapParseBasicRadioTLV(sess->basicRadioCap, sess->basicRadioCapLen, &maxBSS, 0, 0,
                                  APAC_FALSE /* checkAllOpClasses */);

    if (hyfi20->config.role != APAC_REGISTRAR || map->eProfileCnt == 0 ) {
        dprintf(MSG_ERROR, "%s, not registrar or map file not found !\n", __func__);
        if (*listptr == 0xff) {
            for (i = 0; i < maxBSS; i++) {
                *listptr++ = 0xff;
            }
        }
        *requested_m2 = maxBSS;
        return profilecnt;
    }

    for(i = 0 ; i < map->eProfileCnt; i++) {
        match = APAC_FALSE;
        eProfileMatcher = &map->eProfileMatcher[i];

        if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_AL_SPECIFIC == eProfileMatcher->matcherType) {
            match = apac_map_match_eprofile_al_specific(sess, eProfileMatcher, &maxBSS);
        } else if (APAC_E_MAP_EPROFILE_MATCHER_TYPE_GENERIC == eProfileMatcher->matcherType) {
            match = apac_map_match_eprofile_generic(sess, eProfileMatcher, &maxBSS);
        } else {
            dprintf(MSG_ERROR, "%s: Unexpected matcher type at index %u\n", __func__, i);
        }

        if (match) {
            dprintf(MSG_MSGDUMP, "%s: Matched eprofile #%u\n", __func__, i);

            *listptr++ = i;
            profilecnt++;

            if (eProfileMatcher->terminateMatching) {
                // No further matching should be done for this radio
                break;
            }
        }
    }

    if (profilecnt < maxBSS) {
        dprintf(MSG_DEBUG, "%s: No profile match found for remaining BSS = %u \n", __func__,
                maxBSS - profilecnt);
        *listptr += profilecnt;
        for (i = 0; i < maxBSS - profilecnt; i++) {
            *listptr++ = 0xff;
        }
    }
    *requested_m2 = maxBSS;

    return profilecnt;
}

u8 apac_map_parse_vendor_ext(struct apac_wps_session *sess,
        u8 *pos,
        u8 len, u8 *mapBssType)
{
    u32 vendor_id;
#define WPS_VENDOR_ID_WFA 14122 //37 2a
#define WFA_ELEM_MAP_BSS_CONFIGURATION 0x06
    apacHyfi20TRACE();

    if (len < 3) {
        dprintf(MSG_DEBUG, "WPS: Skip invalid Vendor Extension");
        return 0;
    }

    vendor_id = WPA_GET_BE24(pos);
    switch (vendor_id) {
        case WPS_VENDOR_ID_WFA:
            len -=3;
            pos +=3;
            const u8 *end = pos + len;
            u8 id, elen;

            while (end - pos >= 2) {
                id = *pos++;
                elen = *pos++;
                if (elen > end - pos)
                    break;

                switch(id) {
                    case WFA_ELEM_MAP_BSS_CONFIGURATION:
                        dprintf(MSG_MSGDUMP,"Received Map Bss Type %x \n", *pos);
                        *mapBssType = *pos;
                        break;
                }
                pos += elen;
            }
    }
    return 0;
}
