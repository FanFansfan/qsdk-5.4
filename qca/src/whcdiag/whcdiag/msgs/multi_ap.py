#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2014-2015, 2018-2019 Qualcomm Technologies, Inc.
#
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#
# 2014-2015 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#
# Message definitions for the WLAN interface module.
#

"""Module providing the message unpacking for the Multi-AP module.

The following types are exported:

    :obj:`MessageID`: identifier for the message

The following classes are exported:

    :class:`APCapability`: basic capability information for an access point

The following functions are exported:

    :func:`unpack_payload_from_bytes`: unpack the message payload from a
        buffer
"""

import struct
import collections

from enum import Enum

from exception import MessageMalformedError
import common

#: Supported message identifiers for WLANIF
MessageID = Enum('MessageID', [('AP_CAPABILITY', 0),
                               ('RADIO_BASIC_CAPABILITY', 1),
                               ('HT_CAPABILITY', 2),
                               ('VHT_CAPABILITY', 3),
                               ('HE_CAPABILITY', 4),
                               ('AP_METRICS', 5),
                               ('ASSOC_STA_LINK_METRICS', 6),
                               ('ASSOC_STA_TRAFFIC_STATS', 7),
                               ('CHANNEL_PREFERENCE', 8),
                               ('CHANNEL_SCAN_REPORT', 9),
                               ('CHANNEL_SELECTION_RESULT', 10),
                               ('UNASSOC_STA_LINK_METRICS', 11)])

_APCapability = struct.Struct('6sBBBB')
APCapability = collections.namedtuple('APCapability',
                                      ['al_id', 'ap_id', 'unassoc_cur_chan',
                                       'unassoc_other_chan',
                                       'agent_initiated_rssi_steering'])

_RadioBasicCapabilityStart = struct.Struct('6s6sBB')
_RadioBasicCapabilityOpClass = struct.Struct('BBB')
RadioBasicCapability = collections.namedtuple('RadioBasicCapability',
                                              ['al_id', 'radio_id', 'max_bss',
                                               'op_classes'])
RadioBasicCapabilityOpClass = collections.namedtuple('RadioBasicCapabilityOpClass',
                                                     ['op_class', 'max_eirp',
                                                      'non_op_chans'])

_HTCapability = struct.Struct('6s6sBBBBB')
HTCapability = collections.namedtuple('HTCapability',
                                      ['al_id', 'radio_id', 'nss_tx',
                                       'nss_rx', 'short_gi_20mhz',
                                       'short_gi_40mhz', 'ht_40mhz'])

_VHTCapabilityFormat = '6s6sHHBBBBBBBB'
_VHTCapabilityLE = struct.Struct('<' + _VHTCapabilityFormat)
_VHTCapabilityBE = struct.Struct('>' + _VHTCapabilityFormat)
VHTCapability = collections.namedtuple('VHTCapability',
                                       ['al_id', 'radio_id', 'tx_mcs',
                                        'rx_mcs', 'nss_tx',
                                        'nss_rx', 'short_gi_80mhz',
                                        'short_gi_160mhz', 'vht_80p80mhz',
                                        'vht_160mhz', 'su_beamformer',
                                        'mu_beamformer'])

_HECapabilityStart = struct.Struct('6s6sB')
_HECapabilityMCSMapFormat = 'HH'
_HECapabilityMCSMapLE = struct.Struct('<' + _HECapabilityMCSMapFormat)
_HECapabilityMCSMapBE = struct.Struct('>' + _HECapabilityMCSMapFormat)
_HECapabilityEnd = struct.Struct('BBBBBBBBBBB')
HECapability = collections.namedtuple('HECapability',
                                      ['al_id', 'radio_id',
                                       'rx_mcs_80', 'tx_mcs_80',
                                       'rx_mcs_160', 'tx_mcs_160',
                                       'rx_mcs_80p80', 'tx_mcs_80p80',
                                       'nss_tx', 'nss_rx', 'he_80p80mhz',
                                       'he_160mhz', 'su_beamformer',
                                       'mu_beamformer', 'ul_mu_mimo',
                                       'ul_mu_mimo_ofdma', 'dl_mu_mimo_ofdma',
                                       'ul_ofdma', 'dl_ofdma'])

AccessCategory = Enum('AccessCategory', [('BK', 0), ('BE', 1), ('VI', 2), ('VO', 3)])
DataFormat = Enum('DataFormat', [('NoAgg', 0), ('AMSDU', 1), ('AMPDU', 2),
                                 ('AMSDU_AMPDU', 3)])

_EstimatedServiceParametersFormat = 'BBBBH'
_EstimatedServiceParametersLE = struct.Struct('<' + _EstimatedServiceParametersFormat)
_EstimatedServiceParametersBE = struct.Struct('>' + _EstimatedServiceParametersFormat)
EstimatedServiceParameters = collections.namedtuple('EstimatedServiceParameters',
                                                    ['ac', 'data_format',
                                                     'ba_window_size',
                                                     'est_airtime_fraction',
                                                     'data_ppdu_duration_target'])

_APMetricsCommonFormat = '6s6sBH'
_APMetricsCommonLE = struct.Struct('<' + _APMetricsCommonFormat)
_APMetricsCommonBE = struct.Struct('>' + _APMetricsCommonFormat)
APMetrics = collections.namedtuple('APMetrics',
                                   ['al_id', 'bssid', 'chan_util',
                                    'num_assoc_stas', 'esp_info'])

_AssocSTALinkMetricsFormat = '6s6sLLLB'
_AssocSTALinkMetricsLE = struct.Struct('<' + _AssocSTALinkMetricsFormat)
_AssocSTALinkMetricsBE = struct.Struct('>' + _AssocSTALinkMetricsFormat)
AssocSTALinkMetrics = collections.namedtuple('AssocSTALinkMetrics',
                                             ['sta_addr', 'bssid', 'age_ms',
                                              'dl_rate', 'ul_rate', 'rssi'])

_AssocSTATrafficStatsFormat = '6s6sLLLLLLL'
_AssocSTATrafficStatsLE = struct.Struct('<' + _AssocSTATrafficStatsFormat)
_AssocSTATrafficStatsBE = struct.Struct('>' + _AssocSTATrafficStatsFormat)
AssocSTATrafficStats = collections.namedtuple('AssocSTATrafficStats',
                                              ['al_id', 'sta_addr', 'tx_bytes',
                                               'rx_bytes', 'tx_pkts', 'rx_pkts',
                                               'tx_pkt_errors', 'rx_pkt_errors',
                                               'retx_count'])

_ChannelPreferenceStart = struct.Struct('6s6sB')
_ChannelPreferenceOpClass = struct.Struct('BBBB')
ChannelPreference = collections.namedtuple('ChannelPreference',
                                           ['al_id', 'radio_id', 'op_classes'])
ChannelPreferenceOpClass = collections.namedtuple('ChannelPreferenceOpClass',
                                                  ['op_class', 'channel', 'preference', 'reason'])

_ChannelScanReportStart = struct.Struct('6s6sBB')

_ChannelScanChanDataFormat = 'BBLLHHLLBBBLLLLLLL'
_ChannelScanChanDataLE = struct.Struct('<' + _ChannelScanChanDataFormat)
_ChannelScanChanDataBE = struct.Struct('>' + _ChannelScanChanDataFormat)

_ChannelScanNeighborDataFormat = 'BLL6s'
_ChannelScanNeighborDataLE = struct.Struct('<' + _ChannelScanNeighborDataFormat)
_ChannelScanNeighborDataBE = struct.Struct('>' + _ChannelScanNeighborDataFormat)

ChannelScanReport = collections.namedtuple('ChannelScanReport',
                                           ['al_id', 'radio_id', 'channel_data', 'neighbor_data'])
ChannelScanChanData = collections.namedtuple('ChannelScanChanData',
                                             ['chan_num', 'n_bss', 'min_rssi', 'max_rssi',
                                              'noise_floor', 'chan_loading', 'chan_load',
                                              'acs_rank', 'chan_in_pool', 'radar_noise',
                                              'non_80211_noise', 'chan_util', 'chan_util_total',
                                              'chan_util_busy', 'chan_util_busy_tx',
                                              'chan_util_busy_rx', 'chan_util_self',
                                              'chan_util_ext'])
ChannelScanNeighborData = collections.namedtuple('ChannelScanNeighborData', ['chan_num', 'phy_mode',
                                                 'rssi', 'bssid'])

_ChannelSelectionResult = struct.Struct('6s6sBBBBBB')
ChannelSelectionResult = collections.namedtuple('ChannelSelectionResult',
                                                ['al_id', 'radio_id',
                                                 'primary_op_class', 'primary_channel', 'op_class',
                                                 'channel', 'bandwidth', 'secondary_channel'])

_UnassocSTALinkMetricsFormat = '6s6sBBBL'
_UnassocSTALinkMetricsLE = struct.Struct('<' + _UnassocSTALinkMetricsFormat)
_UnassocSTALinkMetricsBE = struct.Struct('>' + _UnassocSTALinkMetricsFormat)
UnassocSTALinkMetrics = collections.namedtuple('UnassocSTALinkMetrics',
                                               ['al_id', 'sta_addr', 'op_class', 'chan_num',
                                                'uplink_rssi', 'time_delta'])


def unpack_payload_from_bytes(version, big_endian, buf):
    """Unpack the payload portion of the message provided.

    Args:
        version (int): the version number of the message
        big_endian (bool): whether the payload is encoded in big endian
            format or not
        buf (str): the entire payload to be unpacked

    Returns:
        the unpacked message as a namedtuple of the right type

    Raises:
        :class:`MessageMalformedError`: Unsupported message ID or band
    """
    if len(buf) == 0:
        raise MessageMalformedError("Message ID is missing")

    if version == common.Version.VERSION1:
        raise MessageMalformedError("Unsupported version: %d" % version.value)

    msg_id = ord(buf[0])

    if msg_id == MessageID.AP_CAPABILITY.value:
        unpacker = _APCapability
        constructor = APCapability
    elif msg_id == MessageID.RADIO_BASIC_CAPABILITY.value:
        unpacker = _RadioBasicCapabilityStart
        constructor = RadioBasicCapability
    elif msg_id == MessageID.HT_CAPABILITY.value:
        unpacker = _HTCapability
        constructor = HTCapability
    elif msg_id == MessageID.VHT_CAPABILITY.value:
        unpacker = _VHTCapabilityBE if big_endian else _VHTCapabilityLE
        constructor = VHTCapability
    elif msg_id == MessageID.HE_CAPABILITY.value:
        unpacker = _HECapabilityStart
        mcs_unpacker = _HECapabilityMCSMapBE if big_endian else _HECapabilityMCSMapLE
        constructor = HECapability
    elif msg_id == MessageID.AP_METRICS.value:
        unpacker = _APMetricsCommonBE if big_endian else _APMetricsCommonLE
        esp_unpacker = _EstimatedServiceParametersBE if big_endian \
            else _EstimatedServiceParametersLE
        constructor = APMetrics
    elif msg_id == MessageID.ASSOC_STA_LINK_METRICS.value:
        unpacker = _AssocSTALinkMetricsBE if big_endian else _AssocSTALinkMetricsLE
        constructor = AssocSTALinkMetrics
    elif msg_id == MessageID.ASSOC_STA_TRAFFIC_STATS.value:
        unpacker = _AssocSTATrafficStatsBE if big_endian else _AssocSTATrafficStatsLE
        constructor = AssocSTATrafficStats
    elif msg_id == MessageID.CHANNEL_PREFERENCE.value:
        unpacker = _ChannelPreferenceStart
        constructor = ChannelPreference
    elif msg_id == MessageID.CHANNEL_SCAN_REPORT.value:
        unpacker = _ChannelScanReportStart
        constructor = ChannelScanReport
    elif msg_id == MessageID.CHANNEL_SELECTION_RESULT.value:
        unpacker = _ChannelSelectionResult
        constructor = ChannelSelectionResult
    elif msg_id == MessageID.UNASSOC_STA_LINK_METRICS.value:
        unpacker = _UnassocSTALinkMetricsBE if big_endian else _UnassocSTALinkMetricsLE
        constructor = UnassocSTALinkMetrics
    else:
        raise MessageMalformedError("Unsupported message ID: %d" % msg_id)

    if len(buf) < unpacker.size + 1:
        raise MessageMalformedError("Message too short: %d (need %d)" %
                                    (len(buf), unpacker.size + 1))

    # This message contains a MAC address, which we convert to a more
    # convenient string representation (a human readable one).
    if msg_id == MessageID.RADIO_BASIC_CAPABILITY.value:
        al_id, radio_id, max_bsses, num_op_class = \
                unpacker.unpack(buf[1:unpacker.size + 1])
        al_id = common.ether_ntoa(al_id)
        radio_id = common.ether_ntoa(radio_id)

        # Now for each operating class
        buf = buf[unpacker.size + 1:]
        op_classes = []
        unpacker = _RadioBasicCapabilityOpClass
        for i in range(num_op_class):
            if len(buf) < unpacker.size:
                raise MessageMalformedError("Too few byets for op class #%d" % i)

            op_class, max_eirp, num_non_oper = unpacker.unpack(buf[:unpacker.size])
            buf = buf[unpacker.size:]
            if len(buf) < num_non_oper:
                raise MessageMalformedError("Too few bytes for op class #%d" % i)

            non_oper_chans = []
            if num_non_oper > 0:
                non_oper_chans = list(struct.Struct('B' * num_non_oper)
                                            .unpack(buf[:num_non_oper]))
                buf = buf[num_non_oper:]

            op_classes.append(RadioBasicCapabilityOpClass._make((
                op_class, max_eirp, non_oper_chans)))

        payload = constructor._make((al_id, radio_id, max_bsses, op_classes))
    elif msg_id == MessageID.HE_CAPABILITY.value:
        # Just do min length checks first
        min_len = unpacker.size + 1 + mcs_unpacker.size + _HECapabilityEnd.size
        if len(buf) < min_len:
            raise MessageMalformedError("Message too short: %d (need %d)" %
                                        (len(buf), min_len))

        al_id, radio_id, mcs_len = unpacker.unpack(buf[1:unpacker.size + 1])
        al_id = common.ether_ntoa(al_id)
        radio_id = common.ether_ntoa(radio_id)

        if mcs_len % 4 != 0:
            raise MessageMalformedError("Invalid MCS length for HE Capability")

        buf = buf[1 + unpacker.size:]
        if len(buf) < mcs_len + _HECapabilityEnd.size:
            raise MessageMalformedError("Too few bytes for HE Capability")

        rx_mcs_80, tx_mcs_80 = mcs_unpacker.unpack(buf[:mcs_unpacker.size])
        buf = buf[mcs_unpacker.size:]

        rx_mcs_160 = None
        tx_mcs_160 = None
        if mcs_len > 4:
            rx_mcs_160, tx_mcs_160 = mcs_unpacker.unpack(buf[:mcs_unpacker.size])
            buf = buf[mcs_unpacker.size:]

        rx_mcs_80p80 = None
        tx_mcs_80p80 = None
        if mcs_len > 8:
            rx_mcs_80p80, tx_mcs_80p80 = mcs_unpacker.unpack(buf[:mcs_unpacker.size])
            buf = buf[mcs_unpacker.size:]

        capabilities = _HECapabilityEnd.unpack(buf)
        payload = constructor._make([al_id, radio_id, rx_mcs_80, tx_mcs_80,
                                     rx_mcs_160, tx_mcs_160, rx_mcs_80p80,
                                     tx_mcs_80p80] + list(capabilities))
    elif msg_id == MessageID.HT_CAPABILITY.value or \
            msg_id == MessageID.VHT_CAPABILITY.value:
        fields = unpacker.unpack(buf[1:])
        al_id = common.ether_ntoa(fields[0])
        radio_id = common.ether_ntoa(fields[1])

        payload = constructor._make([al_id, radio_id] + list(fields[2:]))
    elif msg_id == MessageID.AP_METRICS.value:
        fields = unpacker.unpack(buf[1:unpacker.size + 1])
        al_id = common.ether_ntoa(fields[0])
        bssid = common.ether_ntoa(fields[1])

        esp_info = []
        buf = buf[unpacker.size + 1:]
        while len(buf) >= esp_unpacker.size:
            esp_fields = esp_unpacker.unpack(buf[:esp_unpacker.size])

            try:
                ac = AccessCategory(esp_fields[0])
            except ValueError:
                raise MessageMalformedError("Invalid access category %d" % esp_fields[0])

            try:
                data_format = DataFormat(esp_fields[1])
            except ValueError:
                raise MessageMalformedError("Invalid data format %d" % esp_fields[1])

            esp_info.append(EstimatedServiceParameters._make([ac, data_format] +
                                                             list(esp_fields[2:])))

            buf = buf[esp_unpacker.size:]

        if len(buf) > 0:
            raise MessageMalformedError("Unexpected %d extra bytes in ESP info" %
                                        len(buf))

        payload = constructor._make([al_id, bssid] + list(fields[2:]) + [esp_info])
    elif msg_id == MessageID.ASSOC_STA_LINK_METRICS.value:
        fields = unpacker.unpack(buf[1:])
        sta_addr = common.ether_ntoa(fields[0])
        bssid = common.ether_ntoa(fields[1])

        payload = constructor._make([sta_addr, bssid] + list(fields[2:]))
    elif msg_id == MessageID.ASSOC_STA_TRAFFIC_STATS.value:
        fields = unpacker.unpack(buf[1:])
        al_id = common.ether_ntoa(fields[0])
        sta_addr = common.ether_ntoa(fields[1])

        payload = constructor._make([al_id, sta_addr] + list(fields[2:]))
    elif msg_id == MessageID.CHANNEL_PREFERENCE.value:
        al_id, radio_id, num_pairs = \
                unpacker.unpack(buf[1:unpacker.size + 1])
        al_id = common.ether_ntoa(al_id)
        radio_id = common.ether_ntoa(radio_id)

        # Loop through <op class, channel> pairs
        buf = buf[unpacker.size + 1:]
        op_classes = []
        unpacker = _ChannelPreferenceOpClass
        for i in range(num_pairs):
            if (len(buf) < unpacker.size):
                raise MessageMalformedError("Too few bytes for op class #%d" % i)

            op_class, chan, pref, reason = unpacker.unpack(buf[:unpacker.size])
            op_classes.append(ChannelPreferenceOpClass._make((op_class, chan, pref, reason)))

            buf = buf[unpacker.size:]

        payload = constructor._make((al_id, radio_id, op_classes))
    elif msg_id == MessageID.CHANNEL_SCAN_REPORT.value:
        al_id, radio_id, num_chans, num_neighbors = unpacker.unpack(buf[1:unpacker.size+1])
        al_id = common.ether_ntoa(al_id)
        radio_id = common.ether_ntoa(radio_id)

        buf = buf[unpacker.size+1:]

        # Loop through channel data
        chan_data = []
        unpacker = _ChannelScanChanDataBE if big_endian else _ChannelScanChanDataLE
        for i in range(num_chans):
            if len(buf) < unpacker.size:
                raise MessageMalformedError("Too few bytes for channel data #%d" % i)
            fields = unpacker.unpack(buf[:unpacker.size])
            chan_data.append(ChannelScanChanData._make(list(fields)))

            buf = buf[unpacker.size:]

        # Loop through neighbor data
        neighbor_data = []
        unpacker = _ChannelScanNeighborDataBE if big_endian else _ChannelScanNeighborDataLE
        for i in range(num_neighbors):
            if len(buf) < unpacker.size:
                raise MessageMalformedError("Too few bytes for neighbor data #%d" % i)
            chan, mode, rssi, bssid = unpacker.unpack(buf[:unpacker.size])
            bssid = common.ether_ntoa(bssid)
            neighbor_data.append(ChannelScanNeighborData._make((chan, mode, rssi, bssid)))

            buf = buf[unpacker.size:]

        payload = constructor._make((al_id, radio_id, chan_data, neighbor_data))
    elif msg_id == MessageID.CHANNEL_SELECTION_RESULT.value:
        fields = unpacker.unpack(buf[1:])
        al_id = common.ether_ntoa(fields[0])
        radio_id = common.ether_ntoa(fields[1])

        payload = constructor._make([al_id, radio_id] +
                                    list(fields)[2:])
    elif msg_id == MessageID.UNASSOC_STA_LINK_METRICS.value:
        fields = unpacker.unpack(buf[1:])
        al_id = common.ether_ntoa(fields[0])
        sta_addr = common.ether_ntoa(fields[1])

        payload = constructor._make([al_id, sta_addr] + list(fields[2:]))
    else:  # types that only include the AL ID
        fields = unpacker.unpack(buf[1:])
        payload = constructor._make([common.ether_ntoa(fields[0])] +
                                    list(fields)[1:])

    return common.check_band(payload)


__all__ = ['MessageID', 'APCapability', 'RadioBasicCapability', 'HTCapability',
           'VHTCapability', 'HECapability', 'ChannelPreference']
