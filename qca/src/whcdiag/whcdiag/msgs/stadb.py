#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2014-2015, 2018 Qualcomm Technologies, Inc.
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
# Message definitions for the station database module.
#

"""Module providing the message unpacking for the stadb module.

The following types are exported:

    :obj:`MessageID`: identifier for the message

The following classes are exported:

    :class:`AssociationUpdate`: a specific STA associated or disassociated
    :class:`RSSIUpdate`: the RSSI for a specific STA was updated
    :class:`ActivityUpdate`: whether a specific STA was active or inactive
        was updated
    :class:`DualBandUpdate`: whether a specific STA is dual band capable
        was updated

The following functions are exported:

    :func:`unpack_payload_from_bytes`: unpack the message payload from a
        buffer
"""

import struct
import collections

from enum import Enum

from exception import MessageMalformedError
from whcdiag.constants import CHANNEL_WIDTH, PHY_MODE
import common

#: Supported message identifiers for stadb
MessageID = Enum('MessageID', [('ASSOCIATION_UPDATE', 0), ('RSSI_UPDATE', 1),
                               ('ACTIVITY_UPDATE', 2), ('DUAL_BAND_UPDATE', 3),
                               ('CAPACITIES_UPDATE', 4),
                               ('BAND_PHY_CAPABILITIES_UPDATE', 5)])

_AssociationUpdate = struct.Struct('6sBBB')
AssociationUpdate = collections.namedtuple('AssociationUpdate',
                                           ['sta_addr', 'band', 'is_active',
                                            'is_dual_band'])

_AssociationUpdate_v2 = struct.Struct('6s%dsBBBBB' % common._BSSInfo.size)
AssociationUpdate_v2 = collections.namedtuple('AssociationUpdate',
                                              ['sta_addr', 'bss_info',
                                               'is_associated', 'is_active',
                                               'is_dual_band', 'is_btm_capable',
                                               'is_rrm_capable'])

_RSSIUpdate = struct.Struct('6sBB')
RSSIUpdate = collections.namedtuple('RSSIUpdate',
                                    ['sta_addr', 'band', 'rssi'])
_RSSIUpdate_v2 = struct.Struct('6s%dsB' % common._BSSInfo.size)
RSSIUpdate_v2 = collections.namedtuple('RSSIUpdate',
                                       ['sta_addr', 'bss_info', 'rssi'])

_ActivityUpdate = struct.Struct('6sBB')
ActivityUpdate = collections.namedtuple('ActivityUpdate',
                                        ['sta_addr', 'band', 'is_active'])
_ActivityUpdate_v2 = struct.Struct('6s%dsB' % common._BSSInfo.size)
ActivityUpdate_v2 = collections.namedtuple('ActivityUpdate',
                                           ['sta_addr', 'bss_info', 'is_active'])

_DualBandUpdate = struct.Struct('6sB')
DualBandUpdate = collections.namedtuple('DualBandUpdate',
                                        ['sta_addr', 'is_dual_band'])

_CapacitiesUpdateFormat = '6s%dsHH' % common._BSSInfo.size
_CapacitiesUpdateLE = struct.Struct('<' + _CapacitiesUpdateFormat)  # little endian
_CapacitiesUpdateBE = struct.Struct('>' + _CapacitiesUpdateFormat)  # little endian
CapacitiesUpdate = collections.namedtuple('CapacitiesUpdate',
                                          ['sta_addr', 'bss_info',
                                           'ul_capacity', 'dl_capacity'])

_BandPHYCapabilitiesUpdate = struct.Struct('6sBBBBBB')
BandPHYCapabilitiesUpdate = collections.namedtuple('BandPHYCapabilitiesUpdate',
                                                   ['sta_addr', 'band',
                                                    'max_ch_width', 'nss',
                                                    'phy_mode', 'max_mcs',
                                                    'max_tx_power'])


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

    msg_id = ord(buf[0])

    allow_invalid_band = False
    if msg_id == MessageID.ASSOCIATION_UPDATE.value:
        if version == common.Version.VERSION2:
            unpacker = _AssociationUpdate_v2
            constructor = AssociationUpdate_v2
        else:
            unpacker = _AssociationUpdate
            constructor = AssociationUpdate
        allow_invalid_band = True
    elif msg_id == MessageID.RSSI_UPDATE.value:
        if version == common.Version.VERSION2:
            unpacker = _RSSIUpdate_v2
            constructor = RSSIUpdate_v2
        else:
            unpacker = _RSSIUpdate
            constructor = RSSIUpdate
    elif msg_id == MessageID.ACTIVITY_UPDATE.value:
        if version == common.Version.VERSION2:
            unpacker = _ActivityUpdate_v2
            constructor = ActivityUpdate_v2
        else:
            unpacker = _ActivityUpdate
            constructor = ActivityUpdate
    elif msg_id == MessageID.DUAL_BAND_UPDATE.value:
        unpacker = _DualBandUpdate
        constructor = DualBandUpdate
    elif msg_id == MessageID.CAPACITIES_UPDATE.value:
        unpacker = _CapacitiesUpdateBE if big_endian else _CapacitiesUpdateLE
        constructor = CapacitiesUpdate
    elif msg_id == MessageID.BAND_PHY_CAPABILITIES_UPDATE.value:
        unpacker = _BandPHYCapabilitiesUpdate
        constructor = BandPHYCapabilitiesUpdate
    else:
        raise MessageMalformedError("Unsupported message ID: %d" % msg_id)

    if len(buf) < unpacker.size + 1:
        raise MessageMalformedError("Message too short: %d (need %d)" %
                                    (len(buf), unpacker.size + 1))

    fields = unpacker.unpack(buf[1:(unpacker.size + 1)])
    if msg_id == MessageID.BAND_PHY_CAPABILITIES_UPDATE.value:
        fields = list(fields)  # to allow modification
        try:
            fields[2] = CHANNEL_WIDTH(fields[2])
        except ValueError:
            raise MessageMalformedError("Invalid channel width %d" % fields[2])

        try:
            fields[4] = PHY_MODE(fields[4])
        except ValueError:
            raise MessageMalformedError("Invalid PHY mode %d" % fields[4])

    payload = constructor._make([common.ether_ntoa(fields[0])] +
                                list(fields)[1:])

    if hasattr(payload, 'bss_info'):
        (payload, buf) = common.get_bss_info(payload.bss_info, payload,
                                             'bss_info', 1)

    return common.check_band(payload, allow_invalid_band)


__all__ = ['MessageID', 'AssociationUpdate', 'RSSIUpdate', 'ActivityUpdate',
           'DualBandUpdate', 'CapacitiesUpdate']
