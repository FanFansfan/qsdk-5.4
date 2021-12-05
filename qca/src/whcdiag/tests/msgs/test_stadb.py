#!/usr/bin/env python
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

import unittest
import itertools

from whcdiag.msgs import common
from whcdiag.msgs import stadb
from whcdiag.msgs.exception import MessageMalformedError

from whcdiag.constants import BAND_TYPE, CHANNEL_WIDTH, PHY_MODE


class TestStaDBMsgs(unittest.TestCase):

    def test_invalid_msg(self):
        """Verify invalid messages are rejected."""
        # Test 1: Message not even long enough for message ID
        msg = ''
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Test 2: Invalid message ID
        msg = '\x06\x11'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Test 3: Invalid length for association
        msg = '\x00\x7b\xd8\x95\x4f\xbf\xeb\x00'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Test 4: Invalid length for RSSI update
        msg = '\x01\x4d\xb4\x41\x8b\xf0\x10\x00'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Test 5: Invalid length for activity update (v1)
        msg = '\x02\x83\x18\x1e\x0a\x12\x18\x00'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Test 6: Invalid length for activity update (v2)
        msg = '\x02\x83\x18\x1e\x0a\x12\x18\xFF\x64\x00'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, True, msg)

        # Test 7: Invalid length for dual band update
        msg = '\x03\x1e\xc5\x3c\xcc\xd0\x7c'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Test 8: Invalid length for capacities update
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x04' + mac + '\xff\x01\x00\x12\x34\x11'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 9a: Invalid length for band PHY capabilities update
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x05' + mac + '\x00\x01\x01\x07'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 9b: Invalid channel width
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x05' + mac + '\x00\x06\x03\x01\x07\x10'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 9c: Invalid PHY mode
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x05' + mac + '\x00\x03\x03\x07\x07\x10'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

    def test_association_update(self):
        """Verify the parsing of the association update message."""
        # Test 1: Associated on 2.4 GHz
        mac = '\xb2\xdd\x69\xa1\xb3\xe3'
        msg = '\x00' + mac + '\x00\x01\x00'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.AssociationUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_24G, True, False)),
            payload)

        # Same as above but in big-endian (which makes no difference)
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.AssociationUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_24G, True, False)),
            payload)

        # Test 2: Associated on 5 GHz
        mac = '\x67\xae\x3b\x86\xc3\x8e'
        msg = '\x00' + mac + '\x01\x01\x01'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.AssociationUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_5G, True, True)),
            payload)

        # Same as above but in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.AssociationUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_5G, True, True)),
            payload)

        # Test 3: Disassociated
        mac = '\x29\xed\x66\x8b\x16\x77'
        msg = '\x00' + mac + '\x02\x00\x00'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.AssociationUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_INVALID, False,
             False)), payload)

        # Same as above but in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.AssociationUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_INVALID, False,
             False)), payload)

        # Test 3.1: A valid version 1 payload with a version 2 header is malformed
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, True, msg)

        # Test 4: Association update on a bogus band is malformed
        mac = '\xfc\x91\x14\xc5\x3c\x7f'
        msg = '\x00' + mac + '\x03\x00\x01'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Repeat above test with a version 2 message
        # Test 5: Associated on 2.4 GHz
        mac = '\xb2\xdd\x69\xa1\xb3\xe3'
        msg = '\x00' + mac + '\xFF\x0b\x00\x01\x01\x00\x01\x00'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.AssociationUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 11, 0),
             True, True, False, True, False)),
            payload)

        # Same as above but in big-endian (which makes no difference)
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.AssociationUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 11, 0),
             True, True, False, True, False)),
            payload)

        # Test 6: Associated on 5 GHz
        mac = '\x67\xae\x3b\x86\xc3\x8e'
        msg = '\x00' + mac + '\xFF\x64\x00\x01\x01\x01\x00\x01'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.AssociationUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 100, 0),
             True, True, True, False, True)),
            payload)

        # Same as above but in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.AssociationUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 100, 0),
             True, True, True, False, True)),
            payload)

        # Test 7: Disassociated
        mac = '\x29\xed\x66\x8b\x16\x77'
        msg = '\x00' + mac + '\xFF\x64\x00\x00\x00\x00\x00\x00'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.AssociationUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 100, 0),
             False, False, False, False, False)), payload)

        # Same as above but in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.AssociationUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 100, 0),
             False, False, False, False, False)), payload)

    def test_rssi_update(self):
        """Verify the parsing of the RSSI update message v1."""
        # Test 1: RSSI update on 2.4 GHz
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x01' + mac + '\x00\x17'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.RSSIUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_24G, 23)),
            payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.RSSIUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_24G, 23)),
            payload)

        # Test 2: RSSI update on 5 GHz
        mac = '\x32\x10\xbb\xf6\xa5\x35'
        msg = '\x01' + mac + '\x01\x12'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.RSSIUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_5G, 18)),
            payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.RSSIUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_5G, 18)),
            payload)

        # Test 3: RSSI update on invalid band is malformed
        mac = '\xff\x7e\x74\x17\x52\xa9'
        msg = '\x01' + mac + '\x02\x06'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        # Test 4: RSSI update on invalid band is malformed
        mac = '\xab\xd6\xd1\xd0\xfd\x25'
        msg = '\x01' + mac + '\x03\x06'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, True, msg)

        """Verify the parsing of the RSSI update message v2."""
        # Test 1: RSSI update on channel 1
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x02' + mac + '\xff\x01\x00\x17'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.RSSIUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 1, 0), 23)),
            payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.RSSIUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 1, 0), 23)),
            payload)

        # Test 2: RSSI update on channel 100
        mac = '\x32\x10\xbb\xf6\xa5\x35'
        msg = '\x02' + mac + '\x00\x24\x01\x12'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.RSSIUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0, 36, 1), 18)),
            payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.RSSIUpdate_v2._make(
            (common.ether_ntoa(mac), common.BSSInfo(0, 36, 1), 18)),
            payload)

        # Test 3: RSSI update with V2 header and V1 payload is malformed
        mac = '\x32\x10\xbb\xf6\xa5\x35'
        msg = '\x02' + mac + '\x01\x12'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION2, True, msg)

    def test_activity_update(self):
        """Verify the parsing of the activity update message v1."""
        test_cases = itertools.product([BAND_TYPE.BAND_24G,
                                        BAND_TYPE.BAND_5G],
                                       [True, False])
        for test_case in test_cases:
            # Test with all combinations of band and activity change
            mac = '\xcd\x92\x1f\xe3\x84\x11'
            msg = '\x02' + mac + chr(test_case[0].value) + chr(test_case[1])
            payload = stadb.unpack_payload_from_bytes(
                common.Version.VERSION1, False, msg)
            self.assertEquals(stadb.ActivityUpdate._make(
                (common.ether_ntoa(mac), test_case[0], test_case[1])),
                payload)

            # Same as above but in big-endian (which makes no difference)
            payload = stadb.unpack_payload_from_bytes(
                common.Version.VERSION1, True, msg)
            self.assertEquals(stadb.ActivityUpdate._make(
                (common.ether_ntoa(mac), test_case[0], test_case[1])),
                payload)

        # Test 2: Activity update on a invalid band is malformed
        mac = '\x00\x66\x9a\x85\x7b\xd9'
        msg = '\x02' + mac + '\x02\x00'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Test 3: Activity update on a bogus band is malformed
        mac = '\xbb\xb9\x21\xd4\xab\xd4'
        msg = '\x02' + mac + '\x03\x00'
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Same in big endian
        self.assertRaises(
            MessageMalformedError, stadb.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        """Verify the parsing of the activity update message v2."""
        for activity in [True, False]:
            # Test with all combinations of activity change
            mac = '\xcd\x92\x1f\xe3\x84\x11'
            msg = '\x02' + mac + '\xFF\x64\x00' + chr(activity)
            payload = stadb.unpack_payload_from_bytes(
                common.Version.VERSION2, False, msg)
            self.assertEquals(stadb.ActivityUpdate_v2._make(
                (common.ether_ntoa(mac), common.BSSInfo(0xFF, 100, 0),
                 activity)), payload)

            # Same as above but in big-endian (which makes no difference)
            payload = stadb.unpack_payload_from_bytes(
                common.Version.VERSION2, True, msg)
            self.assertEquals(stadb.ActivityUpdate_v2._make(
                (common.ether_ntoa(mac), common.BSSInfo(0xFF, 100, 0),
                 activity)), payload)

    def test_dual_band_update(self):
        """Verify the parsing of the dual band update message."""
        # Test 1: Device becomes dual band
        mac = '\x91\x89\x0e\x16\xfb\x4e'
        msg = '\x03' + mac + '\x01'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.DualBandUpdate._make(
            (common.ether_ntoa(mac), True)),
            payload)

        # Same as above but in big-endian (which makes no difference)
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.DualBandUpdate._make(
            (common.ether_ntoa(mac), True)),
            payload)

        # Test 2: Device is no longer considered dual band
        mac = '\x3b\x16\xf7\x1c\xbc\xd7'
        msg = '\x03' + mac + '\x00'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, False, msg)
        self.assertEquals(stadb.DualBandUpdate._make(
            (common.ether_ntoa(mac), False)),
            payload)

        # Same as above but in big-endian (which makes no difference)
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION1, True, msg)
        self.assertEquals(stadb.DualBandUpdate._make(
            (common.ether_ntoa(mac), False)),
            payload)

    def test_capacities_update(self):
        """Verify the parsing of the Capacities Update message."""
        # Test 1: Capacities update on channel 1
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x04' + mac + '\xff\x01\x00\x12\x34\x11\x22'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.CapacitiesUpdate._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 1, 0), 13330, 8721)),
            payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.CapacitiesUpdate._make(
            (common.ether_ntoa(mac), common.BSSInfo(0xFF, 1, 0), 4660, 4386)),
            payload)

        # Test 2: Capacities update on channel 100
        mac = '\x32\x10\xbb\xf6\xa5\x35'
        msg = '\x04' + mac + '\x00\x24\x01\x2c\x01\xfa\x00'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.CapacitiesUpdate._make(
            (common.ether_ntoa(mac), common.BSSInfo(0, 36, 1), 300, 250)),
            payload)

        # Same in big endian
        mac = '\x32\x10\xbb\xf6\xa5\x35'
        msg = '\x04' + mac + '\x00\x24\x01\x01\x2c\x00\xfa'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.CapacitiesUpdate._make(
            (common.ether_ntoa(mac), common.BSSInfo(0, 36, 1), 300, 250)),
            payload)

    def test_band_phy_capabilities_update(self):
        """Verify the parsing of the Band PHY Capabilities Update message."""
        # Test 1: Capabilities update on 2.4 GHz
        mac = '\x8a\x25\xf2\x83\x93\x85'
        msg = '\x05' + mac + '\x00\x01\x03\x01\x07\x16'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.BandPHYCapabilitiesUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_24G,
             CHANNEL_WIDTH.CHWIDTH_40, 3, PHY_MODE.HT, 7, 22)), payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.BandPHYCapabilitiesUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_24G,
             CHANNEL_WIDTH.CHWIDTH_40, 3, PHY_MODE.HT, 7, 22)), payload)

        # Test 2: Capabilities update on 5 GHz
        mac = '\x32\x10\xbb\xf6\xa5\x35'
        msg = '\x05' + mac + '\x01\x02\x04\x02\x09\x1b'
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(stadb.BandPHYCapabilitiesUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_5G,
             CHANNEL_WIDTH.CHWIDTH_80, 4, PHY_MODE.VHT, 9, 27)), payload)

        # Same in big endian
        payload = stadb.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(stadb.BandPHYCapabilitiesUpdate._make(
            (common.ether_ntoa(mac), BAND_TYPE.BAND_5G,
             CHANNEL_WIDTH.CHWIDTH_80, 4, PHY_MODE.VHT, 9, 27)), payload)


if __name__ == '__main__':
    unittest.main()
