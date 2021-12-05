#!/usr/bin/env python
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

import unittest

from whcdiag.msgs import common
from whcdiag.msgs import multi_ap
from whcdiag.msgs.exception import MessageMalformedError


class TestMultiAPMsgs(unittest.TestCase):

    def test_invalid_msg(self):
        """Verify invalid messages are rejected."""
        # Test 1: Message not even long enough for message ID
        msg = ''
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 2: Invalid message ID
        msg = '\x16\x11'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, True, msg)

        # Test 3: Invalid version 1
        msg = '\x00\x00'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION1, False, msg)

        # Test 4: Invalid AP capability length (v2)
        msg = '\x00\x01\x02\x03\x04\x05\x06\x01\x00\x00'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 5: Invalid Radio Basic Capability length (not even start)
        msg = '\x01\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x05'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 6: Invalid Radio Basic Capability length (insufficient for op
        #         class fields)
        msg = '\x01\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x05\x01\x81\x1a'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 7: Invalid Radio Basic Capability length (insufficient for non-
        #         operable channels)
        msg = '\x01\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x05\x01\x81\x1a\x02\x01'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 8: Invalid HT Capability length
        msg = '\x02\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x05'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 9: Invalid VHT Capability length
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x12\x34\x56\x78\x02\x02\x00\x00\x00\x00\x00'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 10: Invalid HE Capability length (too few bytes for the end
        #          portion)
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x08\x01\x23\x45\x67\x89\xab\xcd\xef' + \
              '\x07\x08\x01\x01\x01\x01\x01\x01\x01\x01'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 11: Invalid HE Capability (MCS length not a multiple of 4)
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x07\x01\x23\x45\x67\x89\xab\xcd' + \
              '\x07\x08\x01\x01\x01\x01\x01\x01\x01\x01\x01'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 12a: Invalid AP Metrics (too short for even common portion)
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 12b: Invalid AP Metrics (too short for first ESP info)
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x00\x27' + \
              '\x01\x03\x40\x13\x13'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 12c: Invalid AP Metrics (invalid access category)
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x00\x27' + \
              '\x05\x03\x40\x13\x13\x27'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 12d: Invalid AP Metrics (invalid data format)
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x00\x27' + \
              '\x03\x0d\x40\x13\x13\x27'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 12e: Invalid AP Metrics (too short for second ESP info)
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x00\x27' + \
              '\x00\x02\x20\x08\x02\x26' + \
              '\x02\x01\x10\x25\x0a'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 12f: Invalid AP Metrics (extra bytes)
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x00\x27' + \
              '\x00\x02\x20\x08\x02\x26' + \
              '\x02\x01\x10\x25\x0a\x28\x17'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 13: Invalid Associated STA Link Metrics length
        msg = '\x06\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00\x00\x04\xe9\x00\x00\x01\xc2\x00\x00\x01\x6f'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 14: Invalid Associated STA Traffic Stats length
        msg = '\x07\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00\x00\xdd\x75\x00\x00\x87\x45\x00\x00\x16\x41' + \
              '\x00\x00\x07\xcf\x00\x00\x00\x1e\x00\x00\x00\x19' + \
              '\x00\x00\x00'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 15: Invalid Channel Preference length
        msg = '\x08\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 16: Invalid channel scan report length
        msg = '\x09\x11\x22\x33\x44\x55\x66\x01\x00'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 17: Invalid channel selection result length
        msg = '\x0a\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' +\
              '\x51\x06'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

        # Test 18: Invalid Unassociated STA Link Metrics length
        msg = '\x0b\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x73\x24\x36\x4c\x04'
        self.assertRaises(
            MessageMalformedError, multi_ap.unpack_payload_from_bytes,
            common.Version.VERSION2, False, msg)

    def test_ap_capability(self):
        """Verify the parsing of the AP Capability message."""
        # Test 1: Valid message with all capabilities negative.
        msg = '\x00\x01\x02\x03\x04\x05\x06\x01\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.APCapability._make(
            ('01:02:03:04:05:06', 1, False, False, False)), payload)

        # Test 2: Similar but in big endian format (which makes no difference)
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.APCapability._make(
            ('01:02:03:04:05:06', 1, False, False, False)), payload)

        # Test 3: Valid message with some capabilities positive
        msg = '\x00\x11\xac\x27\x93\x76\xfb\x10\x01\x00\x01'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.APCapability._make(
            ('11:ac:27:93:76:fb', 16, True, False, True)), payload)

        # Test 4: Same in big endian
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.APCapability._make(
            ('11:ac:27:93:76:fb', 16, True, False, True)), payload)

    def test_radio_basic_capability(self):
        """Verify the parsing of the Radio Basic Capability message."""
        # Test 1: Valid message with one op class and no non-operable channels
        msg = '\x01\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x03\x01\x51\x14\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.RadioBasicCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 3,
             [multi_ap.RadioBasicCapabilityOpClass._make((81, 20, []))])), payload)

        # Test 2: Same but in big endian (no difference)
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.RadioBasicCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 3,
             [multi_ap.RadioBasicCapabilityOpClass._make((81, 20, []))])), payload)

        # Test 3: Multiple op classes with no non-operable channels
        msg = '\x01\x13\x24\x57\x68\x9b\xac\x11\x12\x13\x14\x15\x16' + \
              '\x0f\x02\x51\x14\x00\x73\x16\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.RadioBasicCapability._make(
            ('13:24:57:68:9b:ac', '11:12:13:14:15:16', 15,
             [multi_ap.RadioBasicCapabilityOpClass._make((81, 20, [])),
              multi_ap.RadioBasicCapabilityOpClass._make((115, 22, []))])), payload)

        # Test 4: One op class with non-operable channels and two with no
        #         non-operable channels
        msg = '\x01\x13\x24\x57\x68\x9b\xac\x21\x22\x23\x24\x25\x26' + \
              '\x1f\x03\x51\x14\x00' + \
              '\x73\x16\x02\x24\x28\x7d\x1b\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.RadioBasicCapability._make(
            ('13:24:57:68:9b:ac', '21:22:23:24:25:26', 31,
             [multi_ap.RadioBasicCapabilityOpClass._make((81, 20, [])),
              multi_ap.RadioBasicCapabilityOpClass._make((115, 22, [36, 40])),
              multi_ap.RadioBasicCapabilityOpClass._make((125, 27, []))])), payload)

        # Test 5: Multiple op classes with non-operable channels
        msg = '\x01\x13\x24\x57\x68\x9b\xac\x31\x32\x33\x34\x35\x36' + \
              '\x0a\x03\x51\x14\x03\x02\x07\x09' + \
              '\x73\x16\x01\x2c\x7d\x1b\x02\x95\xa1'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.RadioBasicCapability._make(
            ('13:24:57:68:9b:ac', '31:32:33:34:35:36', 10,
             [multi_ap.RadioBasicCapabilityOpClass._make((81, 20, [2, 7, 9])),
              multi_ap.RadioBasicCapabilityOpClass._make((115, 22, [44])),
              multi_ap.RadioBasicCapabilityOpClass._make((125, 27, [149, 161]))])), payload)

    def test_ht_capability(self):
        """Verify the parsing of the HT Capability message."""
        # Test 1: Valid message with 2 SS for Tx and Rx and no 40 MHz support
        msg = '\x02\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x02\x02\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 2, 2, False, False,
             False)), payload)

        # Test 2: Same but in big endian (no difference)
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.HTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 2, 2, False, False,
             False)), payload)

        # Test 3: Valid message with 4 SS for Tx and 3 SS for Rx, short GI
        #         for 20 MHz
        msg = '\x02\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x04\x03\x01\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 4, 3, True, False,
             False)), payload)

        # Test 4: Valid message with 4 SS for Tx and 3 SS for Rx, short GI
        #         for 40 MHz
        msg = '\x02\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x04\x03\x00\x01\x01'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 4, 3, False, True,
             True)), payload)

        # Test 4: Valid message with 1 SS for Tx and 1 SS for Rx, no short GI
        #         for 40 MHz
        msg = '\x02\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x01\x01\x00\x00\x01'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 1, 1, False, False,
             True)), payload)

    def test_vht_capability(self):
        """Verify the parsing of the VHT Capability message."""
        # Test 1: Valid message with 2 SS for Tx and Rx and no optional support
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x12\x34\x87\x65\x02\x02\x00\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x6587, 2, 2,
             False, False, False, False, False, False)), payload)

        # Test 2: Same but in big endian (only the MCS representation changes)
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x34\x12\x65\x87\x02\x02\x00\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x6587, 2, 2,
             False, False, False, False, False, False)), payload)

        # Test 3: Valid message with 8 SS for Tx and 7 SS for Rx, short GI
        #         for 80 MHz
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x27\x95\x0a\x6f\x08\x07\x01\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x9527, 0x6f0a, 8, 7,
             True, False, False, False, False, False)), payload)

        # Test 4: Same as previous test but with short GI for 160 MHz
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x27\x95\x0a\x6f\x08\x07\x01\x01\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x9527, 0x6f0a, 8, 7,
             True, True, False, False, False, False)), payload)

        # Test 5: Same as previous test but with 80+80 MHz support
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x27\x95\x0a\x6f\x08\x07\x01\x01\x01\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x9527, 0x6f0a, 8, 7,
             True, True, True, False, False, False)), payload)

        # Test 6: Same as previous test but with 160 MHz support
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x27\x95\x0a\x6f\x08\x07\x01\x01\x01\x01\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x9527, 0x6f0a, 8, 7,
             True, True, True, True, False, False)), payload)

        # Test 7: Same as previous test but with SU beamformer support
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x27\x95\x0a\x6f\x08\x07\x01\x01\x01\x01\x01\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x9527, 0x6f0a, 8, 7,
             True, True, True, True, True, False)), payload)

        # Test 8: Same as previous test but with MU beamformer support
        msg = '\x03\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x27\x95\x0a\x6f\x08\x07\x01\x01\x01\x01\x01\x01'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.VHTCapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x9527, 0x6f0a, 8, 7,
             True, True, True, True, True, True)), payload)

    def test_he_capability(self):
        """Verify the parsing of the HE Capability message."""
        # Test 1: Valid message with 2 SS for Tx and Rx and no optional support
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 2, 2, False, False,
             False, False, False, False, False, False, False)), payload)

        # Test 2: Same in big endian, only the MCS info is impacted
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x1234, 0x5678,
             None, None, None, None, 2, 2, False, False,
             False, False, False, False, False, False, False)), payload)

        # Test 3: Valid message with 7 SS for Tx and 8 SS for Rx, 80+80 MHz
        #         support
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x0c\x10\x21\x32\x43\xff\xff\xff\xff\x54\x65\x76\x87' + \
              '\x07\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x2110, 0x4332,
             0xffff, 0xffff, 0x6554, 0x8776, 7, 8, True, False,
             False, False, False, False, False, False, False)), payload)

        # Test 4: Same as above but with 160 MHz support and not 80+80 MHz
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x08\x01\x12\x23\x34\x45\x56\x67\x78' + \
              '\x07\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x1201, 0x3423,
             0x5645, 0x7867, None, None, 7, 8, False, True,
             False, False, False, False, False, False, False)), payload)

        # Test 5: Same as above but with SU beamformer capability
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x00\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, False, False, False, False, False, False)), payload)

        # Test 6: Same as above but with MU beamformer capability
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x01\x00\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, True, False, False, False, False, False)), payload)

        # Test 7: Same as above but with UL MU-MIMO capable
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x01\x01\x00\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, True, True, False, False, False, False)), payload)

        # Test 8: Same as above but with UL MU-MIMO + OFDMA capable
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x01\x01\x01\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, True, True, True, False, False, False)), payload)

        # Test 9: Same as above but with DL MU-MIMO + OFDMA capable
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x01\x01\x01\x01\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, True, True, True, True, False, False)), payload)

        # Test 10: Same as above but with UL OFDMA capable
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x01\x01\x01\x01\x01\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, True, True, True, True, True, False)), payload)

        # Test 11: Same as above but with DL OFDMA capable
        msg = '\x04\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x04\x12\x34\x56\x78\x07\x08\x01\x01\x01\x01\x01\x01\x01\x01\x01'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.HECapability._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 0x3412, 0x7856,
             None, None, None, None, 7, 8, True, True,
             True, True, True, True, True, True, True)), payload)

    def test_ap_metrics(self):
        """Verify the parsing of the AP Metrics message."""
        # Test 1: Single ESP info in big endian
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x37\x00\x27\x01\x03\x40\x13\x13\x88'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.APMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 55, 39,
             [multi_ap.EstimatedServiceParameters(multi_ap.AccessCategory.BE,
                                                  multi_ap.DataFormat.AMSDU_AMPDU,
                                                  64, 19, 5000)])), payload)

        # Test 2: Same as above but little endian
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x37\x27\x00\x01\x03\x40\x13\x88\x13'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.APMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 55, 39,
             [multi_ap.EstimatedServiceParameters(multi_ap.AccessCategory.BE,
                                                  multi_ap.DataFormat.AMSDU_AMPDU,
                                                  64, 19, 5000)])), payload)

        # Test 3: Multiple ESP info in big endian
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x00\x27' + \
              '\x00\x02\x20\x08\x02\x26' + \
              '\x02\x01\x10\x25\x0a\x28'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.APMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 55, 39,
             [multi_ap.EstimatedServiceParameters(multi_ap.AccessCategory.BK,
                                                  multi_ap.DataFormat.AMPDU,
                                                  32, 8, 550),
              multi_ap.EstimatedServiceParameters(multi_ap.AccessCategory.VI,
                                                  multi_ap.DataFormat.AMSDU,
                                                  16, 37, 2600)])), payload)

        # Test 4: Multiple ESP info in little endian
        msg = '\x05\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x37\x27\x00' + \
              '\x00\x02\x20\x08\x26\x02' + \
              '\x02\x01\x10\x25\x28\x0a'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.APMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 55, 39,
             [multi_ap.EstimatedServiceParameters(multi_ap.AccessCategory.BK,
                                                  multi_ap.DataFormat.AMPDU,
                                                  32, 8, 550),
              multi_ap.EstimatedServiceParameters(multi_ap.AccessCategory.VI,
                                                  multi_ap.DataFormat.AMSDU,
                                                  16, 37, 2600)])), payload)

    def test_assoc_sta_link_metrics(self):
        """Verify the parsing of the Associated STA Link Metrics message."""
        # Test 1: Valid message with single BSSID (all that is supported
        #         right now) in big endian
        msg = '\x06\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00\x00\x04\xe9\x00\x00\x01\xc2\x00\x00\x01\x6f\x19'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.AssocSTALinkMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 1257, 450, 367, 25)),
            payload)

        # Test 2: Same as above but little endian
        msg = '\x06\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\xe9\x04\x00\x00\xc2\x01\x00\x00\x6f\x01\x00\x00\x19'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.AssocSTALinkMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 1257, 450, 367, 25)),
            payload)

    def test_assoc_sta_traffic_stats(self):
        """Verify the parsing of the Associated STA Traffic Stats message."""
        # Test 1: Valid message in big endian
        msg = '\x07\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00\x00\xdd\x75\x00\x00\x87\x45\x00\x00\x16\x41' + \
              '\x00\x00\x07\xcf\x00\x00\x00\x1e\x00\x00\x00\x19' + \
              '\x00\x00\x00\x1f'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.AssocSTATrafficStats._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 56693, 34629, 5697,
             1999, 30, 25, 31)), payload)

        # Test 2: Same as above but little endian
        msg = '\x07\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x75\xdd\x00\x00\x45\x87\x00\x00\x41\x16\x00\x00' + \
              '\xcf\x07\x00\x00\x1e\x00\x00\x00\x19\x00\x00\x00' + \
              '\x1f\x00\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.AssocSTATrafficStats._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 56693, 34629, 5697,
             1999, 30, 25, 31)), payload)

    def test_channel_preference(self):
        # Test 1: No explicit pairs, little endian
        msg = '\x08\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  False, msg)
        self.assertEquals(multi_ap.ChannelPreference._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', [])
            ), payload)

        # Test 2: No explicit pairs, big endian (no difference from LE)
        msg = '\x08\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  True, msg)
        self.assertEquals(multi_ap.ChannelPreference._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', [])
            ), payload)

        # Test 3: 2 explicit pairs
        msg = '\x08\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x02\x51\x07\x0b\x01\x73\x24\x0a\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  False, msg)
        self.assertEquals(multi_ap.ChannelPreference._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06',
                [multi_ap.ChannelPreferenceOpClass._make((81, 7, 11, 1)),
                 multi_ap.ChannelPreferenceOpClass._make((115, 36, 10, 0))])
            ), payload)

    def test_channel_scan_report(self):
        # Test 1: No channels and neighbors in report
        msg = '\x09\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  False, msg)
        self.assertEquals(multi_ap.ChannelScanReport._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', [], [])
            ), payload)

        # Test 2: Only two channel datas in report (Big Endian)
        msg = '\x09\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x02\x00' + \
              '\x03\x00\x00\x00\x00\x09\x00\x00\x00\x11' + \
              '\x00\x08\x00\x10\x00\x00\x00\x20\x00\x00\x00\x02\x02\x03\x04' + \
              '\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x0c' + \
              '\x00\x00\x00\x0d\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00\x09' + \
              '\x06\x01\x00\x00\x00\xa1\x00\x00\x00\xa9' + \
              '\x00\x0a\x00\x1a\x00\x00\x00\x30\x00\x00\x00\x04\x12\x13\x14' + \
              '\x00\x00\x00\x1a\x00\x00\x00\x1b\x00\x00\x00\x1c' + \
              '\x00\x00\x00\x1d\x00\x00\x00\x1e\x00\x00\x00\x1f\x00\x00\x00\x19'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  True, msg)
        self.assertEquals(multi_ap.ChannelScanReport._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06',
             [multi_ap.ChannelScanChanData._make(
                (3, 0, 9, 17, 8, 16, 32, 2, 2, 3, 4, 10, 11, 12, 13, 14, 15, 9)),
              multi_ap.ChannelScanChanData._make(
                (6, 1, 161, 169, 10, 26, 48, 4, 18, 19, 20, 26, 27, 28, 29, 30, 31, 25))],
             [])
            ), payload)

        # Test 3: Only two neighbor data in report (Big Endian)
        msg = '\x09\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x00\x02' + \
              '\x0b\x00\x00\x00\x07\x00\x00\x00\x60\xa1\xb2\xc3\xd4\xe5\xf6' + \
              '\x09\x00\x00\x00\x17\x00\x00\x00\x61\x1a\x1b\x1c\x1d\x1e\x1f'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  True, msg)
        self.assertEquals(multi_ap.ChannelScanReport._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06',
             [],
             [multi_ap.ChannelScanNeighborData._make(
                (11, 7, 96, "a1:b2:c3:d4:e5:f6")),
              multi_ap.ChannelScanNeighborData._make(
                (9, 23, 97, "1a:1b:1c:1d:1e:1f"))])
            ), payload)

        # Test 4: 1 channel and 1 neighbor data in report (Big Endian)
        msg = '\x09\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x01\x01' + \
              '\x03\x01\x00\x00\x00\x09\x00\x00\x00\x01' + \
              '\x00\x08\x00\x10\x00\x00\x00\x20\x00\x00\x00\x02\x02\x03\x04' + \
              '\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x0c' + \
              '\x00\x00\x00\x0d\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00\x09' + \
              '\x06\x00\x00\x00\x07\x00\x00\x00\x60\xaa\xbb\xcc\xdd\xee\xff'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  True, msg)
        self.assertEquals(multi_ap.ChannelScanReport._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06',
             [multi_ap.ChannelScanChanData._make(
                (3, 1, 9, 1, 8, 16, 32, 2, 2, 3, 4, 10, 11, 12, 13, 14, 15, 9))],
             [multi_ap.ChannelScanNeighborData._make(
                (6, 7, 96, "aa:bb:cc:dd:ee:ff"))])
            ), payload)

        # Test 5: 1 channel and 1 neighbor data in report (Little Endian)
        msg = '\x09\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06\x01\x01' + \
              '\x03\x01\x09\x00\x00\x00\x01\x00\x00\x00' + \
              '\x08\x00\x10\x00\x20\x00\x00\x00\x02\x00\x00\x00\x02\x03\x04' + \
              '\x0a\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00' + \
              '\x0d\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00\x09\x00\x00\x00' + \
              '\x06\x07\x00\x00\x00\x60\x00\x00\x00\xaa\xbb\xcc\xdd\xee\xff'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2,  False, msg)
        self.assertEquals(multi_ap.ChannelScanReport._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06',
             [multi_ap.ChannelScanChanData._make(
                (3, 1, 9, 1, 8, 16, 32, 2, 2, 3, 4, 10, 11, 12, 13, 14, 15, 9))],
             [multi_ap.ChannelScanNeighborData._make(
                (6, 7, 96, "aa:bb:cc:dd:ee:ff"))])
            ), payload)

    def test_channel_selection_result(self):
        # Test 1: Device specific result (Big Endian)
        msg = '\x0a\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x51\x06\x53\x06\x01\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.ChannelSelectionResult._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 81, 6, 83, 6, 1, 0)
            ), payload)

        # Test 2: Device specific result (Little Endian, but same as BE)
        msg = '\x0a\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x51\x06\x53\x06\x01\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.ChannelSelectionResult._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 81, 6, 83, 6, 1, 0)
            ), payload)

        # Test 3: Global optimum result (Big Endian)
        msg = '\x0a\x00\x00\x00\x00\x00\x00\xa1\xa2\xa3\xa4\xa5\xa6' + \
              '\x51\x06\x53\x06\x01\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.ChannelSelectionResult._make(
            ('00:00:00:00:00:00', 'a1:a2:a3:a4:a5:a6', 81, 6, 83, 6, 1, 0)
            ), payload)

    def test_unassoc_sta_link_metrics(self):
        """Verify the parsing of Unassociated STA Link Metrics message."""
        # Test 1: Valid message in big endian
        msg = '\x0b\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x73\x24\x36\x00\x00\x04\x4c'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, True, msg)
        self.assertEquals(multi_ap.UnassocSTALinkMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 115, 36, 54, 1100)),
            payload)

        # Test 2: Same as above but little endian
        msg = '\x0b\x11\x22\x33\x44\x55\x66\x01\x02\x03\x04\x05\x06' + \
              '\x73\x24\x36\x4c\x04\x00\x00'
        payload = multi_ap.unpack_payload_from_bytes(
            common.Version.VERSION2, False, msg)
        self.assertEquals(multi_ap.UnassocSTALinkMetrics._make(
            ('11:22:33:44:55:66', '01:02:03:04:05:06', 115, 36, 54, 1100)),
            payload)


if __name__ == '__main__':
    unittest.main()
