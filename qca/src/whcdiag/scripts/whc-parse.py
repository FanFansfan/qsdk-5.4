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

import enum
import datetime
import json

from whcdiag.io.filesystem import FileReaderRaw
import whcdiag.msgs.parser as diagparser
import whcdiag.hydmsgs.parser as hyddiagparser


class EnumEncoder(json.JSONEncoder):
    """Custom encoder that handles :class:`enum.Enum` subtypes.

    These may be serialized either with their integer value or the
    string representation. Note that no consideration is given towards
    deserialization as this conversion to JSON is expected to be one
    way.
    """

    def __init__(self, use_names=False, *args, **kwargs):
        """Initialize the encoder with its behavior params.

        Args:
            use_names (bool): whether to serialize using the human
                readable string names or to use the integer value
        """
        super(EnumEncoder, self).__init__(*args, **kwargs)
        self._use_names = use_names

    def default(self, obj):
        """Perform the necessary conversion of the object in question.

        Args:
            obj: the object to be serialized
        """
        if isinstance(obj, enum.Enum):
            if not self._use_names:
                return obj.value
            else:
                return str(obj)

        # This will generate a TypeError
        return JSONEncoder.default(self, obj)


def force_dict(obj):
    """Convert the object into a dictionary if possible.

    If it is a :class:`collections.namedtuple` type, convert it into a
    dictionary. If it is a :obj:`list` type, apply this rule recursively.
    Otherwise, return the object as is.

    Args:
        obj: the object to be converted

    Returns:
        the converted object, or the original one if there is nothing to
        do
    """
    if isinstance(obj, tuple) and hasattr(obj, '_asdict'):
        return force_dict(obj._asdict())
    elif isinstance(obj, list):
        return map(force_dict, obj)
    else:
        return obj


def print_msg_json(output_fh, timestamp_str, src_addr, header, payload,
                   use_names=False, no_ip=False, no_timestamp=False):
    """Process a single parsed log.

    Args:
        output_fh (:object:`file`): the file handle to use for output
        timestamp_str (str): the time at which the log was generated
            in a human-readable format
        src_addr (str): the address of the node that emitted the
            log
        header (str): log header
        payload (str): log payload
        use_names (bool): whether to serialize using the human
            readable string names or to use the integer value
        no_ip (bool): if True, omit the source IP address from the
            message metadata
        no_timestamp (bool): if True, omit the receive timestamp from
            the message metadata
    """
    msg_name = type(payload).__name__
    payload = force_dict(payload)
    for key in payload:
        payload[key] = force_dict(payload[key])

    metadata = {}
    if not no_ip:
        metadata['src_addr'] = src_addr

    if not no_timestamp:
        metadata['timestamp'] = timestamp_str

    if header:
        metadata['header'] = force_dict(header)

    data = {msg_name: payload}
    if metadata:
        data['metadata'] = metadata

    enc = EnumEncoder(use_names)
    print >>output_fh, enc.encode(data)


def print_msg_text(output_fh, timestamp_str, src_addr, header, payload,
                   no_ip=False, no_timestamp=False, **kwargs):
    """Output a single parsed log in the normal text format.

    Args:
        output_fh (:object:`file`): the file handle to use for output
        timestamp_str (str): the time at which the log was generated
            in a human-readable format
        src_addr (str): the address of the node that emitted the
            log
        header (str): log header
        payload (str): log payload
        no_ip (bool): if True, omit the source IP address from the
            message metadata
        no_timestamp (bool): if True, omit the receive timestamp from
            the message metadata
    """
    if not no_timestamp:
        print >>output_fh, "%s\t" % timestamp_str,

    if not no_ip:
        print >>output_fh, "%s\t" % src_addr,

    if header:
        print >>output_fh, "%s\t%s" % (header, payload)
    else:
        print >>output_fh, payload


def print_msg(output_fh, timestamp_str, src_addr, header, payload,
              json, **kwargs):
    """Process a single parsed log.

    Args:
        output_fh (:object:`file`): the file handle to use for output
        timestamp_str (str): the time at which the log was generated
            in a human-readable format
        src_addr (str): the address of the node that emitted the
            log
        header (str): log header
        payload (str): log payload
        json (bool): whether to output in JSON format
    """
    if json:
        print_msg_json(output_fh, timestamp_str, src_addr, header, payload,
                       **kwargs)
    else:
        print_msg_text(output_fh, timestamp_str, src_addr, header, payload,
                       **kwargs)


def output_msg(output_fh, timestamp, src_addr, data, include_date,
               include_header, parser, reassembler, **kwargs):
    """Process a single message read from the file.

    Args:
        output_fh (:object:`file`): the file handle to use for output
        timestamp (float): the time at which the log was generated
            (as returned from :func:`time.time`)
        src_addr (str): the address of the node that emitted the
            log
        data (str): the actual data that was logged
        include_date (bool): whether to include the full date or only
            the time
        include_header (bool): whether to include the diagnostic
            logging header information or not
        parser (:object:`class`): parser to use to parse messages
        reassembler (:object:`class`): used to reassemble fragmented logs
    """
    header, payload = parser.unpack_msg(data)

    dt = datetime.datetime.fromtimestamp(timestamp)
    if include_date:
        timestamp_str = dt.isoformat()
    else:
        timestamp_str = dt.time().isoformat()

    if reassembler:
        if include_header:
            object_to_store = (timestamp_str, header, payload)
        else:
            object_to_store = (timestamp_str, None, payload)

        (should_output_current, entries) = reassembler.reassemble(
            header, src_addr, object_to_store)

        # Output any reassembled entries
        if entries:
            for entry in entries:
                print_msg(output_fh, entry[1][0], src_addr, entry[1][1],
                          entry[1][2], **kwargs)

    else:
        should_output_current = True

    # Output the current entry if required
    if should_output_current:
        if include_header:
            print_msg(output_fh, timestamp_str, src_addr, header, payload,
                      **kwargs)
        else:
            print_msg(output_fh, timestamp_str, src_addr, None, payload,
                      **kwargs)


def parse_logs(input_file, output_fh, *args, **kwargs):
    """Read all of the logs out of the file and output them.

    Args:
        input_file (str): the name of the input file
        output_fh (:object:`file`): the file handle to use for output
    """
    with FileReaderRaw(input_file) as reader:
        num_msgs = 0
        msg = reader.read_msg()
        while msg is not None:
            output_msg(output_fh, *msg, **kwargs)
            num_msgs += 1

            msg = reader.read_msg()

        logging.info("Processed %d messages", num_msgs)


if __name__ == '__main__':
    import argparse
    import logging
    import sys

    parser = argparse.ArgumentParser(description="Parse and display " +
                                                 "previously captured " +
                                                 "diagnostic logs " +
                                                 "to a file")

    parser.add_argument('-i', '--input', help='Capture file to parse',
                        required=True)
    parser.add_argument('-o', '--output',
                        help='Output filename (stdout if not specified)',
                        required=False)
    parser.add_argument('-a', '--append', help='Append to log file',
                        default=False, action='store_true')
    parser.add_argument('--hyd', help='Parse as hyd format',
                        action='store_true')

    format_group = parser.add_argument_group('Output format options')
    format_group.add_argument('-t', '--time', action='store_true',
                              default=False,
                              help='Output only the timestamp (not the date)')
    format_group.add_argument('-j', '--json', action='store_true',
                              default=False,
                              help='Output in JSON format (one record per line')
    format_group.add_argument('--no-header', action='store_true',
                              default=False,
                              help='Do not output the diaglog header')
    format_group.add_argument('--no-ip', action='store_true',
                              default=False,
                              help='Do not output the source IP')
    format_group.add_argument('--no-timestamp', action='store_true',
                              default=False,
                              help='Do not output the receive timestamp')

    json_group = parser.add_argument_group('JSON output format options')
    format_group.add_argument('--use-enum-names', action='store_true',
                              default=False,
                              help='When outputting enum values, use string ' +
                                   'names instead of the integer value')

    log_group = parser.add_argument_group('Logging options')
    log_group.add_argument('-v', '--verbose', action='store_true',
                           default=False,
                           help='Enable debug level logging')
    log_group.add_argument('-l', '--logfile', default=None,
                           help='Specify filename to use for debug logging')

    args = parser.parse_args()

    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG

    format = '%(asctime)-15s %(levelname)-8s %(name)-15s %(message)s'
    logging.basicConfig(filename=args.logfile, level=level,
                        format=format)

    if args.hyd:
        parser = hyddiagparser
        reassembler = hyddiagparser.Reassembler()
    else:
        parser = diagparser
        reassembler = None

    kwargs = {'include_date': not args.time,
              'include_header': not args.no_header,
              'parser': parser,
              'reassembler': reassembler,
              'json': args.json, 'use_names': args.use_enum_names,
              'no_ip': args.no_ip, 'no_timestamp': args.no_timestamp}
    if args.output is None:
        parse_logs(args.input, sys.stdout, **kwargs)
    else:
        mode = "w+" if args.append else "w"
        with open(args.output, mode) as output_fh:
            parse_logs(args.input, output_fh, **kwargs)
