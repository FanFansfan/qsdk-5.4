/*
 * Copyright (c) 2012, 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <sys/socket.h>
#include <linux/types.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <a_osapi.h>
#include <athtypes_linux.h>
#include "athdiag_read_write.h"

int main(int argc, char **argv)
{
	int c, dev;
	unsigned int address = 0;
	unsigned int wordcount = 1;
	A_UINT32 param = 0;
	char devicename[PATH_MAX];
	char ifname[IFNAME_MAX];
	unsigned int cmd = 0;
	unsigned int bitwise_mask = 0;
	unsigned int bar = 0;

	progname = argv[0];

	if (argc == 1)
		usage_lite();

	flag = 0;
	memset(devicename, '\0', sizeof(devicename));

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"address", 1, NULL, 'a'},
			{"get", 0, NULL, 'g'},
			{"quiet", 0, NULL, 'q'},
			{"set", 0, NULL, 's'},
			{"value", 1, NULL, 'p'},
			{"count", 1, NULL, 'z'},
			{"wifi",1,NULL,'W'},
			{"bar",1,NULL,'B'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "a:gqsp:z:W:B:", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'g':
				cmd = DIAG_READ_WORD;
				break;

			case 's':
				cmd = DIAG_WRITE_WORD;
				break;

			case 'a':
				address = parse_address(optarg);
				flag |= ADDRESS_FLAG;
				break;

			case 'p':
				param = strtoul(optarg, NULL, 0);
				flag |= PARAM_FLAG;
				break;

			case 'q':
				flag |= QUIET_FLAG;
				break;

			case 'z':
				wordcount = parse_address(optarg);
				flag |= WORDCOUNT_FLAG;
				break;

			case 'W':
				flag |= INTERFACE_FLAG;
				strlcpy(ifname, optarg, sizeof(ifname));
				break;

			case 'B':
				bar = parse_address(optarg);
				break;

			default:
				fprintf(stderr, "Cannot understand '%s'\n", argv[option_index]);
				usage_lite();
		}
	}

	dev = athdiag_open_sys_interface(ifname, devicename);

	switch(cmd)
	{
		case DIAG_READ_WORD:
			if ((flag & (ADDRESS_FLAG)) == (ADDRESS_FLAG))
			{
				if(bar) {
					athdiag_read_write_direct(address, param, bar, cmd);
				} else {
					athdiag_read_word(dev, wordcount, address, param);
				}
			}
			else usage_lite();
			break;

		case DIAG_WRITE_WORD:
			if ((flag & (ADDRESS_FLAG | PARAM_FLAG)) == (ADDRESS_FLAG | PARAM_FLAG))
			{
				if(bar) {
					athdiag_read_write_direct(address, param, bar, cmd);
				} else {
					athdiag_write_word(dev, address, param, bitwise_mask);
				}
			}
			else usage_lite();
			break;

		default:
			usage_lite();
	}

	exit (0);
}
