#!/bin/sh
#
# Copyright (c) 2020, The Linux Foundation. All rights reserved.

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

include /lib/wifi

function do_init_kernel54_config()
{
	echo -n "/ini" > /sys/module/firmware_class/parameters/path
	update_ini_file cfg80211_config "1"

	[ -f /tmp/sysinfo/board_name ] && {
		board_name=$(cat /tmp/sysinfo/board_name)
	}

	if [ "$board_name" = "ap-hk10-c1"  ]; then
		update_internal_ini global_i.ini mode_2g_phyb 1
	fi

	#Temporarily keep coldboot calibration disabled
	touch /ini/firmware_rdp_feature.ini
	touch /ini/firmware_rdp_feature_512P.ini

	is_ftm=`grep wifi_ftm_mode /proc/cmdline | wc -l`
	is_wal=`grep waltest_mode /proc/cmdline | wc -l`
	if [ $is_wal = 1 ]; then
		echo 3 > /sys/module/cnss2/parameters/driver_mode
	elif [ $is_ftm = 1 ]; then
		dmesg -n1
		do_cold_boot_calibration_qcawificfg80211
		# If coldboot calibration is enabled in FW INI file, driver_mode
		# would be set to 10. After coldboot calibration, driver would
		# automatically switch to FTM mode.
		# If coldboot calibration is disabled, driver_mode should be
		# set to 1 (FTM) here.
		if [ "$(cat /sys/module/cnss2/parameters/driver_mode)" == 10 ]; then
			echo "Entering FTM mode operation after Coldboot Calibration" > /dev/console
		else
			echo "Entering FTM mode operation" > /dev/console
			echo 1 > /sys/module/cnss2/parameters/driver_mode
		fi
	else
		do_cold_boot_calibration_qcawificfg80211
	fi
}
