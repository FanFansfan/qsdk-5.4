PART_NAME=firmware
REQUIRE_IMAGE_METADATA=1

RAMFS_COPY_BIN='fw_printenv fw_setenv'
RAMFS_COPY_DATA='/etc/fw_env.config /var/lock/fw_printenv.lock'

platform_check_image() {
	return 0;
}

platform_do_upgrade() {
	case "$(board_name)" in
	wxr-2533dhp)
		buffalo_upgrade_prepare_ubi
		CI_ROOTPART="ubi_rootfs"
		nand_do_upgrade "$1"
		;;
	ap-cp01-c1|\
	ap-cp01-c3|\
	ap-cp03-c1)
		CI_ROOTPART="ubi_rootfs"
		CI_IPQ807X=1
		nand_do_upgrade "$1"
		;;
	ap-hk14 |\
	ap-ac04)
		CI_UBIPART="rootfs_1"
		nand_do_upgrade "$1"
		;;
	wpq864 |\
	d7800 |\
	r7500 |\
	r7500v2 |\
	r7800 |\
	ap148 |\
	ap161 |\
        core-517 |\
	rg-mtfi-m520 |\
	nbg6817)
		nand_do_upgrade "$1"
		;;
	ea8500)
		platform_do_upgrade_linksys "$1"
		;;
	c2600)
		PART_NAME="os-image:rootfs"
		MTD_CONFIG_ARGS="-s 0x200000"
		default_do_upgrade "$1"
		;;
	vr2600v)
		PART_NAME="kernel:rootfs"
		MTD_CONFIG_ARGS="-s 0x200000"
		default_do_upgrade "$1"
		;;
	wg2600hp |\
	*)
		default_do_upgrade "$1"
		;;
	esac
}

platform_nand_pre_upgrade() {
	case "$(board_name)" in
	rg-mtfi-m520)
		ruijie_do_upgrade "$1"
		;;
	core-517)
		norton_do_upgrade "$1"
		;;
	nbg6817)
		zyxel_do_upgrade "$1"
		;;
	esac
}
