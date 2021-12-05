/*
*Copyright (c) 2020 Qualcomm Technologies, Inc.
*All Rights Reserved.
*Confidential and Proprietary - Qualcomm Technologies, Inc.
*/

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>

enum minidump_tlv_type_t {
    QCA_WDT_LOG_DUMP_TYPE_INVALID,
    QCA_WDT_LOG_DUMP_TYPE_UNAME,
    QCA_WDT_LOG_DUMP_TYPE_DMESG,
    QCA_WDT_LOG_DUMP_TYPE_LEVEL1_PT,
    QCA_WDT_LOG_DUMP_TYPE_WLAN_MOD,
    QCA_WDT_LOG_DUMP_TYPE_WLAN_MOD_DEBUGFS,
    QCA_WDT_LOG_DUMP_TYPE_WLAN_MOD_INFO,
    QCA_WDT_LOG_DUMP_TYPE_WLAN_MMU_INFO,
    QCA_WDT_LOG_DUMP_TYPE_EMPTY,
};

#define MINIDUMP_IOCTL_MAGIC    'm'
#define MINIDUMP_IOCTL_PREPARE_HDR _IOR(MINIDUMP_IOCTL_MAGIC, 0, int)
#define MINIDUMP_IOCTL_PREPARE_SEG _IOR(MINIDUMP_IOCTL_MAGIC, 1, int)
#define MINIDUMP_IOCTL_PREPARE_TYP _IOR(MINIDUMP_IOCTL_MAGIC, 2, int)
#define MINIDUMP_IOCTL_PREPARE_PHY _IOR(MINIDUMP_IOCTL_MAGIC, 3, int)

#define LOG_SIZE 250

struct minidump_hdr {
    int total_size;
    int num_seg;
    int flag;
    unsigned char *type;
    int *seg_size;
    unsigned long *phy;
} hdr;

struct minidump_handle {
	int dev_handle;
	int log_file;
	char *path;
} hdl;

/*
* Function: minidump_free
*
* Description: Free allocated resources and close open filepointers
*
* @param: none
*
* Return: none
*/
void minidump_free() {

	free(hdr.seg_size);
	free(hdr.phy);
	free(hdr.type);
	close(hdl.dev_handle);
	close(hdl.log_file);
}

/*
* Function: minidump_dump_segments
*
* Description: segment dumpfile into individual dump binaries
* and label them based on dump type.
*
* @param: none
*
* Return 0 on success; EINVAL on failure
*/
int minidump_dump_segments() {
int i = 0;
int dump_seg = 0;
int ret = 0;
int offset = 0;
char dump_seg_name[LOG_SIZE];
char *dump = NULL;

	for(i=0;i<hdr.num_seg; i++) {
		dump = (char *)malloc(hdr.seg_size[i]);
		if (!dump) {
			printf("error in allocation for dump\n");
			return -EINVAL;
		}

		switch(hdr.type[i]) {
			case QCA_WDT_LOG_DUMP_TYPE_WLAN_MOD_INFO:
				snprintf(dump_seg_name, sizeof(dump_seg_name), "%s/MOD_INFO.txt", hdl.path);
				break;
			case QCA_WDT_LOG_DUMP_TYPE_WLAN_MMU_INFO:
				snprintf(dump_seg_name, sizeof(dump_seg_name), "%s/MMU_INFO.txt", hdl.path);
				break;
			case QCA_WDT_LOG_DUMP_TYPE_WLAN_MOD_DEBUGFS:
				snprintf(dump_seg_name, sizeof(dump_seg_name), "%s/DEBUGFS_%lx.BIN", hdl.path,hdr.phy[i]);
				break;
			default:
				snprintf(dump_seg_name, sizeof(dump_seg_name), "%s/%lx.BIN", hdl.path, hdr.phy[i]);
				break;
		}

		dump_seg = open(dump_seg_name,O_RDWR | O_CREAT);
		ret = pread(hdl.log_file, dump, hdr.seg_size[i],offset);
		if (ret < 0) {
			printf("error in read %d\n",ret);
			minidump_free();
			return -EINVAL;
		}
		ret = pwrite(dump_seg, dump, hdr.seg_size[i],0);
		if (ret < 0) {
			printf("error in read %d\n",ret);
			minidump_free();
			return -EINVAL;
		}
		offset=offset + hdr.seg_size[i];
		free(dump);
		close(dump_seg);
	}
return 0;
}

/*
* Function: minidump_prepare
*
* Description: Prepare dumpfiles by reading metadata information for
* dump segments
*
* @param: none
*
* Return 0 on success; EINVAL on failure
*/
int minidump_prepare() {

	int ret = 0;

	ret = ioctl(hdl.dev_handle, MINIDUMP_IOCTL_PREPARE_HDR, &hdr);
	if (ret < 0) {
		printf("ioctl read error %d\n",ret);
		return -EINVAL;
	}

	hdr.seg_size = (int *)malloc(sizeof(int) * hdr.num_seg);
	hdr.phy = (unsigned long *)malloc(sizeof(unsigned long) * hdr.num_seg);
	hdr.type = (unsigned char *)malloc(sizeof(unsigned char) * hdr.num_seg);

	if (!hdr.seg_size || !hdr.phy || !hdr.type) {
		printf("Error in allocation for metadata headers\n");
		return -EINVAL;
	}

	char internal_buf[hdr.total_size];
	memset(internal_buf,0,hdr.total_size);
	memset(hdr.seg_size,0,(sizeof(int) * hdr.num_seg));
	memset(hdr.phy,0,(sizeof(unsigned long) * hdr.num_seg));
	memset(hdr.type,0,(sizeof(unsigned char) * hdr.num_seg));

	ret = ioctl(hdl.dev_handle, MINIDUMP_IOCTL_PREPARE_SEG, hdr.seg_size);
	if (ret < 0) {
		printf("ioctl read error %d\n",ret);
		minidump_free();
		return -EINVAL;
	}

	ret = ioctl(hdl.dev_handle, MINIDUMP_IOCTL_PREPARE_TYP, hdr.type);
	if (ret < 0) {
		printf("ioctl read error %d\n",ret);
		minidump_free();
		return -EINVAL;
	}

	ret = ioctl(hdl.dev_handle, MINIDUMP_IOCTL_PREPARE_PHY, hdr.phy);
	if (ret < 0) {
		printf("ioctl read error %d\n",ret);
		minidump_free();
		return -EINVAL;
	}

	ret = read(hdl.dev_handle , internal_buf, hdr.total_size);
	if (ret < 0) {
		printf("read error %d\n",ret);
		minidump_free();
		return -EINVAL;
	}

	ret = write(hdl.log_file , internal_buf, hdr.total_size);
	if (ret < 0) {
		printf("read error %d\n",ret);
		minidump_free();
		return -EINVAL;
	}
	return 0;
}

int main(int args, char *argv[]) {

	char log[LOG_SIZE];
	int ret = 0;
	hdl.dev_handle = 0;
	hdl.log_file = 0;
	hdl.path = argv[2];

	memset(&hdr,0,sizeof(hdr));

	/* Open and close device node file if livedump
			option is disabled */
	if(!(int)(uintptr_t)argv[1]) {
		hdl.dev_handle = open("/dev/minidump",O_RDONLY);
		close(hdl.dev_handle);
		return 0;
	}

	/* Open file pointer to minidump device node
		/dev/minidump */
	hdl.dev_handle = open("/dev/minidump",O_RDONLY);
	snprintf(log, sizeof(log), "%s/log.txt", hdl.path);
	/* Open file pointer to minidump log file */
	hdl.log_file = open(log,O_RDWR | O_CREAT);

	/* Prepare minidump metadata information */
	ret = minidump_prepare();
	if (ret) {
		printf("error preparing dump files %d\n",ret);
		return 0;
	}

	/* Process minidump log file and segment it
			into individual dump binaries */
	ret = minidump_dump_segments();
	if (ret) {
		printf("error reading dump files %d\n",ret);
		return 0;
	}

	/* Free allocated resources */
	minidump_free();
	return 0;
}
