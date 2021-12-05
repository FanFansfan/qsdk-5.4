/*
 * Copyright (c) 2012, 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <sys/mman.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define IFNAME_MAX 6
#define DIAG_READ_TARGET      1
#define DIAG_WRITE_TARGET     2
#define DIAG_READ_WORD        3
#define DIAG_WRITE_WORD       4
#define DIAG_PHYDBG_DUMP      5
#define DIAG_TRACE_DUMP       6
#define DIAG_EVENT_CFG        7
#define DIAG_TRACE_START      8
#define DIAG_TRACE_STOP       9
#define DIAG_TRACE_CLEAR     10
#define DIAG_TRACE_CFG       11
#define DIAG_CONFIG_PHYDBG_ADCCAPTURE		12
#define DIAG_DUMP_PHYDBG_ADCCAPTURE		13
#define DIAG_PHYDBG_STOP			14
#define DIAG_BB_SM_RECORDER_CFG			15
#define DIAG_BB_SM_RECORDER_DUMP		16
#define DIAG_PHYTLV_CNT                 17
#define DIAG_PHYERR_CNT                 18
#define DIAG_CYCLE_CNT                  19


#define ADDRESS_FLAG                    0x001
#define LENGTH_FLAG                     0x002
#define PARAM_FLAG                      0x004
#define FILE_FLAG                       0x008
#define UNUSED0x010                     0x010
#define AND_OP_FLAG                     0x020
#define BITWISE_OP_FLAG                 0x040
#define QUIET_FLAG                      0x080
#define OTP_FLAG                        0x100
#define HEX_FLAG                     	0x200 //dump file mode,x: hex mode; other binary mode.
#define UNUSED0x400                     0x400
#define DEVICE_FLAG                     0x800
#define WORDCOUNT_FLAG                  0x1000
#define INDEX_FLAG                  0x2000
#define EVENTDATAMASK_FLAG                  0x4000
#define EVENTDATAVALUE_FLAG                  0x8000
#define INTERFACE_FLAG                       0x10000

//eventbus config file parser flags
#define EVENTCFG_BEGIN_FLAG 0x001
#define EVENTCFG_END_FLAG 0xe
#define EVENTSTOP_BEGIN_FLAG 0x002
#define EVENTSTOP_END_FLAG 0xd
#define EVENTSTOPDATA_BEGIN_FLAG 0x004
#define EVENTSTOPDATA_END_FLAG 0xb
#define BUFFER_CFG_BEGIN_FLAG 0x008
#define BUFFER_CFG_END_FLAG 0x7
/* Limit malloc size when reading/writing file */
#define MAX_BUF                         (8*1024)

#define MBUFFER 1024
#define STRCAT_BUF(buf1, buf2) do {                                            \
	if ((strlen(buf1) + strlen(buf2)) < (MBUFFER)) {                         \
		strlcat(buf1, buf2, sizeof(buf1));                                                    \
	}                                                                          \
	else                                                                       \
	printf("Buffer size is too less to perform string concatenation\n");   \
} while(0)

FILE *pFile;
unsigned int flag;
const char *progname;
const char commands[] =
"commands and options:\n\
		--get --address=<target word address> [--count=<wordcount>]\n\
		--set --address=<target word address> --[value|param]=<value>\n\
		--or=<OR-ing value>\n\
		--and=<AND-ing value>\n\
		--read --address=<target address> --length=<bytes> --file=<filename>\n\
		--write --address=<target address> --file=<filename>\n\
		--[value|param]=<value>\n\
		--otp --read --address=<otp offset> --length=<bytes> --file=<filename>\n\
		--otp --write --address=<otp offset> --file=<filename>\n\
		--tracerClear\n\
		--eventCfg --file=<event_config_filename>\n\
		--tracerCfg --file=<tracer_config_filename>\n\
		--tracerStart\n\
		--tracerStop\n\
		--tracerDump --file=<filename>\n\
		--smrecorderCfg\n\
		--smrecorderDump --file=<filename>\n\
		--phydbgCfg --file=<phydbg_cfg_filename\n\
		--phydbgDump --file=<phydbg_cfg_filename\n\
		--phydbgStop\n\
		--quiet\n\
		--device=<device name> (if not default)\n\
		--phytlv_cnt\n\
		--phyerr_cnt\n\
		--cycle_cnt\n\
		--wifi=<index>\n\
		The options can also be given in the abbreviated form --option=x or -o x.\n\
		The options can be given in any order.\n\
		If you need to read cal data add --cal ahead of --read command";

const char commands_lite[] =
"commands and options:\n\
		--get --address=<target word address> [--count=<wordcount>]\n\
		--set --address=<target word address> --value=<value>\n\
		--quiet\n\
		--wifi=<index>\n\
		The options can also be given in the abbreviated form --option=x or -o x.\n\
		The options can be given in any order";

#define A_ROUND_UP(x, y)             ((((x) + ((y) - 1)) / (y)) * (y))
#define min(x,y) ((x) < (y) ? (x) : (y))
#define rev(ui) ((ui >> 24) |((ui<<8) & 0x00FF0000) | ((ui>>8) & 0x0000FF00) | (ui << 24))
#define rev2(a) ((a>>8)|((a&0xff)<<8))
#define quiet() (flag & QUIET_FLAG)
#define nqprintf(args...) if (!quiet()) {printf(args);}
#define WINDOW_REGISTER_OFFSET 0x310c
#define WINDOW_REGISTER_VALUE 0x40014DC0
#define WINDOW_SHIFT 19
#define WINDOW_VALUE_MASK 0x3F
#define WINDOW_RANGE_MASK 0x7FFFF
#define WINDOW_SIZE 0x80000
#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

int ValidWriteOTP(int dev, A_UINT32 address, A_UINT8 *buffer, A_UINT32 length);
void print_cnt(int dev, A_UINT32 address);
int Qc98xxTargetPowerGet(int frequency, int rate, double *power);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static INLINE void *
MALLOC(int nbytes)
#else
static INLINE void *
MALLOC(int nbytes)
#endif
{
    void *p= malloc(nbytes);

    if (!p)
    {
        fprintf(stderr, "err -Cannot allocate memory\n");
    }

    return p;
}

static inline void usage(void)
{
    fprintf(stderr, "usage:\n%s ", progname);
    fprintf(stderr, "%s\n", commands);
    exit(-1);
}

static inline void usage_lite(void)
{
    fprintf(stderr, "usage:\n%s ", progname);
    fprintf(stderr, "%s\n", commands_lite);
    exit(-1);
}
static inline int athdiag_open_sys_interface(char *ifname, char *devicename)
{
	int dev;
	for (;;) {
		/* DIAG uses a sysfs special file which may be auto-detected */
		if (!(flag & DEVICE_FLAG)) {
			FILE *find_dev = NULL;
			size_t nbytes = 0;
			char *pos = NULL;

			/* If interface name is provided find the device */
			if (flag & INTERFACE_FLAG) {
				char command[PATH_MAX];
				int len;
				len = snprintf(command, sizeof(command), "find /sys/devices -name wifi%s", ifname);
				if (len <= sizeof(command)) {
					/* the output filename received is /sys/devices/<devicename>/net/wifiX */
					find_dev = popen(command, "r");
					if (find_dev)
					{
						nbytes=fread(devicename, 1, PATH_MAX, find_dev);
						if(nbytes) {
							devicename[nbytes-1]='\0';
							if (!quiet())
								fprintf(stderr, "Detected the interface %s\n",devicename);
						}
					}
				}
			} else {
				/*
				 * Convenience: if no device was specified on the command
				 * line, try to figure it out.  Typically there's only a
				 * single device anyway.
				 */
				/* Check for proprietary driver */
				find_dev = popen("find /sys/devices -name athdiag | head -1", "r");
				if (find_dev) {
					nbytes=fread(devicename, 1, PATH_MAX, find_dev);
					if(nbytes) {
						if (!quiet())
							fprintf(stderr, "Detected prop\n");
						goto start;
					}
					pclose(find_dev);
				}
				/*Check for ath10k driver */
				find_dev = popen("find /sys/kernel/debug/ieee80211 -name athdiag |head -1", "r");
				if (find_dev) {
					nbytes=fread(devicename, 1, PATH_MAX, find_dev);
					if(nbytes)
						fprintf(stderr, "Detected ath10k\n");
				}
			}
start:
			if (find_dev)
			{
				pclose(find_dev);
			}
			if (nbytes > 15) {
				/* auto-detect possibly successful */
				devicename[nbytes-1]='\0'; /* replace \n with 0 */
				/* If device name is /sys/devices/<devicename>/net/wifiX, truncate string "net" onwards */
				pos = strstr(devicename,"net");

				if (!quiet())
					fprintf(stderr, "Autodetected:  %s Diag file (%s)\n", __FUNCTION__, devicename);

				if (pos) {
					*pos = '\0';
					/* Concatenate athdiag to /sys/devices/<devicename> , to get sysfs special file or /sys/kernel/debug/ieee80211/<devicename>, to get debugfs file used by DIAG  */
					if (!quiet())
						fprintf(stderr, "Reading from device %s\n",devicename);
					strlcat(devicename, "athdiag", PATH_MAX);
				}
			}else {
				strlcpy(devicename, "unknown_DIAG_device", PATH_MAX);
			}
		}

		dev = open(devicename, O_RDWR);
		if (dev >= 0) {
			if (!quiet())
				fprintf(stderr, " %s Diag file (%s) dev: %d\n", __FUNCTION__, devicename, dev);
			break; /* successfully opened diag special file */
		} else {
			fprintf(stderr, "err %s failed (%d) to open DIAG file (%s)\n",
					__FUNCTION__, errno, devicename);
			exit(1);
		}
	}
	return dev;
}
