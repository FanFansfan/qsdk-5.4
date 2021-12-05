/*
 * Copyright (c) 2012, 2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "athdiag_include.h"

static inline unsigned int parse_address(char *optarg)
{
    unsigned int address;

    /* may want to add support for symbolic addresses here */

    address = strtoul(optarg, NULL, 0);

    return address;
}

static inline void WriteTargetRange(int dev, A_UINT32 address, A_UINT8 *buffer, A_UINT32 length)
{
	int nbyte;
	unsigned int remaining;

	(void)lseek(dev, address, SEEK_SET);

	remaining = length;
	while (remaining) {
		nbyte = write(dev, buffer, (size_t)remaining);
		if (nbyte <= 0) {
			fprintf(stderr, "err %s failed (nbyte=%d, address=0x%lx remaining=%d).\n",
					__FUNCTION__, nbyte, (long unsigned int)address, remaining);
			exit(1);
		}

		remaining -= nbyte;
		buffer += nbyte;
		address += nbyte;
	}
}

static inline void WriteTargetWord(int dev, A_UINT32 address, A_UINT32 value)
{
	A_UINT32 param = value;

	WriteTargetRange(dev, address, (A_UINT8 *)&param, sizeof(param));
}

static inline void ReadTargetRange(int dev, A_UINT32 address, A_UINT8 *buffer, A_UINT32 length)
{
	int nbyte;
	unsigned int remaining;

	(void)lseek(dev, address, SEEK_SET);

	remaining = length;
	while (remaining) {
		nbyte = read(dev, buffer, (size_t)remaining);
		if (nbyte <= 0) {
			fprintf(stderr, "err %s failed (nbyte=%d, address=0x%lx remaining=%d).\n",
					__FUNCTION__, nbyte, (long unsigned int)address, remaining);
			exit(1);
		}

		remaining -= nbyte;
		buffer += nbyte;
		address += nbyte;
	}
}

static inline void ReadTargetWord(int dev, A_UINT32 address, A_UINT32 *buffer)
{
	ReadTargetRange(dev, address, (A_UINT8 *)buffer, sizeof(*buffer));
}


static inline void athdiag_read_word(int dev, unsigned int wordcount, unsigned int address, A_UINT32 param)
{
	for ( ; wordcount; address += 4, wordcount--) {
		nqprintf("DIAG Read Word (address: 0x%x)\n", address);
		ReadTargetWord(dev, address, &param);

		if (quiet()) {
			printf("0x%08x\t", param);
			if ((wordcount % 4) == 1) printf("\n");
		} else {
			printf("Value in target at 0x%x: 0x%x (%d)\n", address, le32toh(param), le32toh(param));
		}
	}
}

static inline void athdiag_write_word(int dev, unsigned int address, A_UINT32 param, unsigned int bitwise_mask)
{
	A_UINT32 origvalue = 0;

	if (flag & BITWISE_OP_FLAG) {
		/* first read */
		ReadTargetWord(dev, address, &origvalue);
		param = origvalue;

		/* now modify */
		if (flag & AND_OP_FLAG) {
			param &= bitwise_mask;
		} else {
			param |= bitwise_mask;
		}

		/* fall through to write out the parameter */
	}

	if (flag & BITWISE_OP_FLAG) {
		if (quiet()) {
			printf("0x%lx\n", (long unsigned int)origvalue);
		} else {
			printf("DIAG Bit-Wise (%s) modify Word (address: 0x%lx, orig:0x%lx, new: 0x%lx,  mask:0x%lX)\n",
					(flag & AND_OP_FLAG) ? "AND" : "OR", (long unsigned int)address, (long unsigned int)origvalue, (long unsigned int)param, (long unsigned int)bitwise_mask );
		}
	} else{
		nqprintf("DIAG Write Word (address: 0x%lx, param: 0x%lx)\n", (long unsigned int)address, (long unsigned int)param);
	}

	WriteTargetWord(dev, address, htole32(param));
}

static void execute_operation(unsigned int address, unsigned int write_offset, int operation, unsigned int write_value)
{
	int fd;
	unsigned int read_result = 0;
	off_t target = write_offset;
	void *map, *virt_addr;
	fd = open("/dev/mem", O_RDWR | O_SYNC);
	map = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = map + (target & MAP_MASK);
	if(operation == DIAG_READ_WORD) {
		read_result = *((unsigned int *) virt_addr);
		printf("Value in target at 0x%x: 0x%x (%d)\n", address, le32toh(read_result), le32toh(read_result));
	} else {
		*((unsigned int *)virt_addr) = htole32(write_value);
	}
	munmap(map, MAP_SIZE);
	close(fd);
}

static inline void athdiag_read_write_direct(unsigned int address, unsigned int value, unsigned int bar, int operation)
{
	unsigned int window_value;
	unsigned int window_address;
	unsigned int offset;
	unsigned int write_offset;

	window_value = ((address >> WINDOW_SHIFT) & WINDOW_VALUE_MASK) | WINDOW_REGISTER_VALUE ;
	offset = address & WINDOW_RANGE_MASK;
	window_address = bar + WINDOW_REGISTER_OFFSET;
	write_offset = bar + offset + WINDOW_SIZE;

	execute_operation(address, window_address, DIAG_WRITE_WORD, window_value);
	execute_operation(address, write_offset, operation, value);
}
