/*
* Copyright (c) 2019 Qualcomm Technologies, Inc.
*
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Technologies, Inc.
*
*/

#ifndef __HASH_MAP_H
#define __HASH_MAP_H
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-D- hmap_node -- the named node and stored in a table by the
 * name's hash value
 */
struct hmap_node {
	struct hmap_node *next;	/* Next in linked list. */
	char name[IFNAMSIZ];	/* Devname*/
};

/* -D- hmap --A hash table, it is a container to hold hmap_node by
 * hashing the node's name
 */
struct hmap {
	struct hmap_node **buckets;	/*Initiate the buckets to hap_node point array*/
	size_t hash_size;
	size_t n;
};

struct hmap *hmapInit(struct hmap *map, int size);
struct hmap_node *hmapInsert(struct hmap *map, struct hmap_node *node);
struct hmap_node *hmapLookUp(struct hmap *map, const char *name);
struct hmap_node *hmapRemove(struct hmap *map, struct hmap_node *node);
struct hmap_node *hmapFirst(struct hmap *map);
struct hmap_node *hmapNext(struct hmap *map, struct hmap_node *node);

/*-D- HMapEntry -- macro to conclude the entry's address by the field's
 * address
 */
#define HMapEntry(_ptr, _type, _member) ({ \
		const typeof( ((_type *)0)->_member ) *__mptr = (_ptr); \
		(_type *)((u_int8_t *)__mptr - offsetof(_type,_member)); \
		})

/*-D- HMapForEachSafe -- macro to traverse the hmap table without writing operation
 */
#define HMapForEach(pos, head) \
	for(pos = hmapFirst(head); pos; pos = hmapNext(head, pos))

/*-D- HMapForEachSafe -- macro to access the hmap table in safe, the node can be delete
 */
#define HMapForEachSafe(pos, n, head) \
	for(pos = hmapFirst(head); pos && ({n = hmapNext(head, pos); 1;}); pos = n)

#ifdef  __cplusplus
}
#endif

#endif /* __HASH_MAP_H */



