/*
* Copyright (c) 2019 Qualcomm Technologies, Inc.
*
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Technologies, Inc.
*
*/

#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include "hashmap.h"

#define HASH_SHIFT 8
#define HASHMAPDEFAULTSIZE 10

/*-F- hashByName -- Generate the hash by the name */
unsigned int hashByName(const char *Name)
{
	unsigned Hash = 0;

	while (*Name) {

		/* Rotate the hash so all bits are used; then combine with next char */
		Hash = (Hash << 1) | (1 & (Hash >> (HASH_SHIFT-1)));
		Hash ^= *Name++;
	}

	return Hash;
}

/*-F- hmapInit -- set up the hmap's container for the hash Map
 *size: How many slots the size should be.
 */
struct hmap *hmapInit(struct hmap *map, int size)
{
	map->buckets = calloc(size, sizeof(struct hmap_node*));
	if (map->buckets != NULL) {
		map->hash_size = size;
	}
	map->n = 0;

	return map;
}

/* -F- hmapInsert -- insert a new node to the table
 */
struct hmap_node *hmapInsert(struct hmap *map, struct hmap_node *node)
{
	unsigned hash = hashByName(node->name);
	struct hmap_node **pos;

	if (map->buckets == NULL)
		hmapInit(map, HASHMAPDEFAULTSIZE);

	pos = &(map->buckets[hash % map->hash_size]);

	while (*pos) {
		pos = &((*pos)->next);
	}
	*pos = node;
	map->n++;

	return *pos;
}

/* -F- hmapLookUp -- search a node in the table
 */
struct hmap_node *hmapLookUp(struct hmap *map, const char *name)
{
	unsigned hash = hashByName(name);
	struct hmap_node *pos;

	if (map->buckets == NULL)
		hmapInit(map, HASHMAPDEFAULTSIZE);

	pos = (map->buckets[hash % map->hash_size]);
	while ( pos && strncmp(name, pos->name, sizeof(pos->name))) {
		pos = pos->next;
	}

	return pos;
}

/* -F- hmapRemove -- delete a node from the table
 */
struct hmap_node *hmapRemove(struct hmap *map, struct hmap_node *node)
{
	unsigned hash = hashByName(node->name);
	struct hmap_node **pos;

	if (map->buckets == NULL)
		hmapInit(map, HASHMAPDEFAULTSIZE);

	pos = &(map->buckets[hash % map->hash_size]);
	while (*pos && *pos != node && (*pos)->next != node)
	       pos = &((*pos)->next);
	if (*pos) {
		*pos = node->next;
		map->n--;
		return node;
	} else {
		return NULL;
	}
}

/* hmapPositionFirst -- look for the first non-null entry start
 * from the position start
 */
static struct hmap_node *hmapPositionFirst(struct hmap *map, int start)
{
	int i;

	for (i = start; i < map->hash_size; i++) {
		if(map->buckets[i])
			return map->buckets[i];
	}

	return NULL;
}

/* -F- hmapFirst -- look for the first non-null entry from begin
 */
struct hmap_node *hmapFirst(struct hmap *map)
{
	return hmapPositionFirst(map, 0);
}

/* -F- hmapFirst -- look for the next non-null entry from node
 */
struct hmap_node *hmapNext(struct hmap *map, struct hmap_node *node)
{
	unsigned hash;

	if(node->next)
		return node->next;

	hash = hashByName(node->name);
	return hmapPositionFirst(map, (hash % map->hash_size + 1));
}
