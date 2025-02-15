#pragma once

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "osmem.h"
#include "block_meta.h"

#define HEAP_PREALLOC_SIZE (128 * 1024)
#define MMAP_THRESHOLD (128 * 1024)

#define MAP_ANONYMOUS 0x20

typedef struct block_meta block_meta_t;

// Taken from "Resources" -> "Implementing malloc"
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define META_BLOCK_SIZE ALIGN(sizeof(struct block_meta))


void set_next(block_meta_t *block, block_meta_t *next);
void set_prev(block_meta_t *block, block_meta_t *prev);
void set_status(block_meta_t *block, int status);
block_meta_t *search_block_mem(size_t size);
int prealloc(void);
block_meta_t *find_bestblock(size_t size);
void splitting(block_meta_t *block, size_t size);
block_meta_t *expand_last_block(size_t size);
void on_coalesce(void);
block_meta_t *get_last_on_heap(void);
block_meta_t *get_blockfreeheap(size_t size);
void set_connections(void);
void set_size(block_meta_t *block, size_t size);
void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void delete_blockmap(block_meta_t *block);
void memcpy_fuc(block_meta_t *src, block_meta_t *dst, size_t size);
void coal_size(block_meta_t *block, size_t size);
void *os_realloc(void *ptr, size_t size);

