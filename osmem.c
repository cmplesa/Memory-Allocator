// SPDX-License-Identifier: BSD-3-Clause

#include "helpers.h"

block_meta_t head;
int head_init_done;
int heap_prealloc_done;

#define MMAP(x) mmap(NULL, x, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

void set_next(block_meta_t *block, block_meta_t *next)
{
	block->next = next;
}

void set_prev(block_meta_t *block, block_meta_t *prev)
{
	block->prev = prev;
}

void set_status(block_meta_t *block, int status)
{
	block->status = status;
}

block_meta_t *search_block_mem(size_t size)
{
	size_t requested_size = (META_BLOCK_SIZE + size);
	block_meta_t *block = MMAP(requested_size);

	if (block == MAP_FAILED)
		return NULL;

	block->size = size;
	block->status = STATUS_MAPPED;

	block_meta_t *last = NULL;

	last = head.prev;
	set_next(last, block);
	set_prev(block, last);
	set_next(block, &head);
	set_prev(&head, block);


	return block;
}

int prealloc(void)
{
	if (heap_prealloc_done == 0) {
		void *request_block = sbrk(HEAP_PREALLOC_SIZE);

		if (request_block == (void *) -1)
			return 0;

		heap_prealloc_done = 1;

		block_meta_t *prealloc_block = (block_meta_t *)request_block;

		size_t allocated = HEAP_PREALLOC_SIZE - META_BLOCK_SIZE;

		prealloc_block->size = allocated;
		set_status(prealloc_block, STATUS_FREE);

		block_meta_t *last = NULL;

		last = head.prev;
		set_next(last, prealloc_block);
		set_prev(prealloc_block, last);
		set_next(prealloc_block, &head);
		set_prev(&head, prealloc_block);

	} else {
		return 1;
	}

	return 1;
}

block_meta_t *find_bestblock(size_t size)
{
	block_meta_t *best_fit = NULL;

	for (block_meta_t *iterator = head.next; iterator != &head; iterator = iterator->next) {
		if (iterator->size >= ALIGN(size) && iterator->status == STATUS_FREE) {
			if (!best_fit || iterator->size < best_fit->size)
				best_fit = iterator;
		}
	}

	return best_fit;
}

void splitting(block_meta_t *block, size_t size)
{
	int ok = 0;

	if (block->size == ALIGN(size))
		ok = 1;

	if (ok == 1)
		return;

	size_t minimum_occupied_size = ALIGN(size) + META_BLOCK_SIZE + 1;

	int check = 1 ? minimum_occupied_size >= block->size : 0;

	if (check == 1)
		return;

	char *new_block_address = (char *)block + META_BLOCK_SIZE + ALIGN(size);
	block_meta_t *new_block = (block_meta_t *)new_block_address;

	size_t allocated = block->size - ALIGN(size) - META_BLOCK_SIZE;

	new_block->size = allocated;
	new_block->status = STATUS_FREE;

	block->size = ALIGN(size);

	set_next(new_block, block->next);
	set_prev(new_block, block);
	set_prev(block->next, new_block);
	set_next(block, new_block);
}

block_meta_t *expand_last_block(size_t size)
{
	block_meta_t *last_block = NULL;

	block_meta_t *iterator = head.prev;

	while (iterator->status == STATUS_MAPPED && iterator != &head)
		iterator = iterator->prev;

	last_block = (iterator == &head) ? NULL : iterator;

	if (!last_block)
		return NULL;

	size_t add = META_BLOCK_SIZE + last_block->size;

	void *heap_end = (char *)last_block + add;

	size_t needaddsize = size - last_block->size;

	heap_end = sbrk(needaddsize);

	if (heap_end == (void *) -1)
		return NULL;

	last_block->size += needaddsize;
	return last_block;
}

void on_coalesce(void)
{
	block_meta_t *iterator = head.next;
	block_meta_t *to_coalesce1 = NULL, *to_coalesce2 = NULL;


	while (iterator != &head) {
		if (iterator->status == 1) {
			to_coalesce1 = NULL;
			to_coalesce2 = NULL;
			iterator = iterator->next;
			continue;
		}

		if (iterator->status == 2) {
			iterator = iterator->next;
			continue;
		}

		if (to_coalesce1 == NULL) {
			to_coalesce1 = iterator;
			iterator = iterator->next;
			continue;
		}

		to_coalesce2 = iterator;

		iterator = iterator->next;


		to_coalesce1->size += META_BLOCK_SIZE + to_coalesce2->size;
		to_coalesce2->prev->next = to_coalesce2->next;
		to_coalesce2->next->prev = to_coalesce2->prev;
	}
}

block_meta_t *get_last_on_heap(void)
{
	block_meta_t *iterator = head.prev;

	while (iterator != &head && iterator->status == STATUS_MAPPED)
		iterator = iterator->prev;

	return (iterator == &head) ? NULL : iterator;
}


block_meta_t *get_blockfreeheap(size_t size)
{
	if (!prealloc())
		return NULL;

	on_coalesce();

	size_t aligned_size = ALIGN(size);
	block_meta_t *bestblock = find_bestblock(aligned_size);

	if (bestblock) {
		splitting(bestblock, aligned_size);
		return bestblock;
	}

	block_meta_t *last_on_heap = get_last_on_heap();

	if (last_on_heap != NULL && last_on_heap->status == STATUS_FREE) {
		block_meta_t *expanded_block = expand_last_block(aligned_size);

		return expanded_block ? expanded_block : NULL;
	}

	size_t requested_size = META_BLOCK_SIZE + aligned_size;

	void *request_block = sbrk(requested_size);

	int check = 0;

	if (request_block == (void *)-1)
		check = 1;

	if (check == 1)
		return NULL;

	block_meta_t *new_block = (block_meta_t *)request_block;

	new_block->size = aligned_size;

	block_meta_t *last = NULL;

	last = head.prev;
	set_next(last, new_block);
	set_prev(new_block, last);
	set_next(new_block, &head);
	set_prev(&head, new_block);

	return new_block;
}


void set_connections(void)
{
	head.next = &head;
	head.prev = &head;
}

void set_size(block_meta_t *block, size_t size)
{
	block->size = size;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	if (!head_init_done) {
		set_size(&head, 0);
		set_connections();
		head_init_done += 1;
	}

	size_t aligned_size;

	aligned_size = (size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);

	size_t total_size = META_BLOCK_SIZE + aligned_size;

	if (total_size < MMAP_THRESHOLD) {
		block_meta_t *heap_block = NULL;

		if (!prealloc())
			return NULL;

		on_coalesce();

		block_meta_t *bestblock = find_bestblock(ALIGN(size));

		if (bestblock) {
			splitting(bestblock, ALIGN(size));
			heap_block = bestblock;
		} else {
			block_meta_t *iterator = head.prev;

			while (iterator->status == STATUS_MAPPED && iterator != &head)
				iterator = iterator->prev;

			block_meta_t *last_on_heap = (iterator == &head) ? NULL : iterator;

			if (last_on_heap != NULL && last_on_heap->status == STATUS_FREE) {
				size_t needaddsize = ALIGN(size) - last_on_heap->size;

				size_t addition = META_BLOCK_SIZE + last_on_heap->size;

				void *heap_end = (char *)last_on_heap + addition;

				heap_end = sbrk(needaddsize);

				int check = 0;

				if (heap_end == (void *)-1)
					check = 1;

				if (check == 1)
					return NULL;

				last_on_heap->size = last_on_heap->size + needaddsize;
				heap_block = last_on_heap;
			} else {
				size_t all = META_BLOCK_SIZE + ALIGN(size);
				void *request_block = sbrk(all);

				if (request_block == (void *) -1)
					return NULL;

				block_meta_t *new_block = (block_meta_t *)request_block;

				new_block->size = ALIGN(size);
				block_meta_t *last = head.prev;

				set_next(last, new_block);
				set_prev(new_block, last);
				set_next(new_block, &head);
				set_prev(&head, new_block);
				heap_block = new_block;
			}
		}
		if (!heap_block)
			return NULL;

		heap_block->status = STATUS_ALLOC;
		return (void *)((char *)heap_block + META_BLOCK_SIZE);

	} else {
		size_t requested_size = META_BLOCK_SIZE + ALIGN(size);
		block_meta_t *block = MMAP(requested_size);

		if (block == MAP_FAILED)
			return NULL;

		block->size = ALIGN(size);
		set_status(block, STATUS_MAPPED);

		block_meta_t *last = head.prev;

		set_next(last, block);
		set_prev(block, last);
		set_next(block, &head);
		set_prev(&head, block);

		if (!block)
			return NULL;

		void *result = (void *)((char *)block + META_BLOCK_SIZE);

		return result;
	}
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	block_meta_t *block = NULL;
	block_meta_t *iterator = head.next;

	while (iterator != &head) {
		if (((char *)iterator + META_BLOCK_SIZE) == ptr) {
			block = iterator;
			break;
		}
		iterator = iterator->next;
	}

	if (!block || block->status == STATUS_FREE)
		return;

	if (block->status == 2) {
		if (block->status != 2)
			return;

		set_next(block->prev, block->next);
		set_prev(block->next, block->prev);

		int munmap_size = block->size + META_BLOCK_SIZE;

		int munmap_ret_val = munmap(block, munmap_size);

		DIE(munmap_ret_val == -1, "Critical error: munmap() failed.\n");
		return;
	}

	if (block->status == STATUS_ALLOC) {
		set_status(block, STATUS_FREE);
		return;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0)
		return NULL;

	if (size == 0)
		return NULL;


	if (!head_init_done) {
		head.size = 0;
		set_next(&head, &head);
		set_prev(&head, &head);
		head_init_done = 1;
	}

	size_t total_size = size * nmemb;

	size_t aligned_size = ALIGN(total_size);


	if (aligned_size < size)
		return NULL;

	if (aligned_size < nmemb)
		return NULL;

	long pagesize = getpagesize();

	long aligned_size_meta = META_BLOCK_SIZE + aligned_size;

	if (aligned_size_meta < pagesize) {
		block_meta_t *heap_block = NULL;

		get_blockfreeheap(aligned_size);
		if (!prealloc())
			return NULL;


		on_coalesce();

		block_meta_t *bestblock = find_bestblock(aligned_size);

		if (bestblock) {
			splitting(bestblock, aligned_size);
			heap_block = bestblock;
		} else {
			block_meta_t *iterator = head.prev;

			while (iterator->status == STATUS_MAPPED && iterator != &head)
				iterator = iterator->prev;


			block_meta_t *last_on_heap = (iterator == &head) ? NULL : iterator;

			void *heap_end = (char *)last_on_heap + META_BLOCK_SIZE + last_on_heap->size;

			if (last_on_heap != NULL && last_on_heap->status == STATUS_FREE) {
				size_t needaddsize = aligned_size - last_on_heap->size;

				heap_end = sbrk(needaddsize);

				int check = 0;

				if (heap_end == (void *)-1)
					check = 1;

				if (check == 1)
					return NULL;

				last_on_heap->size += needaddsize;
				heap_block = last_on_heap;
			} else {
				void *request_block = sbrk(META_BLOCK_SIZE + aligned_size);

				int check = 0;

				if (request_block == (void *) -1)
					check = 1;

				if (check == 1)
					return NULL;

				block_meta_t *new_block = (block_meta_t *)request_block;

				new_block->size = aligned_size;
				block_meta_t *last = head.prev;

				set_next(last, new_block);
				set_prev(new_block, last);
				set_next(new_block, &head);
				set_prev(&head, new_block);
				heap_block = new_block;
			}
		}
		if (!heap_block)
			return NULL;

		heap_block->status = STATUS_ALLOC;
		char *result = (char *)heap_block + META_BLOCK_SIZE;

		memset(result, 0, aligned_size);
		return (void *)((char *)heap_block + META_BLOCK_SIZE);
	}

	size_t requested_size = META_BLOCK_SIZE + aligned_size;
	block_meta_t *block = MMAP(requested_size);

	block->size = aligned_size;

	if (block == MAP_FAILED)
		return NULL;

	set_status(block, STATUS_MAPPED);

	block_meta_t *last = head.prev;

	set_next(last, block);
	set_prev(block, last);
	set_next(block, &head);
	set_prev(&head, block);

	memset((void *)((char *)block + META_BLOCK_SIZE), 0, aligned_size);
	return (void *)((char *)block + META_BLOCK_SIZE);
}


void delete_blockmap(block_meta_t *block)
{
	if (block->status != STATUS_MAPPED)
		return;

	set_next(block->prev, block->next);
	set_prev(block->next, block->prev);

	int munmap_value_to_check = block->size + META_BLOCK_SIZE;

	int munmap_ret_val = munmap(block, munmap_value_to_check);

	DIE(munmap_ret_val == -1, "munmap failed\n");
}


void memcpy_fuc(block_meta_t *src, block_meta_t *dst, size_t size)
{
	memcpy((void *)((char *)dst + META_BLOCK_SIZE), (void *)((char *)src + META_BLOCK_SIZE), size);
}

void coal_size(block_meta_t *block, size_t size)
{
	block_meta_t *iterator = block->next;

	while (iterator != &head) {
		if (iterator->status == STATUS_FREE) {
			size_t add = META_BLOCK_SIZE + iterator->size;

			block->size += add;
			set_next(iterator->prev, iterator->next);
			set_prev(iterator->next, iterator->prev);

			if (block->size >= size)
				break;

			iterator = iterator->next;
			continue;
		} else if (iterator->status == STATUS_MAPPED) {
			iterator = iterator->next;
			continue;
		} else {
			break;
		}
	}
}


void *os_realloc(void *ptr, size_t size)
{
	block_meta_t *req_block = NULL;

	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	block_meta_t *iterator = head.next;

	while (iterator != &head) {
		char *block_ptr = (char *)iterator + META_BLOCK_SIZE;

		if (ptr == block_ptr) {
			req_block = iterator;
			break;
		}
		iterator = iterator->next;
	}

	if (!req_block)
		return NULL;


	if (req_block->status == STATUS_FREE)
		return NULL;


	size_t aligned_size = ALIGN(size);

	if (aligned_size == req_block->size) {
		void *result = (void *)((char *)req_block + META_BLOCK_SIZE);
		return result;
	}

	if (aligned_size > req_block->size) {
		if (req_block->status == STATUS_MAPPED) {
			block_meta_t *new_map_block = NULL;

			size_t requested_size = (META_BLOCK_SIZE + aligned_size);
			block_meta_t *block = MMAP(requested_size);

			if (block == MAP_FAILED)
				return NULL;

			block->size = aligned_size;
			set_status(block, STATUS_MAPPED);

			block_meta_t *last = head.prev;

			set_next(last, block);
			set_prev(block, last);
			set_next(block, &head);
			set_prev(&head, block);

			new_map_block = block;

			if (!new_map_block)
				return NULL;
			void *old_payload = (char *)req_block + META_BLOCK_SIZE;
			void *new_payload = (char *)new_map_block + META_BLOCK_SIZE;

			memmove(new_payload, old_payload, req_block->size);
			if (req_block->status != STATUS_MAPPED)
				return NULL;

			set_next(req_block->prev, req_block->next);
			set_prev(req_block->next, req_block->prev);

			size_t munmap_value = req_block->size + META_BLOCK_SIZE;

			int munmap_ret_val = munmap(req_block, munmap_value);

			DIE(munmap_ret_val == -1, "failed");

			void *result = (void *)((char *)new_map_block + META_BLOCK_SIZE);

			return result;
		}

		if (aligned_size >= MMAP_THRESHOLD) {
			block_meta_t *new_map_block = search_block_mem(aligned_size);

			if (!new_map_block)
				return NULL;

			void *old_payload = (char *)req_block + META_BLOCK_SIZE;
			void *new_payload = (char *)new_map_block + META_BLOCK_SIZE;

			memmove(new_payload, old_payload, req_block->size);

			req_block->status = STATUS_FREE;

			void *result = (void *)((char *)new_map_block + META_BLOCK_SIZE);

			return result;
		}

		block_meta_t *last_on_heap = get_last_on_heap();

		if (req_block == last_on_heap) {
			req_block = expand_last_block(aligned_size);
			if (!req_block)
				return NULL;

			void *result = (void *)((char *)req_block + META_BLOCK_SIZE);

			return result;
		}

		size_t original_block_size = req_block->size;

		coal_size(req_block, aligned_size);

		if (req_block->size >= aligned_size) {
			splitting(req_block, aligned_size);

			void *result = (void *)((char *)req_block + META_BLOCK_SIZE);

			return result;
		}

		block_meta_t *heap_block = get_blockfreeheap(aligned_size);

		if (!heap_block)
			return NULL;

		heap_block->status = STATUS_ALLOC;

		void *old_payload = (char *)req_block + META_BLOCK_SIZE;
		void *new_payload = (char *)heap_block + META_BLOCK_SIZE;

		memmove(new_payload, old_payload, original_block_size);

		req_block->status = STATUS_FREE;

		return (void *)((char *)heap_block + META_BLOCK_SIZE);
	}

	if (aligned_size < req_block->size) {
		if (req_block->status == STATUS_MAPPED) {
			if (aligned_size > MMAP_THRESHOLD) {
				block_meta_t *new_map_block = search_block_mem(aligned_size);

				if (!new_map_block)
					return NULL;
				memcpy_fuc(new_map_block, req_block, aligned_size);
				if (req_block->status != STATUS_MAPPED)
					return NULL;

				set_next(req_block->prev, req_block->next);
				set_prev(req_block->next, req_block->prev);

				int munmap_ret_val = munmap(req_block, req_block->size + META_BLOCK_SIZE);

				DIE(munmap_ret_val == -1, "Critical error: munmap() failed.\n");

				return (void *)((char *)new_map_block + META_BLOCK_SIZE);
			}

			block_meta_t *heap_block = get_blockfreeheap(aligned_size);

			if (!heap_block)
				return NULL;

			set_status(heap_block, STATUS_ALLOC);
			memcpy_fuc(heap_block, req_block, aligned_size);

			if (req_block->status != STATUS_MAPPED)
				return NULL;

			set_next(req_block->prev, req_block->next);
			set_prev(req_block->next, req_block->prev);

			int munmap_ret_val = munmap(req_block, req_block->size + META_BLOCK_SIZE);

			DIE(munmap_ret_val == -1, "Critical error: munmap() failed.\n");

			return (void *)((char *)heap_block + META_BLOCK_SIZE);
		}

		splitting(req_block, aligned_size);
		return (void *)((char *)req_block + META_BLOCK_SIZE);
	}

	return NULL;
}
