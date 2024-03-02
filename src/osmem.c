// SPDX-License-Identifier: BSD-3-Clause

#include "../utils/osmem.h"
#include "../utils/block_meta.h"
#include <printf.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAP_ANONYMOUS 0x20
#define ALIGNMENT 8
#define MMAP_THRESHOLD 131072
#define SIZE_MAX 100 * MMAP_THRESHOLD
static struct block_meta *head_brk = NULL;
static struct block_meta *head_mmap = NULL;
static struct block_meta *tail_brk = NULL;

int ALLOCATED = 0;
int CALLOCATED = 0;

#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

void add_block(struct block_meta *block)
{
	if(head_brk == NULL) {
		head_brk = block;
		tail_brk = block;
		block->next = NULL;
		block->prev = NULL;
	} else {
		tail_brk->next = block;
		block->prev = tail_brk;
		block->next = NULL;
		tail_brk = block;
	}
}

struct block_meta *find_block(size_t size)
{
	struct block_meta *temp = head_brk;
	struct block_meta *block = NULL;
	size_t best_fit = SIZE_MAX;

	while(temp != NULL) {
		if(temp->status == STATUS_FREE && temp->size >= size) {
			if(temp->size <= best_fit) {
				block = temp;
				best_fit = temp->size;
			}
		}
		temp = temp->next;
	}
	if(block != NULL) {
		return block;
	}

	if (tail_brk->status == STATUS_FREE) {
		long long total_size = size - tail_brk->size;
		if(total_size > 0) {
			sbrk(ALIGN(total_size));
		}
		return tail_brk;
	}
	return NULL;
}

void split_block(struct block_meta *block, size_t size)
{
	struct block_meta *new_block = NULL;
	long long int new_size = ALIGN(block->size) - ALIGN(size) -  ALIGN(sizeof(struct block_meta));

	if (new_size < 1) {
        return;
    }

	block->size = size;
	new_block = (struct block_meta *)((void *)block + ALIGN(sizeof(struct block_meta)) + ALIGN(size));
	new_block->size = new_size;
	block->status = STATUS_ALLOC;
	new_block->status = STATUS_FREE;
	new_block->next = block->next;
	new_block->prev = block;
	if(block->next != NULL) {
		block->next->prev = new_block;
	}
	block->next = new_block;
	if(block == tail_brk) {
		tail_brk = new_block;
	}
}

void coalesce(struct block_meta *block)
{
    struct block_meta *next = block->next;
    struct block_meta *prev = block->prev;

    int next_allocated = (next != NULL) ? next->status : 1;
    int prev_allocated = (prev != NULL) ? prev->status : 1;

    if (!prev_allocated) {
        prev->size += ALIGN(block->size) + ALIGN(sizeof(struct block_meta));
        prev->next = next;

        if (next != NULL) {
            next->prev = prev;
        }

		block->size += ALIGN(prev->size) + ALIGN(sizeof(struct block_meta));
        block = prev;
		return;
    }

    if (!next_allocated) {
        block->size += ALIGN(next->size) + ALIGN(sizeof(struct block_meta));
        block->next = next->next;

        if (next->next != NULL) {
            next->next->prev = block;
        }

		block->size += ALIGN(next->size) + ALIGN(sizeof(struct block_meta));
		block = next;
    }
}

void *os_malloc(size_t size)
{
	if(size == 0)
		return NULL;
	
	struct block_meta *block = NULL;
	
	size_t alloc_size;
	if(CALLOCATED) {
		alloc_size = getpagesize() - ALIGN(sizeof(struct block_meta));
	} else {
		alloc_size = MMAP_THRESHOLD;
	}
	size = ALIGN(size);
	if(size < alloc_size) {
		if(ALLOCATED == 0) {
			void *pointer = sbrk(0);
			void *p = sbrk(MMAP_THRESHOLD);
			block = (struct block_meta *)pointer;
			block->size = MMAP_THRESHOLD - ALIGN(sizeof(struct block_meta));
			block->status = STATUS_FREE;
			
			add_block(block);

			ALLOCATED = 1;
			CALLOCATED = 0;
		}

		block = find_block(size);
		
		if(block == NULL) {
			block = sbrk(ALIGN(size) + ALIGN(sizeof(struct block_meta)));
			block->status = STATUS_FREE;
			block->size = size;
			block->next = NULL;
			block->prev = NULL;
			add_block(block);
		} else {
			split_block(block, size);
			block->size = size;
			block->status = STATUS_ALLOC;
		}
	} else {

		void *p = mmap(NULL, ALIGN(size) + ALIGN(sizeof(struct block_meta)), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		block = (struct block_meta *)p;
		block->size = ALIGN(size);
		block->status = STATUS_MAPPED;

		return (void *)block + ALIGN(sizeof(struct block_meta));
	}

	block->status = STATUS_ALLOC;
	return (void *)block + ALIGN(sizeof(struct block_meta));
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	
	struct block_meta *block = (void *)ptr - ALIGN(sizeof(struct block_meta));

	if(block->status == STATUS_MAPPED) {
		munmap(block, ALIGN(block->size) + ALIGN(sizeof(struct block_meta)));
	} else if(block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce(block);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	CALLOCATED = 1;

	size_t total_size = nmemb * size;
	void *p = os_malloc(total_size);
	if(p == NULL)
		return NULL;
	memset(p, 0, total_size);
	return p;
}

struct block_meta *get_block_ptr(void *ptr) {
  return (struct block_meta*)((void *)ptr - 1);
}

void *os_realloc(void *ptr, size_t size)
{
    if (size == 0)
    {
        os_free(ptr);
        return NULL;
    }

    if (ptr == NULL)
    {
        return os_malloc(size);
    }

    struct block_meta *block = get_block_ptr(ptr);

    if (block->status == STATUS_FREE)
    {
        return NULL;
    }

    if (block->size >= size)
    {
        return ptr;
    }

    if(block->status == STATUS_ALLOC) {
		struct block_meta *next = block->next;
		int next_alloc = (next != NULL) ? next->status : 1;

		if (!next_alloc && (block->size + next->size + ALIGN(sizeof(struct block_meta)) >= size))
		{
			block->size += ALIGN(next->size) + ALIGN(sizeof(struct block_meta));
			block->next = next->next;

			if (next->next != NULL)
			{
				next->next->prev = block;
			}
			
		}

		if(block->size >= size) {
			split_block(block, size);
			return (void *)block + ALIGN(sizeof(struct block_meta));
		} else {
			void *new_ptr = os_malloc(size);
			memmove(new_ptr, ptr, block->size);
			os_free(ptr);
			return new_ptr;
		}
	}

    void *new_ptr = os_malloc(size);
    memmove(new_ptr, ptr, block->size);
    return new_ptr;
}