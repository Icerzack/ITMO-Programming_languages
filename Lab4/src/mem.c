#include <stdarg.h>
#define _DEFAULT_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#include "mem_internals.h"
#include "mem.h"
#include "util.h"

void debug_block(struct block_header *b, const char *fmt, ...);

void debug(const char *fmt, ...);

extern inline block_size size_from_capacity(block_capacity cap);

extern inline block_capacity capacity_from_size(block_size sz);

static inline void* split_addr_block(struct block_header* block, size_t query) {
    return (void*) ((uint8_t*) block + query + offsetof(struct block_header, contents));
}

static bool block_is_big_enough(size_t query, struct block_header *block) { return block->capacity.bytes >= query; }

static size_t pages_count(size_t mem) { return mem / getpagesize() + ((mem % getpagesize()) > 0); }

static size_t round_pages(size_t mem) { return getpagesize() * pages_count(mem); }

static void block_init(void *restrict addr, block_size block_sz, void *restrict next) {
    *((struct block_header *) addr) = (struct block_header) {
            .next = next,
            .capacity = capacity_from_size(block_sz),
            .is_free = true
    };
}

static size_t region_actual_size(size_t query) { return size_max(round_pages(query), REGION_MIN_SIZE); }

extern inline bool region_is_invalid(const struct region *r);

void *map_pages(void const *addr, size_t length, int additional_flags) {
    return mmap((void *) addr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | additional_flags, 0, 0);
}

/*  аллоцировать регион памяти и инициализировать его блоком */
static struct region alloc_region(void const *addr, size_t query) {
    size_t actual_size = region_actual_size(query);
    void* map_address = map_pages(addr, actual_size, MAP_FIXED_NOREPLACE);
    struct region allocated_region;
    if (map_address == MAP_FAILED || map_address == NULL){
        map_address = map_pages(addr, actual_size, 0);
        block_init(map_address, (block_size) {actual_size}, NULL);
        allocated_region = REGION_INVALID;
    } else {
        block_init(map_address, (block_size) {actual_size}, NULL);
        allocated_region = (struct region) {
                .addr = map_address,
                .size = actual_size,
                .extends = true
        };
    }
    return allocated_region;
}

static void *block_after(struct block_header const *block);

void *heap_init(size_t initial) {
    const struct region region = alloc_region(HEAP_START, initial);
    if (region_is_invalid(&region)) return NULL;

    return region.addr;
}

#define BLOCK_MIN_CAPACITY 24

/*  --- Разделение блоков (если найденный свободный блок слишком большой )--- */

static bool block_splittable(struct block_header *restrict block, size_t query) {
    return block->is_free &&
           query + offsetof(struct block_header, contents) + BLOCK_MIN_CAPACITY <= block->capacity.bytes;
}

static bool split_if_too_big(struct block_header *block, size_t query) {
    if (block_splittable(block, query)) {
        void* block_part = (void*) ((uint8_t*)block + offsetof(struct block_header, contents) + query);
        block_init(block_part, (block_size){block->capacity.bytes - query}, block->next);
        block->capacity.bytes = query;
        block->next = block_part;
        return 1;
    }
    return 0;
}


/*  --- Слияние соседних свободных блоков --- */

static void *block_after(struct block_header const *block) {
    return (void *) (block->contents + block->capacity.bytes);
}

static bool blocks_continuous(
        struct block_header const *fst,
        struct block_header const *snd) {
    return (void *) snd == block_after(fst);
}

static bool mergeable(struct block_header const *restrict fst, struct block_header const *restrict snd) {
    return fst->is_free && snd->is_free && blocks_continuous(fst, snd);
}

static bool try_merge_with_next(struct block_header *block) {
    if (block->next==NULL){
        return 0;
    } else {
        if (mergeable(block, block->next)) {
            block->capacity.bytes += size_from_capacity((block->next)->capacity).bytes;
            block->next = (block->next)->next;
            return 1;
        } else {
            return 0;
        }
    }
}


/*  --- ... ecли размера кучи хватает --- */

struct block_search_result {
    enum {
        BSR_FOUND_GOOD_BLOCK, BSR_REACHED_END_NOT_FOUND, BSR_CORRUPTED
    } type;
    struct block_header *block;
};


static struct block_search_result find_good_or_last(struct block_header *restrict block, size_t sz) {
    struct block_header* last_block;
    struct block_search_result result_block;
    if (block==NULL) {
        result_block.type = BSR_CORRUPTED;
        return result_block;
    } else {
        while(block!=NULL){
            if ((block_is_big_enough(sz, block)) && block->is_free) {
                result_block.type = BSR_FOUND_GOOD_BLOCK;
                result_block.block = block;
                return result_block;
            }
            last_block = block;
            block = block->next;
        }
        result_block.type = BSR_REACHED_END_NOT_FOUND;
        result_block.block = last_block;
        return result_block;
    }
}

/*  Попробовать выделить память в куче начиная с блока `block` не пытаясь расширить кучу
 Можно переиспользовать как только кучу расширили. */
static struct block_search_result try_memalloc_existing(size_t query, struct block_header *block) {
    struct block_header* next_block = block;
    while (next_block != NULL) {
        try_merge_with_next(next_block);
        next_block = next_block->next;
    }
    return find_good_or_last(block, size_max(query, BLOCK_MIN_CAPACITY));
}


static struct block_header* grow_heap( struct block_header* restrict last, size_t query ) {
    struct region allocated_region = alloc_region(block_after(last), size_max(query, BLOCK_MIN_CAPACITY) + offsetof(struct block_header, contents));
    struct region new_region = allocated_region;
    if (!region_is_invalid(&allocated_region)) {
        last->next = new_region.addr;
        if (try_merge_with_next(last)){
            return last;
        } else {
            return new_region.addr;
        }
    } else {
        return NULL;
    }
}

/*  Реализует основную логику malloc и возвращает заголовок выделенного блока */
static struct block_header *memalloc(size_t query, struct block_header *heap_start) {
    query = size_max(query, BLOCK_MIN_CAPACITY);
    struct block_search_result result_block = try_memalloc_existing(query, heap_start);
    if(result_block.type == BSR_FOUND_GOOD_BLOCK){
        split_if_too_big(result_block.block, query);
    } else if(result_block.type == BSR_REACHED_END_NOT_FOUND){
        struct block_header* next_block = grow_heap(result_block.block, query);
        if (next_block==NULL){
            return NULL;
        }
        split_if_too_big(result_block.block, query);
    } else {
        return NULL;
    }
    result_block.block->is_free = false;
    return result_block.block;
}

void *_malloc(size_t query) {
    struct block_header *const address = memalloc(query, (struct block_header *)HEAP_START);

    if (address)
    {
        return address->contents;
    }
    else {
        return NULL;
    }
}

static struct block_header *block_get_header(void *contents) {
    return (struct block_header *) (((uint8_t *) contents) - offsetof(struct block_header, contents));
}

void _free(void *mem) {
    if (!mem) return;
    struct block_header *header = block_get_header(mem);
    header->is_free = true;
    while (header != NULL) {
        try_merge_with_next(header);
        header = header->next;
    }
}
