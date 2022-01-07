#pragma once

#include "inner_format.h"

struct image rotate(struct image const source);

struct image img_empty();
struct image img_create(uint32_t width, uint32_t height, struct pixel* data);

struct pixel* img_get_data(struct image const* img);
void img_set_data(struct pixel* data, struct image* img);
void free_data(struct image* img);

uint64_t img_get_size(struct image const* img);

uint64_t img_get_width(struct image const* img);
void img_set_width(uint32_t width, struct image* img);

uint64_t img_get_height(struct image const* img);
void img_set_height(uint32_t height, struct image* img);


