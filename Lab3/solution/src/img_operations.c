#include "img_operations.h"

struct image rotate(struct image const source) {
    struct image new_img = img_create(source.height, source.width, NULL);
    new_img.data = malloc(img_get_size(&new_img) * sizeof(struct pixel));
    for (size_t i=0; i<source.height; i++) {
        for (size_t j=0; j<source.width; j++) {
            new_img.data[j * source.height + (source.height-i-1)] = source.data[i * source.width + j];
        }
    }
    return new_img;
}



struct image img_empty() {
    return (struct image) {
        .width = 0,
        .height = 0,
        .data = NULL
    };
}

struct image img_create(uint32_t width, uint32_t height, struct pixel* data) {
    return (struct image) {
        .width = width,
        .height = height,
        .data = data
    };
}



struct pixel* img_get_data(struct image const * img){
    return img->data;
}

void img_set_data(struct pixel* data, struct image* img){
    img->data = data;
}

void free_data(struct image* img) {
    free(img->data);
}



uint64_t img_get_size(struct image const* img){
    return img->width * img->height;
}



uint64_t img_get_width(struct image const* img){
    return img->width;
}

void img_set_width(uint32_t width, struct image* img){
    img->width = width;
}



uint64_t img_get_height(struct image const* img){
    return img->height;
}

void img_set_height(uint32_t height, struct image* img){
    img->height = height;
}



