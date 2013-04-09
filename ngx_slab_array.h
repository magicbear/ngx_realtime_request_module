
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_ARRAY_H_INCLUDED_
#define _NGX_SLAB_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_slab_pool_t  *pool;
} ngx_slab_array_t;


ngx_slab_array_t *ngx_slab_array_create(ngx_slab_pool_t *p, ngx_uint_t n, size_t size);
void ngx_slab_array_destroy(ngx_slab_array_t *a);
void *ngx_slab_array_push(ngx_slab_array_t *a);
void *ngx_slab_array_push_n(ngx_slab_array_t *a, ngx_uint_t n);


static ngx_inline ngx_int_t
ngx_slab_array_init(ngx_slab_array_t *array, ngx_slab_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = ngx_slab_alloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_SLAB_ARRAY_H_INCLUDED_ */
