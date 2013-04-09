
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_slab_array.h"

ngx_slab_array_t *
ngx_slab_array_create(ngx_slab_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_slab_array_t *a;
	
    a = ngx_slab_alloc(p, sizeof(ngx_slab_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_slab_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_slab_array_destroy(ngx_slab_array_t *a)
{
	ngx_slab_free(a->pool, a->elts);
}


void *
ngx_slab_array_push(ngx_slab_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_slab_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;


		/* allocate a new array */

		new = ngx_slab_alloc(p, 2 * size);
		if (new == NULL) {
			return NULL;
		}

		ngx_memcpy(new, a->elts, size);
		a->elts = new;
		a->nalloc *= 2;
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


void *
ngx_slab_array_push_n(ngx_slab_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    ngx_uint_t   nalloc;
    ngx_slab_pool_t  *p;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

		/* allocate a new array */

		nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

		new = ngx_slab_alloc(p, nalloc * a->size);
		if (new == NULL) {
			return NULL;
		}

		ngx_memcpy(new, a->elts, a->nelts * a->size);
		a->elts = new;
		a->nalloc = nalloc;
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
