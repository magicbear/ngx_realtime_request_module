
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_slab_array.h"

#define REALTIME_REQUEST_MODULE_VERSION "0.5"

typedef struct {
	ngx_slab_array_t	*srv_list;	// array of ngx_http_realtime_request_master_srv_conf_t *
	ngx_shm_zone_t		*shm_zone;
	ssize_t				shm_size;	// defaults is 4M
	ngx_slab_pool_t		*shpool; //共享内存slab
	ngx_int_t			startup;
} ngx_http_realtime_request_conf_t;

typedef struct {
    ngx_str_t                   server_name;
	
	ngx_atomic_t	request;
	ngx_atomic_t	sent;
	ngx_atomic_t	recv;
	ngx_atomic_t	upstream_recv;
	
	ngx_atomic_t	request_20x;
	ngx_atomic_t	request_30x;
	ngx_atomic_t	request_40x;
	ngx_atomic_t	request_50x;
} ngx_http_realtime_request_master_srv_conf_t;

typedef struct {
    ngx_http_realtime_request_master_srv_conf_t		*mstat;
} ngx_http_realtime_request_srv_conf_t;

static ngx_int_t ngx_http_realtime_request_handler_init(ngx_conf_t *cf);

static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

static void * ngx_http_realtime_request_create_conf(ngx_conf_t *cf);

static char * ngx_http_realtime_request_init_conf(ngx_conf_t *cf, void *conf);

static void * ngx_http_realtime_request_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_realtime_request_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_realtime_request_set_size(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
	
static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("realtime_request"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      0,
      0,
      NULL },

    { ngx_string("realtime_zonesize"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_realtime_request_set_size,
      0,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_realtime_request_module_ctx = {
    NULL,                                        /* preconfiguration */
    ngx_http_realtime_request_handler_init,      /* postconfiguration */

    ngx_http_realtime_request_create_conf,       /* create main configuration */
    ngx_http_realtime_request_init_conf,         /* init main configuration */

    ngx_http_realtime_request_create_srv_conf,   /* create server configuration */
    ngx_http_realtime_request_merge_srv_conf,    /* merge server configuration */

    NULL,                                        /* create location configuration */
    NULL                                         /* merge location configuration */
};


ngx_module_t  ngx_http_realtime_request_module = {
    NGX_MODULE_V1,
    &ngx_http_realtime_request_module_ctx, /* module context */
    ngx_http_status_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,								   /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_realtime_handler(ngx_http_request_t *r)
{
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }
	
	ngx_http_realtime_request_conf_t *rrmf = ngx_http_get_module_main_conf(r, ngx_http_realtime_request_module);

	ngx_http_realtime_request_master_srv_conf_t **ptr = (ngx_http_realtime_request_master_srv_conf_t **)(rrmf->srv_list->elts);
	size_t i;
	size = sizeof("uptime: version:"REALTIME_REQUEST_MODULE_VERSION"\nhost\trequest\trecv\tsent\tupstream_recv\t20x\t30x\t40x\t50x\n") + NGX_ATOMIC_T_LEN;
	for (i=0; i < rrmf->srv_list->nalloc; i++)
	{
		if (*ptr==NULL) break;
		size+=(*ptr)->server_name.len + 8 * (NGX_ATOMIC_T_LEN + 1) + 1;
		ptr++;
	}

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;
	
    ngx_time_t  *time;
	
    time = ngx_timeofday();
	
    b->last = ngx_sprintf(b->last, "uptime:%ul version:"REALTIME_REQUEST_MODULE_VERSION"\n", time->sec-rrmf->startup);
    b->last = ngx_cpymem(b->last, "host\trequest\trecv\tsent\tupstream_recv\t20x\t30x\t40x\t50x\n", sizeof("host\trequest\trecv\tsent\tupstream_recv\t20x\t30x\t40x\t50x\n")-1);

	ptr = (ngx_http_realtime_request_master_srv_conf_t **)(rrmf->srv_list->elts);
	for (i=0; i < rrmf->srv_list->nalloc; i++)
	{
		if (*ptr==NULL) break;
		b->last = ngx_cpymem(b->last, (*ptr)->server_name.data, (*ptr)->server_name.len);
		
		b->last = ngx_sprintf(b->last, "\t%ul\t%ul\t%ul\t%ul\t%ul\t%ul\t%ul\t%ul\n", (*ptr)->request, (*ptr)->recv, (*ptr)->sent,
			(*ptr)->upstream_recv, (*ptr)->request_20x, (*ptr)->request_30x, (*ptr)->request_40x, (*ptr)->request_50x);
		ptr++;
	}

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_realtime_handler;

    return NGX_CONF_OK;
}

static char *ngx_http_realtime_request_set_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realtime_request_conf_t  *rrmf;

    rrmf = ngx_http_conf_get_module_main_conf(cf, ngx_http_realtime_request_module);
    
    ngx_uint_t                 i;
    ngx_str_t                 *value;
	
	value = cf->args->elts;
	
    for (i = 1; i < cf->args->nelts; i++) {
        rrmf->shm_size = ngx_parse_size(&value[i]);

		if ((long)rrmf->shm_size == -1)
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							   "invalid parameter \"%V\"", &value[i]);
			return NGX_CONF_ERROR;
		}
    }
	
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_realtime_request_handler(ngx_http_request_t *r)
{
	ngx_http_realtime_request_conf_t *rrmf;
	ngx_http_realtime_request_srv_conf_t *rrsf;
	rrmf = ngx_http_get_module_main_conf(r, ngx_http_realtime_request_module);
	rrsf = ngx_http_get_module_srv_conf(r, ngx_http_realtime_request_module);
	size_t i;

	if (rrsf->mstat == NULL)
	{
		// find another core exists configs
		
		ngx_http_core_srv_conf_t	*cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
		
		ngx_shmtx_lock(&rrmf->shpool->mutex);
		ngx_http_realtime_request_master_srv_conf_t **ptr = (ngx_http_realtime_request_master_srv_conf_t **)(rrmf->srv_list->elts);
		for (i=0; i < rrmf->srv_list->nalloc; i++)
		{
			if (*ptr==NULL) break;
			
			// printf("checking %s\n",cscf->server_name.data);
			if ((*ptr)->server_name.len == cscf->server_name.len && 
				ngx_strncmp((*ptr)->server_name.data, cscf->server_name.data, cscf->server_name.len)==0)
			{
				rrsf->mstat = *ptr;
				// printf("%d: initalize %s zone by another records\n", ngx_getpid(), rrsf->mstat->server_name.data);
				break;
			}
			ptr++;
		}
		ngx_shmtx_unlock(&rrmf->shpool->mutex);
		
		if (rrsf->mstat == NULL)
		{
			ngx_http_realtime_request_master_srv_conf_t **p  = ngx_slab_array_push(rrmf->srv_list);
			*p = ngx_slab_alloc(rrmf->shpool, sizeof(ngx_http_realtime_request_master_srv_conf_t));
			(*p)->server_name.data = ngx_slab_alloc(rrmf->shpool, cscf->server_name.len);
			ngx_shmtx_lock(&rrmf->shpool->mutex);
			// after allocate && check again
			ptr = (ngx_http_realtime_request_master_srv_conf_t **)(rrmf->srv_list->elts);
			for (i=0; i < rrmf->srv_list->nalloc; i++)
			{
				if (*ptr==NULL) break;
				
				if ((*ptr)->server_name.len == cscf->server_name.len && 
					ngx_strncmp((*ptr)->server_name.data, cscf->server_name.data, cscf->server_name.len)==0)
				{
					rrsf->mstat = *ptr;
					break;
				}
				ptr++;
			}
			if (rrsf->mstat == NULL)
			{
				rrsf->mstat = *p;
				rrsf->mstat->server_name.len = cscf->server_name.len;
				ngx_memcpy(rrsf->mstat->server_name.data, cscf->server_name.data, cscf->server_name.len);
				rrsf->mstat->request = 0;
				rrsf->mstat->sent = 0;
				rrsf->mstat->recv = 0;
				rrsf->mstat->request_20x = 0;
				rrsf->mstat->request_30x = 0;
				rrsf->mstat->request_40x = 0;
				rrsf->mstat->request_50x = 0;
				ngx_shmtx_unlock(&rrmf->shpool->mutex);
			}else
			{
				ngx_shmtx_unlock(&rrmf->shpool->mutex);
				ngx_slab_free(rrmf->shpool, (*p)->server_name.data);
				ngx_slab_free(rrmf->shpool, p);
			}
			
			// printf("%d: initalize %s zone\n", ngx_getpid(), rrsf->mstat->server_name.data);
		}
	}
	if (r->upstream_states != NULL)
	{
		ngx_http_upstream_state_t  *state;
		state = r->upstream_states->elts;
		size_t upstream_response_length = 0;

		for (i = 0; i < r->upstream_states->nelts; i++) {			
			if (!state[i].peer) {
				continue;
			}
			upstream_response_length+=state[i].response_length;
		}

		if (upstream_response_length > 0)
		{
			ngx_atomic_fetch_add(&rrsf->mstat->upstream_recv, upstream_response_length);
		}
	}
	ngx_atomic_fetch_add(&rrsf->mstat->request, 1);
	ngx_atomic_fetch_add(&rrsf->mstat->sent, r->connection->sent);
	ngx_atomic_fetch_add(&rrsf->mstat->recv, r->request_length);
    if (r->err_status) {
		if (r->err_status >= 400 && r->err_status < 410)
		{
			ngx_atomic_fetch_add(&rrsf->mstat->request_40x, 1);
		}else if (r->err_status >= 500 && r->err_status < 510)
		{
			ngx_atomic_fetch_add(&rrsf->mstat->request_50x, 1);
		}
    } else if (r->headers_out.status) {
		if (r->headers_out.status >= 200 && r->headers_out.status < 210)
		{
			ngx_atomic_fetch_add(&rrsf->mstat->request_20x, 1);
		}else if (r->headers_out.status >= 300 && r->headers_out.status < 310)
		{
			ngx_atomic_fetch_add(&rrsf->mstat->request_30x, 1);
		}
	}

	
	return NGX_DECLINED;
}

static void *
ngx_http_realtime_request_create_conf(ngx_conf_t *cf)
{
    ngx_http_realtime_request_conf_t	*conf;
    ngx_time_t  *time;
	
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realtime_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	conf->shm_size = 4194304;	// defaults for 4M
    time = ngx_timeofday();
	conf->startup = time->sec;
	
    return conf;
}

static ngx_int_t  
ngx_http_realtime_request_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_http_realtime_request_conf_t	*rrmf = shm_zone->data;
	
	rrmf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;  
	
	rrmf->srv_list = ngx_slab_array_create(rrmf->shpool, 4, sizeof(ngx_http_realtime_request_master_srv_conf_t *));	
	
	return NGX_OK;
}

static char * ngx_http_realtime_request_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_realtime_request_conf_t	*rrmf;
	ngx_str_t		name = ngx_string("http_realtime_request_zone");
	
	rrmf = conf;
	
	// printf("%d : init size: %ld\n", ngx_getpid(), rrmf->shm_size);
	rrmf->shm_zone = ngx_shared_memory_add(cf, &name, rrmf->shm_size, &ngx_http_realtime_request_module);
	rrmf->shm_zone->init = ngx_http_realtime_request_init_zone;
	rrmf->shm_zone->data = rrmf;
	
    return NGX_CONF_OK;
}

static void *
ngx_http_realtime_request_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_realtime_request_srv_conf_t	*conf;
	
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realtime_request_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_realtime_request_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_realtime_request_srv_conf_t	*conf = child;
	conf->mstat = NULL;
	
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_realtime_request_handler_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realtime_request_handler;

    return NGX_OK;
}
