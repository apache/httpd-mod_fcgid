#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "fcgid_filter.h"
#include "fcgid_bucket.h"
#include "fcgid_conf.h"
static int g_hasinit = 0;
static int g_buffsize = 0;

apr_status_t fcgid_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
	apr_status_t rv;
	apr_bucket_brigade *tmp_brigade;
	int save_size = 0;
	conn_rec *c = f->c;
	server_rec *main_server = f->r->server;

	if (!g_hasinit) {
		g_buffsize = get_output_buffersize(main_server);
		g_hasinit = 1;
	}

	tmp_brigade =
		apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
	while (!APR_BRIGADE_EMPTY(bb)) {
		apr_size_t readlen;
		const char *buffer;

		apr_bucket *e = APR_BRIGADE_FIRST(bb);

		if (APR_BUCKET_IS_EOS(e))
			break;

		if (APR_BUCKET_IS_METADATA(e)) {
			apr_bucket_delete(e);
			continue;
		}

		/* Read the bucket now */
		if ((rv = apr_bucket_read(e, &buffer, &readlen,
								  APR_BLOCK_READ)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_INFO, rv,
						 main_server,
						 "mod_fcgid: can't read data from fcgid handler");
			return rv;
		}

		/* Move on to next bucket if it's fastcgi header bucket */
		if (e->type == &ap_bucket_type_fcgid_header
			|| (e->type == &apr_bucket_type_immortal && readlen == 0)) {
			apr_bucket_delete(e);
			continue;
		}
		save_size += readlen;

		/* Cache it to tmp_brigade */
		APR_BUCKET_REMOVE(e);
		APR_BRIGADE_INSERT_TAIL(tmp_brigade, e);

		/* I will pass tmp_brigade to next filter if I have got too much buckets */
		if (save_size > g_buffsize) {
			APR_BRIGADE_INSERT_TAIL(tmp_brigade,
									apr_bucket_flush_create(f->r->
															connection->
															bucket_alloc));

			if ((rv =
				 ap_pass_brigade(f->next, tmp_brigade)) != APR_SUCCESS)
				return rv;

			/* Is the client aborted? */
			if (c && c->aborted)
				return APR_SUCCESS;

			save_size = 0;
		}
	}

	/* Any thing left? */
	if (!APR_BRIGADE_EMPTY(tmp_brigade)) {
		if ((rv = ap_pass_brigade(f->next, tmp_brigade)) != APR_SUCCESS)
			return rv;
	}

	/* This filter is done once it has served up its content */
	ap_remove_output_filter(f);
	return APR_SUCCESS;
}
