#ifndef FCGID_BUCKET_H
#define FCGID_BUCKET_H
#include "httpd.h"
#include "fcgid_proc.h"

typedef struct fcgid_bucket_ctx_t {
	fcgid_ipc ipc;
	apr_bucket *buffer;
	fcgid_procnode *procnode;
	apr_time_t active_time;
	int has_error;
} fcgid_bucket_ctx;

extern const apr_bucket_type_t ap_bucket_type_fcgid_header;
apr_bucket *ap_bucket_fcgid_header_create(apr_bucket_alloc_t * list,
										  fcgid_bucket_ctx * ctx);

#endif
