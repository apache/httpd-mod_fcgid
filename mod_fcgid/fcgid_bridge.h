#ifndef FCGID_BRIDGE_H
#define FCGID_BRIDGE_H
#include "httpd.h"
#include "ap_config.h"
#include "http_config.h"
#include "apr_hash.h"
#include "fcgid_conf.h"

int bridge_request(request_rec * r, const char *argv0,
				   fcgid_wrapper_conf * wrapper_conf);

#endif
