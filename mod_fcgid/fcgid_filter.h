#ifndef FCGID_FILTER_H
#define FCGID_FILTER_H
#include "util_filter.h"
#include "apr_buckets.h"

apr_status_t fcgid_filter(ap_filter_t * f, apr_bucket_brigade * bb);

#endif
