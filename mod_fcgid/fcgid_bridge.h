#ifndef FCGID_BRIDGE_H
#define FCGID_BRIDGE_H
#include "httpd.h"

int bridge_request(request_rec* r, const char* argv0);

#endif
