#ifndef FCGID_PM_H
#define FCGID_PM_H
#include "fcgid_global.h"

typedef struct
{
	char cgipath[_POSIX_PATH_MAX];
	apr_ino_t inode;
	dev_t deviceid;
}fcgid_command;

apr_status_t procmgr_post_spawn_cmd(const fcgid_command* command);
apr_status_t procmgr_peek_cmd(fcgid_command* command);

apr_status_t procmgr_child_init(server_rec *main_server, apr_pool_t* pchild);
apr_status_t procmgr_post_config(server_rec *main_server, apr_pool_t* pconf);

apr_status_t procmgr_stop_procmgr(void* dummy);
int procmgr_must_exit();

#endif
