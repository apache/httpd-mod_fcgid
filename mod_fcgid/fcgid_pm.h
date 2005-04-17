#ifndef FCGID_PM_H
#define FCGID_PM_H
#include "fcgid_global.h"
#define INITENV_KEY_LEN 64
#define INITENV_VAL_LEN 128
#define INITENV_CNT 64

typedef struct {
	char cgipath[_POSIX_PATH_MAX];
	char wrapperpath[_POSIX_PATH_MAX];
	apr_ino_t inode;
	dev_t deviceid;
	apr_size_t share_grp_id;
	uid_t uid;					/* For suEXEC */
	gid_t gid;					/* For suEXEC */
	int userdir;				/* For suEXEC */
	char initenv_key[INITENV_CNT][INITENV_KEY_LEN];
	char initenv_val[INITENV_CNT][INITENV_VAL_LEN];
} fcgid_command;

void procmgr_init_spawn_cmd(fcgid_command * command, request_rec * r,
							const char *argv0, dev_t deviceid,
							apr_ino_t inode, apr_size_t share_grp_id);
apr_status_t procmgr_post_spawn_cmd(fcgid_command * command,
									request_rec * r);
apr_status_t procmgr_peek_cmd(fcgid_command * command,
							  server_rec * main_server);
apr_status_t procmgr_finish_notify(server_rec * main_server);

apr_status_t procmgr_child_init(server_rec * main_server,
								apr_pool_t * pchild);
apr_status_t procmgr_post_config(server_rec * main_server,
								 apr_pool_t * pconf);

apr_status_t procmgr_stop_procmgr(void *dummy);
int procmgr_must_exit();

#endif
