#ifndef FCGID_TABLE_H
#define FCGID_TABLE_H
#include <limits.h>
#include "httpd.h"
#include "apr_thread_proc.h"
#include "fcgid_global.h"

/* Increase it if necessary */
#define FCGID_MAX_APPLICATION (1024)

/* FCGID_MAX_APPLICATION + 4 list headers */
#define FCGID_PROC_TABLE_SIZE (FCGID_MAX_APPLICATION+4)

/*
	nNextIndex is for making a node list, there are four kind of list:
	1) free list: no process associate to this node
	2) busy list: a process is associated, and it's handling request
	3) idle list: a process is associated, and it's waiting request
	4) error list: a process is associated, and killing the process now
*/
typedef struct {
	int next_index;				/* the next array index in the list */
	apr_pool_t *proc_pool;		/* pool for process */
	apr_proc_t *proc_id;		/* the process id */
	char socket_path[_POSIX_PATH_MAX];	/* cgi application socket path */
	apr_ino_t inode;			/* cgi file inode */
	apr_dev_t deviceid;			/* cgi file device id */
	 apr_size_t share_grp_id;	/* cgi wrapper share group id */
	apr_time_t start_time;		/* the time of this process create */
	apr_time_t last_active_time;	/* the time this process last active */
	char diewhy;				/* why it die */
} fcgid_procnode;

/* Macros for diewhy */
#define FCGID_DIE_KILLSELF	0
#define FCGID_DIE_IDLE_TIMEOUT 1
#define FCGID_DIE_LIFETIME_EXPIRED 2
#define FCGID_DIE_BUSY_TIMEOUT 3
#define FCGID_DIE_CONNECT_ERROR 4
#define FCGID_DIE_COMM_ERROR 5
#define FCGID_DIE_SHUTDOWN 6
#define FCGID_DIR_PROC_EXIT 7

typedef struct {
	int must_exit;				/* All processes using this share memory must exit */
} fcgid_global_share;

typedef struct {
	fcgid_global_share global;
	fcgid_procnode procnode_array[FCGID_PROC_TABLE_SIZE];
} fcgid_share;

apr_status_t proctable_child_init(server_rec * main_server,
								  apr_pool_t * pchild);
apr_status_t proctable_post_config(server_rec * main_server,
								   apr_pool_t * pconf);

apr_status_t proctable_lock_table();
apr_status_t proctable_unlock_table();

fcgid_procnode *proctable_get_free_list();
fcgid_procnode *proctable_get_busy_list();
fcgid_procnode *proctable_get_idle_list();
fcgid_procnode *proctable_get_error_list();
fcgid_procnode *proctable_get_table_array();
size_t proctable_get_table_size();
fcgid_global_share *proctable_get_globalshare();

void safe_lock(server_rec * main_server);
void safe_unlock(server_rec * main_server);

/* Just for debug */
void proctable_print_debug_info(server_rec * main_server);

#endif
