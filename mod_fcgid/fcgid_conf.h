#ifndef FCGID_CONF_H
#define FCGID_CONF_H
#include "apr_user.h"
#include "fcgid_global.h"

typedef struct {
	char wrapper_path[_POSIX_PATH_MAX];
	apr_ino_t inode;
	apr_dev_t deviceid;
	apr_size_t share_group_id;
} fcgid_wrapper_conf;

typedef struct {
	int idle_timeout;
	int idle_scan_interval;
	int busy_timeout;
	int busy_scan_interval;
	int proc_lifetime;
	int error_scan_interval;
	int zombie_scan_interval;
	char *sockname_prefix;
	int spawnscore_uplimit;
	int spawn_score;
	int termination_score;
	int max_process_count;
	int default_max_class_process_count;
	int ipc_connect_timeout;
	int ipc_comm_timeout;
	int output_buffersize;
	apr_table_t *default_init_env;
	apr_hash_t *wrapper_info_hash;
} fcgid_conf;

void *create_fcgid_config(apr_pool_t * p, server_rec * s);
void *merge_fcgid_config(apr_pool_t * p, void *basev, void *overridesv);

const char *set_idle_timeout(cmd_parms * cmd, void *dummy,
							 const char *arg);
int get_idle_timeout(server_rec * s);

const char *set_idle_scan_interval(cmd_parms * cmd, void *dummy,
								   const char *arg);
int get_idle_scan_interval(server_rec * s);

const char *set_busy_timeout(cmd_parms * cmd, void *dummy,
							 const char *arg);
int get_busy_timeout(server_rec * s);

const char *set_busy_scan_interval(cmd_parms * cmd, void *dummy,
								   const char *arg);
int get_busy_scan_interval(server_rec * s);

const char *set_proc_lifetime(cmd_parms * cmd, void *dummy,
							  const char *arg);
int get_proc_lifetime(server_rec * s);

const char *set_error_scan_interval(cmd_parms * cmd, void *dummy,
									const char *arg);
int get_error_scan_interval(server_rec * s);

const char *set_zombie_scan_interval(cmd_parms * cmd, void *dummy,
									 const char *arg);
int get_zombie_scan_interval(server_rec * s);

const char *set_socketpath(cmd_parms * cmd, void *dummy, const char *arg);
const char *get_socketpath(server_rec * s);

const char *set_termination_score(cmd_parms * cmd, void *dummy,
								  const char *arg);
int get_termination_score(server_rec * s);

const char *set_spawn_score(cmd_parms * cmd, void *dummy, const char *arg);
int get_spawn_score(server_rec * s);

const char *set_spawnscore_uplimit(cmd_parms * cmd, void *dummy,
								   const char *arg);
int get_spawnscore_uplimit(server_rec * s);

const char *set_max_process(cmd_parms * cmd, void *dummy, const char *arg);
int get_max_process(server_rec * s);

const char *set_default_max_class_process(cmd_parms * cmd, void *dummy,
										  const char *arg);
int get_default_max_class_process(server_rec * s);

const char *set_ipc_connect_timeout(cmd_parms * cmd, void *dummy,
									const char *arg);
int get_ipc_connect_timeout(server_rec * s);

const char *set_ipc_comm_timeout(cmd_parms * cmd, void *dummy,
								 const char *arg);
int get_ipc_comm_timeout(server_rec * s);

const char *set_output_buffersize(cmd_parms * cmd, void *dummy,
								  const char *arg);

int get_output_buffersize(server_rec * s);

const char *add_default_env_vars(cmd_parms * cmd, void *sconf,
								 const char *name, const char *value);
apr_table_t *get_default_env_vars(request_rec * r);

const char *set_wrapper_config(cmd_parms * cmd, void *dummy,
							   const char *wrapper, const char *extension);
fcgid_wrapper_conf *get_wrapper_info(const char *cgipath, request_rec * r);

#endif
