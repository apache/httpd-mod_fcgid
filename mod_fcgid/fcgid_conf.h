#ifndef FCGID_CONF_H
#define FCGID_CONF_H
#include "apr_user.h"

struct fcgi_server_info
{
  apr_ino_t inode;
  apr_dev_t deviceid;
  apr_table_t *init_env;
  int max_class_process_count;
  int has_merge;
  struct fcgi_server_info *next;
};
#define LOCAL_MAX_CLASS_NOT_SET -1	/* for max_class_process_count */

#define FCGID_MAX_ID_LEN 128
typedef struct
{
  char wrapper_path[APR_PATH_MAX];
  apr_uid_t uid;
  apr_gid_t gid;
}
fcgid_wrapper_conf;

typedef struct
{
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
  apr_table_t *default_init_env;
  apr_hash_t *wrapper_info_hash;
  struct fcgi_server_info *server_info;
}
fcgid_conf;

void *create_fcgid_config (apr_pool_t * p, server_rec * s);

const char *set_idle_timeout (cmd_parms * cmd, void *dummy, const char *arg);
int get_idle_timeout (server_rec * s);

const char *set_idle_scan_interval (cmd_parms * cmd, void *dummy,
				    const char *arg);
int get_idle_scan_interval (server_rec * s);

const char *set_busy_timeout (cmd_parms * cmd, void *dummy, const char *arg);
int get_busy_timeout (server_rec * s);

const char *set_busy_scan_interval (cmd_parms * cmd, void *dummy,
				    const char *arg);
int get_busy_scan_interval (server_rec * s);

const char *set_proc_lifetime (cmd_parms * cmd, void *dummy, const char *arg);
int get_proc_lifetime (server_rec * s);

const char *set_error_scan_interval (cmd_parms * cmd, void *dummy,
				     const char *arg);
int get_error_scan_interval (server_rec * s);

const char *set_zombie_scan_interval (cmd_parms * cmd, void *dummy,
				      const char *arg);
int get_zombie_scan_interval (server_rec * s);

const char *set_socketpath (cmd_parms * cmd, void *dummy, const char *arg);
const char *get_socketpath (server_rec * s);

const char *set_termination_score (cmd_parms * cmd, void *dummy,
				   const char *arg);
int get_termination_score (server_rec * s);

const char *set_spawn_score (cmd_parms * cmd, void *dummy, const char *arg);
int get_spawn_score (server_rec * s);

const char *set_spawnscore_uplimit (cmd_parms * cmd, void *dummy,
				    const char *arg);
int get_spawnscore_uplimit (server_rec * s);

const char *set_max_process (cmd_parms * cmd, void *dummy, const char *arg);
int get_max_process (server_rec * s);

const char *set_default_max_class_process (cmd_parms * cmd, void *dummy,
					   const char *arg);
int get_default_max_class_process (server_rec * s);

const char *set_ipc_connect_timeout (cmd_parms * cmd, void *dummy,
				     const char *arg);
int get_ipc_connect_timeout (server_rec * s);

const char *set_ipc_comm_timeout (cmd_parms * cmd, void *dummy,
				  const char *arg);
int get_ipc_comm_timeout (server_rec * s);

const char *add_default_env_vars (cmd_parms * cmd, void *sconf,
				  const char *name, const char *value);

const char *set_server_config (cmd_parms * cmd, void *dummy,
			       const char *thearg);

void get_server_info (server_rec * main_server,
		      apr_ino_t inode, apr_dev_t deviceid,
		      struct fcgi_server_info *info);

const char *set_wrapper_config (cmd_parms * cmd, void *dummy,
				const char *arg);
fcgid_wrapper_conf *get_wrapper_info (const char *cgipath, server_rec * s);

#endif
