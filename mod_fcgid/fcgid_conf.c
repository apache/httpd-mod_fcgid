#include "ap_config.h"
#include "ap_mmn.h"
#include "apr_strings.h"
#include "http_main.h"
#include "httpd.h"
#include "http_config.h"
#include "fcgid_global.h"
#include "fcgid_conf.h"
extern module AP_MODULE_DECLARE_DATA fcgid_module;

#define DEFAULT_IDLE_TIMEOUT 300
#define DEFAULT_IDLE_SCAN_INTERVAL 120
#define DEFAULT_BUSY_TIMEOUT 300
#define DEFAULT_BUSY_SCAN_INTERVAL 120
#define DEFAULT_ERROR_SCAN_INTERVAL 3
#define DEFAULT_ZOMBIE_SCAN_INTERVAL 3
#define DEFAULT_PROC_LIFETIME (60*60)
#define DEFAULT_SOCKET_PREFIX "logs/fcgidsock"
#define DEFAULT_SPAWNSOCRE_UPLIMIT 10
#define DEFAULT_SPAWN_SCORE 1
#define DEFAULT_TERMINATION_SCORE 2
#define DEFAULT_MAX_PROCESS_COUNT 1000
#define DEFAULT_MAX_CLASS_PROCESS_COUNT 100
#define DEFAULT_IPC_CONNECT_TIMEOUT 2
#define DEFAULT_IPC_COMM_TIMEOUT 5
#define DEFAULT_OUTPUT_BUFFERSIZE 65536

void *create_fcgid_config(apr_pool_t * p, server_rec * s)
{
	fcgid_conf *config = apr_pcalloc(p, sizeof(*config));

	config->default_init_env = apr_table_make(p, 20);
	config->sockname_prefix =
		ap_server_root_relative(p, DEFAULT_SOCKET_PREFIX);
	config->idle_timeout = DEFAULT_IDLE_TIMEOUT;
	config->idle_scan_interval = DEFAULT_IDLE_SCAN_INTERVAL;
	config->busy_timeout = DEFAULT_BUSY_TIMEOUT;
	config->busy_scan_interval = DEFAULT_BUSY_SCAN_INTERVAL;
	config->proc_lifetime = DEFAULT_PROC_LIFETIME;
	config->error_scan_interval = DEFAULT_ERROR_SCAN_INTERVAL;
	config->zombie_scan_interval = DEFAULT_ZOMBIE_SCAN_INTERVAL;
	config->spawn_score = DEFAULT_SPAWN_SCORE;
	config->spawnscore_uplimit = DEFAULT_SPAWNSOCRE_UPLIMIT;
	config->termination_score = DEFAULT_TERMINATION_SCORE;
	config->default_max_class_process_count =
		DEFAULT_MAX_CLASS_PROCESS_COUNT;
	config->max_process_count = DEFAULT_MAX_PROCESS_COUNT;
	config->ipc_comm_timeout = DEFAULT_IPC_COMM_TIMEOUT;
	config->ipc_connect_timeout = DEFAULT_IPC_CONNECT_TIMEOUT;
	config->output_buffersize = DEFAULT_OUTPUT_BUFFERSIZE;
	config->wrapper_info_hash = apr_hash_make(p);
	return config;
}

const char *set_idle_timeout(cmd_parms * cmd, void *dummy, const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->idle_timeout = atol(arg);
	return NULL;
}

int get_idle_timeout(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->idle_timeout : DEFAULT_IDLE_TIMEOUT;
}

const char *set_idle_scan_interval(cmd_parms * cmd, void *dummy,
								   const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->idle_scan_interval = atol(arg);
	return NULL;
}

int get_idle_scan_interval(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->idle_scan_interval : DEFAULT_IDLE_TIMEOUT;
}

const char *set_busy_timeout(cmd_parms * cmd, void *dummy, const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->busy_timeout = atol(arg);
	return NULL;
}

int get_busy_timeout(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->busy_timeout : DEFAULT_BUSY_TIMEOUT;
}

const char *set_busy_scan_interval(cmd_parms * cmd, void *dummy,
								   const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->busy_scan_interval = atol(arg);
	return NULL;
}

int get_busy_scan_interval(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->
		busy_scan_interval : DEFAULT_BUSY_SCAN_INTERVAL;
}

const char *set_proc_lifetime(cmd_parms * cmd, void *dummy,
							  const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->proc_lifetime = atol(arg);
	return NULL;
}

int get_proc_lifetime(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->proc_lifetime : DEFAULT_PROC_LIFETIME;
}

const char *set_error_scan_interval(cmd_parms * cmd, void *dummy,
									const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->error_scan_interval = atol(arg);
	return NULL;
}

int get_error_scan_interval(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->
		error_scan_interval : DEFAULT_ERROR_SCAN_INTERVAL;
}

const char *set_zombie_scan_interval(cmd_parms * cmd, void *dummy,
									 const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->zombie_scan_interval = atol(arg);
	return NULL;
}

int get_zombie_scan_interval(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->
		zombie_scan_interval : DEFAULT_ZOMBIE_SCAN_INTERVAL;
}

const char *set_socketpath(cmd_parms * cmd, void *dummy, const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->sockname_prefix = ap_server_root_relative(cmd->pool, arg);
	if (!config->sockname_prefix)
		return "Invalid socket path";

	return NULL;
}

const char *get_socketpath(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config->sockname_prefix;
}

const char *set_spawnscore_uplimit(cmd_parms * cmd, void *dummy,
								   const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->spawnscore_uplimit = atol(arg);
	return NULL;
}

int get_spawnscore_uplimit(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->
		spawnscore_uplimit : DEFAULT_SPAWNSOCRE_UPLIMIT;
}

const char *set_spawn_score(cmd_parms * cmd, void *dummy, const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->spawn_score = atol(arg);
	return NULL;
}

int get_spawn_score(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->spawn_score : DEFAULT_SPAWN_SCORE;
}

const char *set_termination_score(cmd_parms * cmd, void *dummy,
								  const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->termination_score = atol(arg);
	return NULL;
}

int get_termination_score(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->termination_score : DEFAULT_TERMINATION_SCORE;
}

const char *set_max_process(cmd_parms * cmd, void *dummy, const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->max_process_count = atol(arg);
	return NULL;
}

int get_max_process(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->max_process_count : DEFAULT_MAX_PROCESS_COUNT;
}

const char *set_output_buffersize(cmd_parms * cmd, void *dummy,
								  const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->output_buffersize = atol(arg);
	return NULL;
}

int get_output_buffersize(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->output_buffersize : DEFAULT_OUTPUT_BUFFERSIZE;
}

const char *set_default_max_class_process(cmd_parms * cmd, void *dummy,
										  const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->default_max_class_process_count = atol(arg);
	return NULL;
}

int get_default_max_class_process(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->
		default_max_class_process_count : DEFAULT_MAX_CLASS_PROCESS_COUNT;
}

const char *set_ipc_connect_timeout(cmd_parms * cmd, void *dummy,
									const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->ipc_connect_timeout = atol(arg);
	return NULL;
}

int get_ipc_connect_timeout(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->
		ipc_connect_timeout : DEFAULT_IPC_CONNECT_TIMEOUT;
}

const char *set_ipc_comm_timeout(cmd_parms * cmd, void *dummy,
								 const char *arg)
{
	server_rec *s = cmd->server;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	config->ipc_comm_timeout = atol(arg);
	return NULL;
}

int get_ipc_comm_timeout(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config ? config->ipc_comm_timeout : DEFAULT_IPC_COMM_TIMEOUT;
}

const char *add_default_env_vars(cmd_parms * cmd, void *dummy,
								 const char *name, const char *value)
{
	fcgid_conf *config = ap_get_module_config(cmd->server->module_config,
											  &fcgid_module);

	apr_table_set(config->default_init_env, name, value ? value : "");
	return NULL;
}

apr_table_t *get_default_env_vars(server_rec * s)
{
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	return config->default_init_env;
}

const char *set_wrapper_config(cmd_parms * cmd, void *dummy,
							   const char *wrapperpath,
							   const char *extension)
{
	apr_status_t rv;
	apr_finfo_t finfo;
	const char *checkarg;
	char *hashkey, *tmpfilename;
	char dirpath[APR_PATH_MAX];
	fcgid_wrapper_conf *wrapper = NULL;
	fcgid_conf *config;

	if ((checkarg =
		 ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LOCATION)))
		return checkarg;

	config =
		ap_get_module_config(cmd->server->module_config, &fcgid_module);

	/* Get the file path */
	apr_snprintf(dirpath, APR_PATH_MAX - 1, "%s", cmd->path);
	dirpath[APR_PATH_MAX - 1] = '\0';

	/* Append the missing '/' */
	if ((rv = apr_filepath_merge(&tmpfilename, dirpath, "",
								 APR_FILEPATH_NOTRELATIVE,
								 cmd->temp_pool)) != APR_SUCCESS)
		return "Can't merge file path";
	apr_snprintf(dirpath, APR_PATH_MAX - 1, "%s", tmpfilename);
	dirpath[APR_PATH_MAX - 1] = '\0';

	/* Create the wrapper node */
	wrapper = apr_pcalloc(cmd->server->process->pconf, sizeof(*wrapper));
	if (!wrapper)
		return "Can't alloc memory for wrapper";
	strncpy(wrapper->wrapper_path, wrapperpath, APR_PATH_MAX - 1);
	wrapper->wrapper_path[APR_PATH_MAX - 1] = '\0';

	/* Is the wrapper exist? */
	if ((rv = apr_stat(&finfo, wrapper->wrapper_path, APR_FINFO_NORM,
					   cmd->temp_pool)) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
							"can't get fastcgi file info: %s, errno: %d",
							wrapper->wrapper_path, apr_get_os_error());
	}

	/* Set inode, device id & shareid */
	wrapper->inode = finfo.inode;
	wrapper->deviceid = finfo.device;
	wrapper->share_group_id = (apr_size_t) - 1;

	/* Add the node now */
	if (extension == NULL) {
		hashkey = apr_psprintf(cmd->pool, "%s", dirpath);
		apr_hash_set(config->wrapper_info_hash, hashkey, strlen(hashkey),
					 wrapper);
	} else if (*extension != '.' || *(extension + 1) == '\0'
			   || strchr(extension, '/') || strchr(extension, '\\'))
		return "Invalid wrapper file extension";
	else {
		hashkey = apr_psprintf(cmd->pool, "%s", extension);
		apr_hash_set(config->wrapper_info_hash, hashkey, strlen(hashkey),
					 wrapper);
	}

	return NULL;
}

const char *set_wrappergrp_config(cmd_parms * cmd, void *dummy,
								  const char *thearg)
{
	fcgid_conf *config = ap_get_module_config(cmd->server->module_config,
											  &fcgid_module);
	const char *args = thearg;
	char *wrapperpath, *thisdir;
	apr_status_t rv;
	apr_finfo_t finfo;
	const char *arg;
	apr_size_t share_group_id;

	/* Get the file path */
	if ((arg = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LOCATION)))
		return arg;

	/* Sanity check */
	if (*args == '\0')
		return "ServerConfig requires an argument";

	/* Append the missing '/' */
	if ((rv = apr_filepath_merge(&thisdir, cmd->path, "",
								 APR_FILEPATH_NOTRELATIVE,
								 cmd->temp_pool)) != APR_SUCCESS)
		return "Can't merge file path";

	/* Get the wrapper file path */
	arg = ap_getword_conf(cmd->pool, &args);
	if ((rv = apr_filepath_merge(&wrapperpath, cmd->path, arg,
								 APR_FILEPATH_NOTRELATIVE,
								 cmd->temp_pool)) != APR_SUCCESS)
		return "Can't merge wrapper file path";

	/* Get the wrapper device id and inode */
	if ((rv =
		 apr_stat(&finfo, wrapperpath, APR_FINFO_INODE | APR_FINFO_DEV,
				  cmd->temp_pool)) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
							"can't get fastcgi wrapper file info: %s, errno: %d",
							wrapperpath, apr_get_os_error());
	}

	/* Now insert the node which share this wrapper */
	share_group_id = apr_hash_count(config->wrapper_info_hash);
	while (1) {
		fcgid_wrapper_conf *wrapper;
		char *hashkey;

		arg = ap_getword_conf(cmd->pool, &args);
		if (!arg)
			break;
		if (*arg == '\0')
			break;

		/* Create wrapper node */
		wrapper =
			apr_pcalloc(cmd->server->process->pconf, sizeof(*wrapper));
		if (!wrapper)
			return "Can't alloc memory for wrapper";
		strncpy(wrapper->wrapper_path, wrapperpath, APR_PATH_MAX - 1);
		wrapper->wrapper_path[APR_PATH_MAX - 1] = '\0';
		wrapper->inode = finfo.inode;
		wrapper->deviceid = finfo.device;
		wrapper->share_group_id = share_group_id;

		/* Add the node now */
		hashkey = apr_psprintf(cmd->pool, "%s%s", thisdir, arg);
		apr_hash_set(config->wrapper_info_hash, hashkey, strlen(hashkey),
					 wrapper);
	}

	return NULL;
}

fcgid_wrapper_conf *get_wrapper_info(const char *cgipath, server_rec * s)
{
	char *extension;
	fcgid_conf *config =
		ap_get_module_config(s->module_config, &fcgid_module);
	char directory[APR_PATH_MAX + 1];
	char *last_slash;
	fcgid_wrapper_conf *wrapperinfo;

	/* Is it match the file path exactly? */
	if ((wrapperinfo = apr_hash_get(config->wrapper_info_hash, cgipath,
									strlen(cgipath))))
		return wrapperinfo;

	/* Is it match file name extension? */
	extension = ap_strrchr_c(cgipath, '.');
	if (extension != NULL)
		return apr_hash_get(config->wrapper_info_hash, extension,
							strlen(extension));

	/* Not match the full path and extension, try the directory now */
	strncpy(directory, cgipath, APR_PATH_MAX);
	directory[APR_PATH_MAX] = '\0';
	last_slash = ap_strrchr_c(directory, '/');
	if (last_slash == NULL)
		return NULL;
	last_slash++;
	*last_slash = '\0';

	return apr_hash_get(config->wrapper_info_hash, directory,
						strlen(directory));
}
