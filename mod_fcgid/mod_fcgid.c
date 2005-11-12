#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_core.h"
#include "apr_buckets.h"
#include "apr_thread_proc.h"
#include "mod_cgi.h"
#include "util_script.h"
#include "fcgid_global.h"
#include "fcgid_pm.h"
#include "fcgid_proctbl.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#include "fcgid_bridge.h"
#include "fcgid_filter.h"

module AP_MODULE_DECLARE_DATA fcgid_module;
static APR_OPTIONAL_FN_TYPE(ap_cgi_build_command) * cgi_build_command;
static ap_filter_rec_t *fcgid_filter_handle;

/* Stolen from mod_cgi.c */
/* KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

static int is_scriptaliased(request_rec * r)
{
	const char *t = apr_table_get(r->notes, "alias-forced-type");

	return t && (!strcasecmp(t, "cgi-script"));
}

static apr_status_t
default_build_command(const char **cmd, const char ***argv,
					  request_rec * r, apr_pool_t * p,
					  cgi_exec_info_t * e_info)
{
	int numwords, x, idx;
	char *w;
	const char *args = NULL;

	if (e_info->process_cgi) {
		*cmd = r->filename;
		/* Do not process r->args if they contain an '=' assignment 
		 */
		if (r->args && r->args[0] && !ap_strchr_c(r->args, '=')) {
			args = r->args;
		}
	}

	if (!args) {
		numwords = 1;
	} else {
		/* count the number of keywords */
		for (x = 0, numwords = 2; args[x]; x++) {
			if (args[x] == '+') {
				++numwords;
			}
		}
	}
	/* Everything is - 1 to account for the first parameter 
	 * which is the program name.
	 */
	if (numwords > APACHE_ARG_MAX - 1) {
		numwords = APACHE_ARG_MAX - 1;	/* Truncate args to prevent overrun */
	}
	*argv = apr_palloc(p, (numwords + 2) * sizeof(char *));
	(*argv)[0] = *cmd;
	for (x = 1, idx = 1; x < numwords; x++) {
		w = ap_getword_nulls(p, &args, '+');
		ap_unescape_url(w);
		(*argv)[idx++] = ap_escape_shell_cmd(p, w);
	}
	(*argv)[idx] = NULL;

	return APR_SUCCESS;
}

/* End of stolen */

static int fcgid_handler(request_rec * r)
{
	cgi_exec_info_t e_info;
	const char *command;
	const char **argv;
	apr_pool_t *p;
	apr_status_t rv;
	int http_retcode;
	fcgid_wrapper_conf *wrapper_conf;

	if (strcmp(r->handler, "fcgid-script"))
		return DECLINED;

	if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r))
		return HTTP_FORBIDDEN;

	if (r->finfo.filetype == 0)
		return HTTP_NOT_FOUND;

	if (r->finfo.filetype == APR_DIR)
		return HTTP_FORBIDDEN;

	if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
		r->path_info && *r->path_info)
		return HTTP_NOT_FOUND;

	e_info.process_cgi = 1;
	e_info.cmd_type = APR_PROGRAM;
	e_info.detached = 0;
	e_info.in_pipe = APR_CHILD_BLOCK;
	e_info.out_pipe = APR_CHILD_BLOCK;
	e_info.err_pipe = APR_CHILD_BLOCK;
	e_info.prog_type = RUN_AS_CGI;
	e_info.bb = NULL;
	e_info.ctx = NULL;
	e_info.next = NULL;
	p = r->main ? r->main->pool : r->pool;

	/* Build the command line */
	if ((wrapper_conf = get_wrapper_info(r->filename, r))) {
		if ((rv =
			 default_build_command(&command, &argv, r, p,
								   &e_info)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
						  "mod_fcgid: don't know how to spawn wrapper child process: %s",
						  r->filename);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	} else if ((rv =
				cgi_build_command(&command, &argv, r, p,
								  &e_info)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
					  "mod_fcgid: don't know how to spawn child process: %s",
					  r->filename);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Check request like "http://localhost/cgi-bin/a.exe/defghi" */
	if (!wrapper_conf && r->finfo.inode == 0 && r->finfo.device == 0) {
		if ((rv =
			 apr_stat(&r->finfo, command, APR_FINFO_IDENT,
					  r->pool)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
						 "mod_fcgid: can't get %s file info", command);
			return HTTP_NOT_FOUND;
		}
	}

	ap_add_common_vars(r);
	ap_add_cgi_vars(r);

	/* Insert output filter */
	ap_add_output_filter_handle(fcgid_filter_handle, NULL, r,
								r->connection);

	http_retcode = bridge_request(r, command, wrapper_conf);
	return (http_retcode == HTTP_OK ? OK : http_retcode);
}

static void initialize_child(apr_pool_t * pchild, server_rec * main_server)
{
	apr_status_t rv;

	if ((rv = proctable_child_init(main_server, pchild)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't initialize share memory or mutex in child");
		return;
	}

	if ((rv = procmgr_child_init(main_server, pchild)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't initialize process manager");
		return;
	}

	return;
}

static int
fcgid_init(apr_pool_t * config_pool, apr_pool_t * plog, apr_pool_t * ptemp,
		   server_rec * main_server)
{
	apr_proc_t *procnew;
	const char *userdata_key = "fcgid_init";
	apr_status_t rv;
	void *dummy = NULL;

	/* Initialize process manager only once */
	apr_pool_userdata_get(&dummy, userdata_key, main_server->process->pool);
	if (!dummy) {
		procnew =
			apr_pcalloc(main_server->process->pool, sizeof(*procnew));
		procnew->pid = -1;
		procnew->err = procnew->in = procnew->out = NULL;
		apr_pool_userdata_set((const void *) procnew, userdata_key,
							  apr_pool_cleanup_null,
							  main_server->process->pool);
		return OK;
	}
	else {
		procnew = dummy;
	}

	/* Initialize share memory and share lock */
	if ((rv =
		 proctable_post_config(main_server, config_pool)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't initialize share memory or mutex");
		return rv;
	}

	/* Initialize process manager */
	if ((rv =
		 procmgr_post_config(main_server, config_pool)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't initialize process manager");
		return rv;
	}

	/* This is the means by which unusual (non-unix) os's may find alternate
	 * means to run a given command (e.g. shebang/registry parsing on Win32)
	 */
	cgi_build_command = APR_RETRIEVE_OPTIONAL_FN(ap_cgi_build_command);
	if (!cgi_build_command) {
		cgi_build_command = default_build_command;
	}

	return APR_SUCCESS;
}

static const command_rec fcgid_cmds[] = {
	AP_INIT_TAKE1("IdleTimeout", set_idle_timeout, NULL, RSRC_CONF,
				  "an idle fastcgi application will be killed after IdleTimeout"),
	AP_INIT_TAKE1("IdleScanInterval", set_idle_scan_interval, NULL,
				  RSRC_CONF,
				  "scan interval for idle timeout process"),
	AP_INIT_TAKE1("BusyTimeout", set_busy_timeout, NULL, RSRC_CONF,
				  "a fastcgi application will be killed after handling a request for BusyTimeout"),
	AP_INIT_TAKE1("BusyScanInterval", set_busy_scan_interval, NULL,
				  RSRC_CONF,
				  "scan interval for busy timeout process"),
	AP_INIT_TAKE1("ErrorScanInterval", set_error_scan_interval, NULL,
				  RSRC_CONF,
				  "scan interval for exited process"),
	AP_INIT_TAKE1("ZombieScanInterval", set_zombie_scan_interval, NULL,
				  RSRC_CONF,
				  "scan interval for zombiz process"),
	AP_INIT_TAKE1("ProcessLifeTime", set_proc_lifetime, NULL, RSRC_CONF,
				  "fastcgi application lifetime"),
	AP_INIT_TAKE1("SocketPath", set_socketpath, NULL, RSRC_CONF,
				  "fastcgi socket file path"),
	AP_INIT_TAKE1("SpawnScoreUpLimit", set_spawnscore_uplimit, NULL,
				  RSRC_CONF,
				  "Spawn score up limit"),
	AP_INIT_TAKE1("SpawnScore", set_spawn_score, NULL, RSRC_CONF,
				  "Score of spawn"),
	AP_INIT_TAKE1("TerminationScore", set_termination_score, NULL,
				  RSRC_CONF,
				  "Score of termination"),
	AP_INIT_TAKE1("MaxProcessCount", set_max_process, NULL, RSRC_CONF,
				  "Max total process count"),
	AP_INIT_TAKE1("DefaultMaxClassProcessCount",
				  set_default_max_class_process,
				  NULL, RSRC_CONF,
				  "Max process count of one class of fastcgi application"),
	AP_INIT_TAKE1("OutputBufferSize", set_output_buffersize, NULL,
				  RSRC_CONF,
				  "CGI output buffer size"),
	AP_INIT_TAKE1("IPCConnectTimeout", set_ipc_connect_timeout, NULL,
				  RSRC_CONF,
				  "Connect timeout to fastcgi server"),
	AP_INIT_TAKE1("IPCCommTimeout", set_ipc_comm_timeout, NULL, RSRC_CONF,
				  "Communication timeout to fastcgi server"),
	AP_INIT_TAKE12("DefaultInitEnv", add_default_env_vars, NULL, RSRC_CONF,
				   "an environment variable name and optional value to pass to FastCGI."),
	AP_INIT_TAKE12("FCGIWrapper", set_wrapper_config, NULL, ACCESS_CONF,
				   "The CGI wrapper setting"),
	{NULL}
};

static void register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(fcgid_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(fcgid_handler, NULL, NULL, APR_HOOK_MIDDLE);

	/* Insert fcgid output filter */
	fcgid_filter_handle =
		ap_register_output_filter("FCGID_OUT",
								  fcgid_filter,
								  NULL, AP_FTYPE_RESOURCE - 10);
}

module AP_MODULE_DECLARE_DATA fcgid_module = {
	STANDARD20_MODULE_STUFF,
	create_fcgid_dir_config,	/* create per-directory config structure */
	NULL,						/* merge per-directory config structures */
	create_fcgid_server_config,	/* create per-server config structure */
	merge_fcgid_server_config,	/* merge per-server config structures */
	fcgid_cmds,					/* command apr_table_t */
	register_hooks				/* register hooks */
};
