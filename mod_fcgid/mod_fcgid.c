#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
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
#include "fcgid_protocol.h"

module AP_MODULE_DECLARE_DATA fcgid_module;
static APR_OPTIONAL_FN_TYPE(ap_cgi_build_command) * cgi_build_command;
static ap_filter_rec_t *fcgid_filter_handle;
static int g_php_fix_pathinfo_enable = 0;

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

static void fcgid_add_cgi_vars(request_rec * r)
{
	apr_array_header_t *passheaders = get_pass_headers(r);

	if (passheaders != NULL) {
		const char **hdr = (const char **) passheaders->elts;
		int hdrcnt = passheaders->nelts;
		int i;

		for (i = 0; i < hdrcnt; i++, ++hdr) {
			const char *val = apr_table_get(r->headers_in, *hdr);

			if (val)
				apr_table_setn(r->subprocess_env, *hdr, val);
		}
	}

	/* Work around cgi.fix_pathinfo = 1 in php.ini */
	if (g_php_fix_pathinfo_enable) {
		char *merge_path;
		apr_table_t *e = r->subprocess_env;

		/* "DOCUMENT_ROOT"/"SCRIPT_NAME" -> "SCRIPT_NAME" */
		const char *doc_root = apr_table_get(e, "DOCUMENT_ROOT");
		const char *script_name = apr_table_get(e, "SCRIPT_NAME");

		if (doc_root && script_name
			&& apr_filepath_merge(&merge_path, doc_root, script_name, 0,
								  r->pool) == APR_SUCCESS) {
			apr_table_setn(e, "SCRIPT_NAME", merge_path);
		}
	}
}

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
	fcgid_add_cgi_vars(r);

	/* Insert output filter */
	ap_add_output_filter_handle(fcgid_filter_handle, NULL, r,
								r->connection);

	http_retcode =
		bridge_request(r, FCGI_RESPONDER, command, wrapper_conf);
	return (http_retcode == HTTP_OK ? OK : http_retcode);
}

static int mod_fcgid_modify_auth_header(void *subprocess_env,
										const char *key, const char *val)
{
	/* When the application gives a 200 response, the server ignores response 
	   headers whose names aren't prefixed with Variable- prefix, and ignores 
	   any response content */
	if (strncasecmp(key, "Variable-", 9) == 0)
		apr_table_setn(subprocess_env, key + 9, val);
	return 1;
}

static int mod_fcgid_authenticator(request_rec * r)
{
	int res = 0;
	const char *password = NULL;
	const char *location = NULL;
	apr_table_t *saved_subprocess_env = NULL;
	fcgid_wrapper_conf *wrapper_conf;
	auth_conf *authenticator_info;
	int authoritative;

	authenticator_info = get_authenticator_info(r, &authoritative);

	/* Is authenticator enable? */
	if (authenticator_info == NULL)
		return DECLINED;

	/* Check wrapper */
	wrapper_conf = get_wrapper_info(authenticator_info->path, r);

	/* Get the user password */
	if ((res = ap_get_basic_auth_pw(r, &password)) != OK)
		return res;

	/* Save old process environment */
	saved_subprocess_env = apr_table_copy(r->pool, r->subprocess_env);

	/* Add some environment variables */
	ap_add_common_vars(r);
	ap_add_cgi_vars(r);
	fcgid_add_cgi_vars(r);
	apr_table_setn(r->subprocess_env, "REMOTE_PASSWD", password);
	apr_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", "AUTHENTICATOR");

	/* Remove some environment variables */
	/* The Web server does not send CONTENT_LENGTH, PATH_INFO, PATH_TRANSLATED, and SCRIPT_NAME headers */
	apr_table_unset(r->subprocess_env, "CONTENT_LENGTH");
	apr_table_unset(r->subprocess_env, "PATH_INFO");
	apr_table_unset(r->subprocess_env, "PATH_TRANSLATED");
	apr_table_unset(r->subprocess_env, "SCRIPT_NAME");

	/* Handle the request */
	res =
		bridge_request(r, FCGI_AUTHORIZER, authenticator_info->path,
					   wrapper_conf);

	/* Restore r->subprocess_env */
	r->subprocess_env = saved_subprocess_env;

	if (res == OK && r->status == 200
		&& (location = apr_table_get(r->headers_out, "Location")) == NULL)
	{
		/* Pass */
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
					  "mod_fcgid: user %s authentication pass", r->user);

		/* Modify headers: An Authorizer application's 200 response may include headers
		   whose names are prefixed with Variable-.  */
		apr_table_do(mod_fcgid_modify_auth_header, r->subprocess_env,
					 r->err_headers_out, NULL);

		return OK;
	} else {
		/* Print error info first */
		if (res != OK)
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s authentication failed, respond %d, URI %s",
						  r->user, res, r->uri);
		else if (r->status != 200)
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s authentication failed, status %d, URI %s",
						  r->user, r->status, r->uri);
		else
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s authentication failed, redirected is not allowed",
						  r->user);

		/* Handle error */
		if (!authoritative)
			return DECLINED;
		else {
			ap_note_basic_auth_failure(r);
			return (res == OK) ? HTTP_UNAUTHORIZED : res;
		}
	}
}

static int mod_fcgid_authorizer(request_rec * r)
{
	int res = 0;
	const char *location = NULL;
	apr_table_t *saved_subprocess_env = NULL;
	fcgid_wrapper_conf *wrapper_conf;
	auth_conf *authorizer_info;
	int authoritative;

	authorizer_info = get_authorizer_info(r, &authoritative);

	/* Is authenticator enable? */
	if (authorizer_info == NULL)
		return DECLINED;

	/* Check wrapper */
	wrapper_conf = get_wrapper_info(authorizer_info->path, r);

	/* Save old process environment */
	saved_subprocess_env = apr_table_copy(r->pool, r->subprocess_env);

	/* Add some environment variables */
	ap_add_common_vars(r);
	ap_add_cgi_vars(r);
	fcgid_add_cgi_vars(r);
	apr_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", "AUTHORIZER");

	/* Remove some environment variables */
	/* The Web server does not send CONTENT_LENGTH, PATH_INFO, PATH_TRANSLATED, and SCRIPT_NAME headers */
	apr_table_unset(r->subprocess_env, "CONTENT_LENGTH");
	apr_table_unset(r->subprocess_env, "PATH_INFO");
	apr_table_unset(r->subprocess_env, "PATH_TRANSLATED");
	apr_table_unset(r->subprocess_env, "SCRIPT_NAME");

	/* Handle the request */
	res =
		bridge_request(r, FCGI_AUTHORIZER, authorizer_info->path,
					   wrapper_conf);

	/* Restore r->subprocess_env */
	r->subprocess_env = saved_subprocess_env;

	if (res == OK && r->status == 200
		&& (location = apr_table_get(r->headers_out, "Location")) == NULL)
	{
		/* Pass */
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
					  "mod_fcgid: access granted");

		/* Modify headers: An Authorizer application's 200 response may include headers
		   whose names are prefixed with Variable-.  */
		apr_table_do(mod_fcgid_modify_auth_header, r->subprocess_env,
					 r->err_headers_out, NULL);

		return OK;
	} else {
		/* Print error info first */
		if (res != OK)
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s access check failed, respond %d, URI %s",
						  r->user, res, r->uri);
		else if (r->status != 200)
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s access check failed, status %d, URI %s",
						  r->user, r->status, r->uri);
		else
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s access check failed, redirected is not allowed",
						  r->user);

		/* Handle error */
		if (!authoritative)
			return DECLINED;
		else {
			ap_note_basic_auth_failure(r);
			return (res == OK) ? HTTP_UNAUTHORIZED : res;
		}
	}
}

static int mod_fcgid_check_access(request_rec * r)
{
	int res = 0;
	const char *location = NULL;
	apr_table_t *saved_subprocess_env = NULL;
	fcgid_wrapper_conf *wrapper_conf;
	auth_conf *access_info;
	int authoritative;

	access_info = get_access_info(r, &authoritative);

	/* Is access check enable? */
	if (access_info == NULL)
		return DECLINED;

	/* Check wrapper */
	wrapper_conf = get_wrapper_info(access_info->path, r);

	/* Save old process environment */
	saved_subprocess_env = apr_table_copy(r->pool, r->subprocess_env);

	/* Add some environment variables */
	ap_add_common_vars(r);
	ap_add_cgi_vars(r);
	fcgid_add_cgi_vars(r);
	apr_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE",
				   "ACCESS_CHECKER");

	/* Remove some environment variables */
	/* The Web server does not send CONTENT_LENGTH, PATH_INFO, PATH_TRANSLATED, and SCRIPT_NAME headers */
	apr_table_unset(r->subprocess_env, "CONTENT_LENGTH");
	apr_table_unset(r->subprocess_env, "PATH_INFO");
	apr_table_unset(r->subprocess_env, "PATH_TRANSLATED");
	apr_table_unset(r->subprocess_env, "SCRIPT_NAME");

	/* Handle the request */
	res =
		bridge_request(r, FCGI_AUTHORIZER, access_info->path,
					   wrapper_conf);

	/* Restore r->subprocess_env */
	r->subprocess_env = saved_subprocess_env;

	if (res == OK && r->status == 200
		&& (location = apr_table_get(r->headers_out, "Location")) == NULL)
	{
		/* Pass */
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
					  "mod_fcgid: access check pass");

		/* Modify headers: An Authorizer application's 200 response may include headers
		   whose names are prefixed with Variable-.  */
		apr_table_do(mod_fcgid_modify_auth_header, r->subprocess_env,
					 r->err_headers_out, NULL);

		return OK;
	} else {
		/* Print error info first */
		if (res != OK)
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s access check failed, respond %d, URI %s",
						  r->user, res, r->uri);
		else if (r->status != 200)
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s access check failed, status %d, URI %s",
						  r->user, r->status, r->uri);
		else
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
						  "mod_fcgid: user %s access check failed, redirected is not allowed",
						  r->user);

		/* Handle error */
		if (!authoritative)
			return DECLINED;
		else {
			ap_note_basic_auth_failure(r);
			return (res == OK) ? HTTP_UNAUTHORIZED : res;
		}
	}
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

	g_php_fix_pathinfo_enable = get_php_fix_pathinfo_enable(main_server);

	/* Initialize process manager only once */
	apr_pool_userdata_get(&dummy, userdata_key,
						  main_server->process->pool);
	if (!dummy) {
		procnew =
			apr_pcalloc(main_server->process->pool, sizeof(*procnew));
		procnew->pid = -1;
		procnew->err = procnew->in = procnew->out = NULL;
		apr_pool_userdata_set((const void *) procnew, userdata_key,
							  apr_pool_cleanup_null,
							  main_server->process->pool);
		return OK;
	} else {
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
	AP_INIT_TAKE1("SharememPath", set_shmpath, NULL, RSRC_CONF,
				  "fastcgi share memory file path"),
	AP_INIT_TAKE1("SpawnScoreUpLimit", set_spawnscore_uplimit, NULL,
				  RSRC_CONF,
				  "Spawn score up limit"),
	AP_INIT_TAKE1("SpawnScore", set_spawn_score, NULL, RSRC_CONF,
				  "Score of spawn"),
	AP_INIT_TAKE1("TimeScore", set_time_score, NULL,
				  RSRC_CONF,
				  "Score of passage of time (in seconds)"),
	AP_INIT_TAKE1("TerminationScore", set_termination_score, NULL,
				  RSRC_CONF,
				  "Score of termination"),
	AP_INIT_TAKE1("MaxProcessCount", set_max_process, NULL, RSRC_CONF,
				  "Max total process count"),
	AP_INIT_TAKE1("DefaultMaxClassProcessCount",
				  set_max_class_process,
				  NULL, RSRC_CONF,
				  "Max process count of one class of fastcgi application"),
	AP_INIT_TAKE1("DefaultMinClassProcessCount",
				  set_min_class_process,
				  NULL, RSRC_CONF,
				  "Min process count of one class of fastcgi application"),
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
	AP_INIT_TAKE1("PassHeader", add_pass_headers, NULL, RSRC_CONF,
				  "Header name which will be passed to FastCGI as environment variable."),
	AP_INIT_TAKE12("FCGIWrapper", set_wrapper_config, NULL,
				   RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
				   "The CGI wrapper setting"),
	AP_INIT_TAKE1("PHP_Fix_Pathinfo_Enable",
				  set_php_fix_pathinfo_enable,
				  NULL, RSRC_CONF,
				  "Set 1, if cgi.fix_pathinfo=1 in php.ini"),
	AP_INIT_TAKE1("MaxRequestsPerProcess", set_max_requests_per_process,
				  NULL, RSRC_CONF,
				  "Max requests handled by each fastcgi application"),
	AP_INIT_TAKE1("FastCgiAuthenticator", set_authenticator_info, NULL,
				  ACCESS_CONF | OR_FILEINFO,
				  "a absolute authenticator file path"),
	AP_INIT_FLAG("FastCgiAuthenticatorAuthoritative",
				 set_authenticator_authoritative, NULL,
				 ACCESS_CONF | OR_FILEINFO,
				 "Set to 'off' to allow authentication to be passed along to lower modules upon failure"),
	AP_INIT_TAKE1("FastCgiAuthenticator", set_authorizer_info, NULL,
				  ACCESS_CONF | OR_FILEINFO,
				  "a absolute authorizer file path"),
	AP_INIT_FLAG("FastCgiAuthenticatorAuthoritative",
				 set_authorizer_authoritative, NULL,
				 ACCESS_CONF | OR_FILEINFO,
				 "Set to 'off' to allow authorization to be passed along to lower modules upon failure"),
	AP_INIT_TAKE1("FastCgiAccessChecker", set_access_info, NULL,
				  ACCESS_CONF | OR_FILEINFO,
				  "a absolute access checker file path"),
	AP_INIT_FLAG("FastCgiAccessCheckerAuthoritative",
				 set_access_authoritative, NULL, ACCESS_CONF | OR_FILEINFO,
				 "Set to 'off' to allow access control to be passed along to lower modules upon failure"),
	{NULL}
};

static void register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(fcgid_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(fcgid_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_check_user_id(mod_fcgid_authenticator, NULL, NULL,
						  APR_HOOK_MIDDLE);
	ap_hook_auth_checker(mod_fcgid_authorizer, NULL, NULL,
						 APR_HOOK_MIDDLE);
	ap_hook_access_checker(mod_fcgid_check_access, NULL, NULL,
						   APR_HOOK_MIDDLE);

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
