#include "httpd.h"
#include "ap_mpm.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "util_script.h"
#include "fcgid_bridge.h"
#include "fcgid_pm.h"
#include "fcgid_proctbl.h"
#include "fcgid_proc.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#include "fcgid_protocol.h"
#define FCGID_APPLY_TRY_COUNT 2
#define FCGID_REQUEST_COUNT 2

static int g_variables_inited = 0;
static int g_busy_timeout;
static int g_connect_timeout;
static int g_comm_timeout;

static fcgid_procnode *apply_free_procnode(server_rec * main_server,
										   apr_ino_t inode,
										   apr_dev_t deviceid)
{
	/* Scan idle list, find a node match inode and deviceid 
	   If there is no one there, return NULL */
	fcgid_procnode *previous_node, *current_node, *next_node;
	fcgid_procnode *busy_list_header, *proc_table;

	proc_table = proctable_get_table_array();
	previous_node = proctable_get_idle_list();
	busy_list_header = proctable_get_busy_list();

	safe_lock(main_server);
	current_node = &proc_table[previous_node->next_index];
	while (current_node != proc_table) {
		next_node = &proc_table[current_node->next_index];

		if (current_node->inode == inode
			&& current_node->deviceid == deviceid) {
			/* Unlink from idle list */
			previous_node->next_index = current_node->next_index;

			/* Link to busy list */
			current_node->next_index = busy_list_header->next_index;
			busy_list_header->next_index = current_node - proc_table;

			safe_unlock(main_server);
			return current_node;
		} else
			previous_node = current_node;

		current_node = next_node;
	}
	safe_unlock(main_server);

	/* Found nothing */
	return NULL;
}

static void
return_procnode(server_rec * main_server,
				fcgid_procnode * procnode, int communicate_error)
{
	fcgid_procnode *previous_node, *current_node, *next_node;
	fcgid_procnode *proc_table = proctable_get_table_array();
	fcgid_procnode *error_list_header = proctable_get_error_list();
	fcgid_procnode *idle_list_header = proctable_get_idle_list();
	fcgid_procnode *busy_list_header = proctable_get_busy_list();

	safe_lock(main_server);

	/* Unlink the node from busy list first */
	previous_node = busy_list_header;
	current_node = &proc_table[previous_node->next_index];
	while (current_node != proc_table) {
		next_node = &proc_table[current_node->next_index];
		if (current_node == procnode) {
			/* Unlink from busy list */
			previous_node->next_index = current_node->next_index;
			break;
		} else
			previous_node = current_node;
		current_node = next_node;
	}

	/* Return to error list or idle list */
	if (communicate_error) {
		/* Link to error list */
		procnode->next_index = error_list_header->next_index;
		error_list_header->next_index = procnode - proc_table;
	} else {
		/* Link to idle list */
		procnode->next_index = idle_list_header->next_index;
		idle_list_header->next_index = procnode - proc_table;
	}

	safe_unlock(main_server);
}

static int
bridge_request_once(request_rec * r, const char *argv0,
					apr_bucket_brigade * output_brigade)
{
	apr_pool_t *request_pool = r->main ? r->main->pool : r->pool;
	apr_time_t begin_request_time;
	fcgid_command fcgi_request;
	fcgid_procnode *procnode;
	fcgid_ipc ipc_handle;
	int i, communicate_error;
	apr_status_t rv;
	apr_bucket_brigade *brigade_stdout;

	if (!g_variables_inited) {
		g_connect_timeout = get_ipc_connect_timeout(r->server);
		g_comm_timeout = get_ipc_comm_timeout(r->server);
		g_busy_timeout = get_busy_timeout(r->server);
		g_variables_inited = 1;
	}

	/* Apply a free process slot, send a spawn request if I can't get one */
	for (i = 0; i < FCGID_APPLY_TRY_COUNT; i++) {
		int mpm_state = 0;

		procnode = apply_free_procnode(r->server,
									   r->finfo.inode, r->finfo.device);
		if (procnode)
			break;

		/* Send a spawn request and wait a second */
		strncpy(fcgi_request.cgipath, argv0, _POSIX_PATH_MAX);
		fcgi_request.cgipath[_POSIX_PATH_MAX - 1] = '\0';
		fcgi_request.deviceid = r->finfo.device;
		fcgi_request.inode = r->finfo.inode;
		procmgr_post_spawn_cmd(&fcgi_request);
		apr_sleep(apr_time_from_sec(1));

		/* Is it stopping? */
		if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
			&& mpm_state == AP_MPMQ_STOPPING)
			break;
	}

	if (!procnode) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
					 "mod_fcgid: can't apply process slot for %s", argv0);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Now I got a process slot
	   I will return this slot to idle(or error) list except:
	   1) I take too much time on this request( greater than get_busy_timeout() ),
	   so the process manager may have put this slot from busy list to error
	   list, and the contain of this slot may have been modified
	   In this case I will do nothing and return, let the process manager 
	   do the job
	 */
	begin_request_time = procnode->last_active_time = apr_time_now();

	/* XXX HACK: I have to read all the respond into memory before sending it 
	   to http client, this prevents slow http clients from keeping the server 
	   in processing too long. 
	   Buf sometimes it's not acceptable(think about downloading a larage attachment)
	   file_bucket is a better choice in this case...
	   To do, or not to do, that is the question ^_^
	 */
	brigade_stdout =
		apr_brigade_create(request_pool, r->connection->bucket_alloc);
	if (!brigade_stdout) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 r->server,
					 "mod_fcgid: can't alloc memory for stdout brigade");
		return apr_get_os_error();
	}

	/* Connect to the fastcgi server and bridge the reqeust */
	communicate_error = 0;
	ipc_handle.request_pool = request_pool;
	ipc_handle.connect_timeout = g_connect_timeout;
	ipc_handle.communation_timeout = g_comm_timeout;
	if (proc_connect_ipc(r->server, procnode, &ipc_handle) != APR_SUCCESS) {
		procnode->diewhy = FCGID_DIE_CONNECT_ERROR;
		communicate_error = 1;
	} else
		if ((rv =
			 proc_bridge_request(r->server, &ipc_handle, output_brigade,
								 brigade_stdout,
								 r->connection->bucket_alloc)) !=
			APR_SUCCESS) {
		procnode->diewhy = FCGID_DIE_COMM_ERROR;
		communicate_error = 1;
	}

	/* Communication is over */
	proc_close_ipc(&ipc_handle);

	/* Is it handle timeout? */
	if (apr_time_sec(apr_time_now()) - apr_time_sec(begin_request_time) >
		g_busy_timeout) {
		/* I have to return and do nothing to the process slot */
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 r->server,
					 "mod_fcgid: process busy timeout, take %d seconds for this request",
					 apr_time_sec(apr_time_now()) -
					 apr_time_sec(procnode->last_active_time));

		apr_brigade_destroy(brigade_stdout);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Now I will release the process slot as soon as I can */
	return_procnode(r->server, procnode, communicate_error);

	/* Now pass the output brigade to output filter */
	if (!communicate_error) {
		char sbuf[MAX_STRING_LEN];
		const char *location;

		/* Check the script header first */
		if (ap_scan_script_header_err_brigade(r, brigade_stdout, sbuf) !=
			OK) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
						 "mod_fcgid: invalid script header");
			apr_brigade_destroy(brigade_stdout);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* Check redirect */
		location = apr_table_get(r->headers_out, "Location");

		if (location && location[0] == '/' && r->status == 200) {
			/* This redirect needs to be a GET no matter what the original 
			 * method was. 
			 */
			r->method = apr_pstrdup(r->pool, "GET");
			r->method_number = M_GET;

			/* We already read the message body (if any), so don't allow 
			 * the redirected request to think it has one. We can ignore 
			 * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR. 
			 */
			apr_table_unset(r->headers_in, "Content-Length");

			apr_brigade_destroy(brigade_stdout);
			ap_internal_redirect_handler(location, r);
			return HTTP_OK;
		} else if (location && r->status == 200) {
			/* XX Note that if a script wants to produce its own Redirect 
			 * body, it now has to explicitly *say* "Status: 302" 
			 */
			apr_brigade_destroy(brigade_stdout);
			return HTTP_MOVED_TEMPORARILY;
		}

		/* Now pass to output filter */
		if ((rv =
			 ap_pass_brigade(r->output_filters,
							 brigade_stdout)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
						 r->server,
						 "mod_fcgid: can't pass the respond to output filter");
		}
	}

	/* Try spawn a new process to replace the error one */
	if (communicate_error) {
		strncpy(fcgi_request.cgipath, argv0, _POSIX_PATH_MAX);
		fcgi_request.cgipath[_POSIX_PATH_MAX - 1] = '\0';
		fcgi_request.deviceid = r->finfo.device;
		fcgi_request.inode = r->finfo.inode;
		procmgr_post_spawn_cmd(&fcgi_request);
	}

	apr_brigade_destroy(brigade_stdout);
	return communicate_error ? HTTP_INTERNAL_SERVER_ERROR : HTTP_OK;
}

int bridge_request(request_rec * r, const char *argv0)
{
	apr_pool_t *request_pool = r->main ? r->main->pool : r->pool;
	server_rec *main_server = r->server;
	apr_status_t rv;
	int i, retcode, seen_eos;
	FCGI_Header *stdin_request_header;
	apr_bucket_brigade *output_brigade;
	apr_bucket *bucket_input, *bucket_header, *bucket_eos;
	char **envp = ap_create_environment(request_pool,
										r->subprocess_env);

	/* Create brigade for the request to fastcgi server */
	output_brigade =
		apr_brigade_create(request_pool, r->connection->bucket_alloc);
	if (!output_brigade) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 main_server,
					 "mod_fcgid: can't alloc memory for output brigade");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Build the begin request and environ request, append them to output_brigade */
	if (!build_begin_block
		(r->server, r->connection->bucket_alloc, output_brigade)
		|| !build_env_block(r->server, envp, r->connection->bucket_alloc,
							output_brigade)) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
					 main_server,
					 "mod_fcgid: can't build begin or env request");
		apr_brigade_destroy(output_brigade);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Stdin header and body */
	/* XXX HACK: I have to read all the request into memory before sending it 
	   to fastcgi application server, this prevents slow clients from 
	   keeping the server in processing too long. 
	   Buf sometimes it's not acceptable(think about uploading a larage attachment)
	   file_bucket is a better choice in this case...
	   To do, or not to do, that is the question ^_^
	 */
	seen_eos = 0;
	do {
		apr_bucket_brigade *input_brigade =
			apr_brigade_create(request_pool,
							   r->connection->bucket_alloc);

		if (!input_brigade
			|| (rv = ap_get_brigade(r->input_filters, input_brigade,
									AP_MODE_READBYTES,
									APR_BLOCK_READ,
									HUGE_STRING_LEN)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_INFO, 0,
						 main_server,
						 "mod_fcgid: can't get data from http client");
			apr_brigade_destroy(output_brigade);
			if (input_brigade)
				apr_brigade_destroy(input_brigade);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		APR_BRIGADE_FOREACH(bucket_input, input_brigade) {
			const char *data;
			apr_size_t len;
			apr_bucket *bucket_stdin;

			if (APR_BUCKET_IS_EOS(bucket_input)) {
				seen_eos = 1;
				break;
			}

			if (APR_BUCKET_IS_FLUSH(bucket_input)
				|| APR_BUCKET_IS_METADATA(bucket_input))
				continue;

			if ((rv = apr_bucket_read(bucket_input, &data, &len,
									  APR_BLOCK_READ)) != APR_SUCCESS) {
				ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
							 main_server,
							 "mod_fcgid: can't read request from HTTP client");
				apr_brigade_destroy(input_brigade);
				apr_brigade_destroy(output_brigade);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/* Append a header, and the the bucket */
			stdin_request_header = apr_bucket_alloc(sizeof(FCGI_Header),
													r->connection->
													bucket_alloc);
			bucket_header =
				apr_bucket_heap_create((const char *) stdin_request_header,
									   sizeof(*stdin_request_header),
									   apr_bucket_free,
									   r->connection->bucket_alloc);
			apr_bucket_copy(bucket_input, &bucket_stdin);
			if (!stdin_request_header || !bucket_header || !bucket_stdin
				|| !init_header(FCGI_STDIN, 1, len, 0,
								stdin_request_header)) {
				ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
							 main_server,
							 "mod_fcgid: can't alloc memory for stdin request");
				apr_brigade_destroy(input_brigade);
				apr_brigade_destroy(output_brigade);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_header);
			APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_stdin);
		}

		apr_brigade_destroy(input_brigade);
	}
	while (!seen_eos);

	/* Append an empty body stdin header */
	stdin_request_header = apr_bucket_alloc(sizeof(FCGI_Header),
											r->connection->bucket_alloc);
	bucket_header =
		apr_bucket_heap_create((const char *) stdin_request_header,
							   sizeof(*stdin_request_header),
							   apr_bucket_free,
							   r->connection->bucket_alloc);
	if (!stdin_request_header || !bucket_header
		|| !init_header(FCGI_STDIN, 1, 0, 0, stdin_request_header)) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 main_server,
					 "mod_fcgid: can't alloc memory for stdin request");
		apr_brigade_destroy(output_brigade);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_header);

	/* The eos bucket now */
	bucket_eos = apr_bucket_eos_create(r->connection->bucket_alloc);
	if (!bucket_eos) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 main_server,
					 "mod_fcgid: can't alloc memory for eos bucket");
		apr_brigade_destroy(output_brigade);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_eos);

	/* Bridge the request */
	retcode = HTTP_INTERNAL_SERVER_ERROR;
	for (i = 0; i < FCGID_REQUEST_COUNT; i++) {
		int mpm_state;

		if ((retcode =
			 bridge_request_once(r, argv0, output_brigade)) == HTTP_OK)
			break;

		/* Is it stopping? */
		if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
			&& mpm_state == AP_MPMQ_STOPPING)
			break;
	}

	apr_brigade_destroy(output_brigade);
	return retcode;
}
