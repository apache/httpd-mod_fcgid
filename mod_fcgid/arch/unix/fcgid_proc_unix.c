#include <sys/un.h>
#include "httpd.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "apr_network_io.h"
#include "util_script.h"
#include "unixd.h"
#include "mod_core.h"
#include "mod_cgi.h"
#include "apr_tables.h"
#include "fcgid_proc.h"
#include "fcgid_proctbl.h"
#include "fcgid_protocol.h"
#include "fcgid_conf.h"
#include "fcgid_pm.h"
#define DEFAULT_FCGID_LISTENBACKLOG 5
typedef struct {
	int handle_socket;
} fcgid_namedpipe_handle;

static int g_process_counter = 0;
static apr_pool_t *g_inode_cginame_map = NULL;
static const char *g_socket_dir = NULL;

static apr_status_t socket_file_cleanup(void *theprocnode)
{
	fcgid_procnode *procnode = (fcgid_procnode *) theprocnode;

	unlink(procnode->socket_path);
	return APR_SUCCESS;
}

apr_status_t
proc_spawn_process(fcgid_proc_info * procinfo, fcgid_procnode * procnode)
{
	server_rec *main_server = procinfo->main_server;
	apr_status_t rv;
	apr_file_t *file;
	int omask, retcode, unix_socket, i;
	char **proc_environ;
	struct sockaddr_un unix_addr;
	fcgid_wrapper_conf *wrapper_conf;
	apr_procattr_t *procattr = NULL;
	char key_name[_POSIX_PATH_MAX];
	fcgid_ipc ipc_handle;
	char *dummy;
	char *argv[2];

	/* Initialize the variables */
	if (!g_inode_cginame_map) {
		apr_pool_create(&g_inode_cginame_map,
						procinfo->main_server->process->pconf);
	}

	if (!g_socket_dir)
		g_socket_dir = get_socketpath(procinfo->main_server);
	if (!g_inode_cginame_map || !g_socket_dir) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 procinfo->main_server,
					 "mod_fcgid: can't cgi name map table");
		return APR_ENOMEM;
	}

	/* 
	   Create UNIX domain socket before spawn 
	 */

	/* Generate a UNIX domain socket file path */
	/* XXX It's nothing I can do if strlen(g_socket_dir) too long... */
	memset(&unix_addr, 0, sizeof(unix_addr));
	unix_addr.sun_family = AF_UNIX;
	apr_snprintf(unix_addr.sun_path, sizeof(unix_addr.sun_path) - 1,
				 "%s/%d.%d", g_socket_dir, getpid(), g_process_counter++);
	strncpy(procnode->socket_path, unix_addr.sun_path,
			sizeof(procnode->socket_path) - 1);

	/* Unlink the file just in case */
	unlink(unix_addr.sun_path);

	/* Create the socket */
	if ((unix_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: couldn't create unix domain socket");
		return errno;
	}

	/* Unlink it when process exit */
	apr_pool_cleanup_register(procnode->proc_pool,
							  procnode, socket_file_cleanup,
							  apr_pool_cleanup_null);

	/* Bind the socket */
	omask = umask(0077);
	retcode = bind(unix_socket, (struct sockaddr *) &unix_addr,
				   sizeof(unix_addr));
	umask(omask);
	if (retcode < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: couldn't bind unix domain socket %s",
					 unix_addr.sun_path);
		close(unix_socket);
		return errno;
	}

	/* Listen the socket */
	if (listen(unix_socket, DEFAULT_FCGID_LISTENBACKLOG) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: couldn't listen on unix domain socket");
		close(unix_socket);
		return errno;
	}

	/* Correct the file owner */
	if (!geteuid()) {
		if (chown(unix_addr.sun_path, unixd_config.user_id, -1) < 0) {
			ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
						 "mod_fcgid: couldn't change owner of unix domain socket %s",
						 unix_addr.sun_path);
			close(unix_socket);
			return errno;
		}
	}

	/* Build environment variables */
	proc_environ = ap_create_environment(procnode->proc_pool,
										 procinfo->proc_environ);
	if (!proc_environ) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
					 procinfo->main_server,
					 "mod_fcgid: can't build environment variables");
		close(unix_socket);
		return APR_ENOMEM;
	}

	/* Prepare the fork */
	if (!
		(procnode->proc_id =
		 apr_pcalloc(procnode->proc_pool, sizeof(apr_proc_t)))
|| (rv =
	apr_procattr_create(&procattr, procnode->proc_pool)) != APR_SUCCESS
|| (rv =
	apr_procattr_child_err_set(procattr,
							   procinfo->main_server->error_log,
							   NULL)) != APR_SUCCESS
|| (rv =
	apr_procattr_child_out_set(procattr,
							   procinfo->main_server->error_log,
							   NULL)) != APR_SUCCESS
|| (rv =
	apr_procattr_dir_set(procattr,
						 ap_make_dirstr_parent(procnode->proc_pool,
											   procinfo->cgipath))) !=
APR_SUCCESS
|| (rv =
	apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) != APR_SUCCESS
|| (rv =
	apr_os_file_put(&file, &unix_socket, 0,
					procnode->proc_pool)) != APR_SUCCESS
|| (rv = apr_procattr_child_in_set(procattr, file, NULL)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
					 "mod_fcgid: couldn't set child process attributes: %s",
					 unix_addr.sun_path);
		close(unix_socket);
		return rv;
	}

	/* fork and exec now */
	wrapper_conf =
		get_wrapper_info(procinfo->cgipath, procinfo->main_server);
	if (wrapper_conf) {
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, procinfo->main_server,
					 "mod_fcgid: call %s with wrapper %s",
					 procinfo->cgipath, wrapper_conf->wrapper_path);

		argv[0] = wrapper_conf->wrapper_path;
		argv[1] = NULL;
		if ((rv =
			 apr_proc_create(procnode->proc_id, wrapper_conf->wrapper_path,
							 (const char *const *) argv,
							 (const char *const *) proc_environ, procattr,
							 procnode->proc_pool)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
						 "mod_fcgid: can't create wrapper process for %s",
						 procinfo->cgipath);
			close(unix_socket);
			return rv;
		}
	} else {
		argv[0] = procinfo->cgipath;
		argv[1] = NULL;
		if ((rv =
			 apr_proc_create(procnode->proc_id, procinfo->cgipath,
							 (const char *const *) argv,
							 (const char *const *) proc_environ, procattr,
							 procnode->proc_pool)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
						 "mod_fcgid: can't create process");
			close(unix_socket);
			return rv;
		}
	}

	/* Set the (deviceid, inode) -> fastcgi path map for log */
	apr_snprintf(key_name, _POSIX_PATH_MAX, "%lX%lX",
				 procnode->inode, procnode->deviceid);
	dummy = NULL;
	apr_pool_userdata_get((void **) &dummy, key_name, g_inode_cginame_map);
	if (!dummy) {
		/* Insert a new item if key not found */
		char *put_key = apr_psprintf(g_inode_cginame_map, "%lX%lX",
									 procnode->inode, procnode->deviceid);
		char *fcgipath = apr_psprintf(g_inode_cginame_map, "%s",
									  procinfo->cgipath);

		if (put_key && fcgipath)
			apr_pool_userdata_set(fcgipath, put_key, NULL,
								  g_inode_cginame_map);
	}

	/* Close socket before try to connect to it */
	close(unix_socket);

	return APR_SUCCESS;
}

apr_status_t
proc_kill_gracefully(fcgid_procnode * procnode, server_rec * main_server)
{
	return apr_proc_kill(procnode->proc_id, SIGTERM);
}

apr_status_t
proc_wait_process(server_rec * main_server, fcgid_procnode * procnode)
{
	apr_status_t rv;
	int exitcode;
	apr_exit_why_e exitwhy;

	if ((rv = apr_proc_wait(procnode->proc_id, &exitcode, &exitwhy,
							APR_NOWAIT)) != APR_CHILD_NOTDONE) {
		/* Log why and how it die */
		proc_print_exit_info(procnode, exitcode, exitwhy, main_server);

		/* Register the death */
		register_termination(main_server, procnode);

		/* Destroy pool */
		apr_pool_destroy(procnode->proc_pool);
		procnode->proc_pool = NULL;
	}

	return rv;
}

static apr_status_t ipc_handle_cleanup(void *thesocket)
{
	fcgid_namedpipe_handle *handle_info =
		(fcgid_namedpipe_handle *) thesocket;
	if (handle_info->handle_socket != -1) {
		close(handle_info->handle_socket);
		handle_info->handle_socket = -1;
	}
	return APR_SUCCESS;
}

apr_status_t
proc_connect_ipc(server_rec * main_server,
				 fcgid_procnode * procnode, fcgid_ipc * ipc_handle)
{
	fcgid_namedpipe_handle *handle_info;
	struct sockaddr_un unix_addr;

	/* Alloc memory for unix domain socket */
	ipc_handle->ipc_handle_info
		= (fcgid_namedpipe_handle *) apr_pcalloc(ipc_handle->request_pool,
												 sizeof
												 (fcgid_namedpipe_handle));
	if (!ipc_handle->ipc_handle_info)
		return APR_ENOMEM;
	handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	handle_info->handle_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	apr_pool_cleanup_register(ipc_handle->request_pool,
							  handle_info, ipc_handle_cleanup,
							  apr_pool_cleanup_null);

	/* Connect to fastcgi server */
	memset(&unix_addr, 0, sizeof(unix_addr));
	unix_addr.sun_family = AF_UNIX;
	strncpy(unix_addr.sun_path, procnode->socket_path,
			sizeof(unix_addr.sun_path) - 1);

	/* I am the only one who connecting the server
	   So I don't have to worry about ECONNREFUSED(listen queue overflow) problem,
	   and I will never retry on error */
	if (connect(handle_info->handle_socket, (struct sockaddr *) &unix_addr,
				sizeof(unix_addr)) < 0) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, apr_get_os_error(),
					 main_server,
					 "mod_fcgid: can't connect unix domain socket: %s",
					 procnode->socket_path);
		apr_pool_cleanup_run(ipc_handle->request_pool,
							 ipc_handle->ipc_handle_info,
							 ipc_handle_cleanup);
		return APR_ECONNREFUSED;
	}

	return APR_SUCCESS;
}

static apr_status_t
read_fcgi_header(server_rec * main_server,
				 fcgid_ipc * ipc_handle, FCGI_Header * header)
{
	fcgid_namedpipe_handle *handle_info =
		(fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	fd_set rset;
	struct timeval tv;
	apr_size_t has_read = 0;
	int unix_socket = handle_info->handle_socket;
	char *buf = (char *) header;

	FD_ZERO(&rset);

	do {
		/* The first read() will not block, 
		   a select() outside has check it */
		int readcount = read(unix_socket, buf + has_read,
							 sizeof(*header) - has_read);

		if (readcount <= 0)
			return apr_get_os_error();

		has_read += readcount;

		if (has_read < sizeof(*header)) {
			FD_SET(unix_socket, &rset);
			tv.tv_usec = 0;
			tv.tv_sec = ipc_handle->communation_timeout;
			if (select(unix_socket + 1, &rset, NULL, NULL, &tv) <= 0)
				return apr_get_os_error();
		}
	}
	while (has_read < sizeof(*header));

	return APR_SUCCESS;
}

static apr_status_t
handle_fcgi_body(server_rec * main_server,
				 fcgid_ipc * ipc_handle,
				 FCGI_Header * header,
				 apr_bucket_brigade * brigade_recv,
				 apr_bucket_alloc_t * alloc)
{
	apr_status_t rv;
	char *readbuf;
	fcgid_namedpipe_handle *handle_info =
		(fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	fd_set rset;
	struct timeval tv;
	apr_size_t has_read = 0;
	int unix_socket = handle_info->handle_socket;

	FD_ZERO(&rset);

	/* Recognize these types only */
	if (header->type == FCGI_STDERR
		|| header->type == FCGI_STDOUT || header->type == FCGI_END_REQUEST)
	{
		int readsize = header->contentLengthB1;

		readsize <<= 8;
		readsize += header->contentLengthB0;
		readsize += header->paddingLength;
		readbuf = apr_bucket_alloc(readsize + 1 /* ending '\0' */ , alloc);
		if (!readbuf)
			return APR_ENOMEM;

		/* Read the respond from fastcgi server */
		has_read = 0;
		while (has_read < readsize) {
			int readcount;

			FD_SET(unix_socket, &rset);
			tv.tv_usec = 0;
			tv.tv_sec = ipc_handle->communation_timeout;
			if (select(unix_socket + 1, &rset, NULL, NULL, &tv) <= 0) {
				apr_bucket_free(readbuf);
				return apr_get_os_error();
			}

			readcount = read(unix_socket, readbuf + has_read,
							 readsize - has_read);

			if (readcount <= 0) {
				apr_bucket_free(readbuf);
				return apr_get_os_error();
			}

			has_read += readcount;
		}
		readbuf[readsize] = '\0';

		/* Now dispatch the respond */
		if (header->type == FCGI_STDERR) {
			/* Write to log, skip the empty contain, and empty line */
			int content_len = header->contentLengthB1;

			content_len <<= 8;
			content_len += header->contentLengthB0;
			if (!((content_len == 1 && readbuf[0] == '\r')
				  || (content_len == 1 && readbuf[0] == '\n')
				  || (content_len == 2 && readbuf[0] == '\r'
					  && readbuf[1] == '\n') || content_len == 0)) {
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
							 main_server, "mod_fcgid: cgi stderr log: %s",
							 readbuf);
			}
			apr_bucket_free(readbuf);
			return APR_SUCCESS;
		} else if (header->type == FCGI_END_REQUEST) {
			/* End of the respond */
			apr_bucket_free(readbuf);
			return APR_SUCCESS;
		} else if (header->type == FCGI_STDOUT) {
			apr_bucket *bucket_stdout;

			if ((readsize - header->paddingLength) == 0) {
				apr_bucket_free(readbuf);
				return APR_SUCCESS;
			}

			/* Append the respond to brigade_stdout */
			bucket_stdout = apr_bucket_heap_create(readbuf,
												   readsize -
												   header->
												   paddingLength,
												   apr_bucket_free, alloc);

			if (!bucket_stdout) {
				apr_bucket_free(readbuf);
				return APR_ENOMEM;
			}

			/* Append it now */
			APR_BRIGADE_INSERT_TAIL(brigade_recv, bucket_stdout);
			return APR_SUCCESS;
		}
	}

	/* I have no idea about the type of the header */
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
				 main_server, "mod_fcgid: invalid respond type: %d",
				 header->type);
	return APR_ENOTIMPL;
}

apr_status_t
proc_bridge_request(server_rec * main_server,
					fcgid_ipc * ipc_handle,
					apr_bucket_brigade * birgade_send,
					apr_bucket_brigade * brigade_recv,
					apr_bucket_alloc_t * alloc)
{
	fcgid_namedpipe_handle *handle_info;
	apr_bucket *bucket_request;
	apr_status_t rv;
	FCGI_Header fcgi_header;
	apr_size_t has_write;
	fd_set rset, wset;
	struct timeval tv;
	int retcode, unix_socket, all_bucket_sent;

	handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	unix_socket = handle_info->handle_socket;

	/* 
	   Try read data to brigade_recv and write data from birgade_send
	   Loop until get read/write error or get "end request" struct 
	   from fastcgi application server
	 */
	APR_BRIGADE_FOREACH(bucket_request, birgade_send) {
		const char *write_buf;
		apr_size_t write_buf_len;
		apr_size_t has_write;

		if (APR_BUCKET_IS_EOS(bucket_request))
			break;

		if (APR_BUCKET_IS_FLUSH(bucket_request))
			continue;

		if ((rv =
			 apr_bucket_read(bucket_request, &write_buf, &write_buf_len,
							 APR_BLOCK_READ)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, rv, main_server,
						 "mod_fcgid: can't read request from bucket");
			return rv;
		}

		has_write = 0;
		while (has_write < write_buf_len) {
			/* Is it readable or writeable? */
			/* APR has poor support on UNIX domain socket, I have to
			   use select() directly :-( */
			FD_SET(unix_socket, &rset);
			FD_SET(unix_socket, &wset);
			tv.tv_usec = 0;
			tv.tv_sec = ipc_handle->communation_timeout;
			retcode = select(unix_socket + 1, &rset, &wset, NULL, &tv);
			if (retcode <= 0 && (errno == EINTR || errno == EAGAIN))
				continue;
			else if (retcode <= 0) {
				return APR_ETIMEDOUT;
			}

			if (FD_ISSET(unix_socket, &rset)) {
				if (read_fcgi_header(main_server,
									 ipc_handle,
									 &fcgi_header) != APR_SUCCESS
					|| handle_fcgi_body(main_server, ipc_handle,
										&fcgi_header, brigade_recv,
										alloc) != APR_SUCCESS) {
					ap_log_error(APLOG_MARK, APLOG_INFO,
								 apr_get_os_error(), main_server,
								 "mod_fcgid: read from fastcgi server error");
					return APR_ESPIPE;
				}

				/* Is it "end request" respond? */
				if (fcgi_header.type == FCGI_END_REQUEST)
					return APR_SUCCESS;
			}

			if (FD_ISSET(unix_socket, &wset)) {
				if ((retcode = write(unix_socket, write_buf + has_write,
									 write_buf_len - has_write)) < 0) {
					ap_log_error(APLOG_MARK, APLOG_WARNING,
								 apr_get_os_error(), main_server,
								 "mod_fcgid: write error on unix socket");
					return APR_ESPIPE;
				}
				has_write += retcode;
			}
		}
	}

	/* Now I have send all to fastcgi server, and not get the "end request"
	   respond yet, so I keep reading until I get one */
	while (1) {
		FD_SET(unix_socket, &rset);
		tv.tv_usec = 0;
		tv.tv_sec = ipc_handle->communation_timeout;
		retcode = select(unix_socket + 1, &rset, NULL, NULL, &tv);
		if (retcode <= 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		else if (retcode <= 0) {
			return APR_ETIMEDOUT;
		} else if (retcode == 1) {
			if (read_fcgi_header(main_server, ipc_handle, &fcgi_header) !=
				APR_SUCCESS
				|| handle_fcgi_body(main_server, ipc_handle, &fcgi_header,
									brigade_recv, alloc) != APR_SUCCESS) {
				return APR_ESPIPE;
			}

			if (fcgi_header.type == FCGI_END_REQUEST)
				return APR_SUCCESS;
		}
	}
}

apr_status_t proc_close_ipc(fcgid_ipc * ipc_handle)
{
	return apr_pool_cleanup_run(ipc_handle->request_pool,
								ipc_handle->ipc_handle_info,
								ipc_handle_cleanup);
}

void
proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
					 apr_exit_why_e exitwhy, server_rec * main_server)
{
	char *cgipath = NULL;
	char *diewhy = NULL;
	char signal_info[HUGE_STRING_LEN];
	char key_name[_POSIX_PATH_MAX];
	int signum = exitcode;

	memset(signal_info, 0, HUGE_STRING_LEN);

	/* Get the file name infomation base on inode and deviceid */
	apr_snprintf(key_name, _POSIX_PATH_MAX, "%lX%lX",
				 procnode->inode, procnode->deviceid);
	apr_pool_userdata_get((void **) &cgipath, key_name,
						  g_inode_cginame_map);

	/* Reasons to exit */
	switch (procnode->diewhy) {
	case FCGID_DIE_KILLSELF:
		diewhy = "normal exit";
		break;
	case FCGID_DIE_IDLE_TIMEOUT:
		diewhy = "idle timeout";
		break;
	case FCGID_DIE_LIFETIME_EXPIRED:
		diewhy = "lifetime expired";
		break;
	case FCGID_DIE_BUSY_TIMEOUT:
		diewhy = "busy timeout";
		break;
	case FCGID_DIE_CONNECT_ERROR:
		diewhy = "connect error";
		break;
	case FCGID_DIE_COMM_ERROR:
		diewhy = "communication error";
		break;
	case FCGID_DIE_SHUTDOWN:
		diewhy = "shutting down";
		break;
	default:
		diewhy = "unknow";
	}

	/* Get signal info */
	if (APR_PROC_CHECK_SIGNALED(exitwhy)) {
		switch (signum) {
		case SIGTERM:
		case SIGHUP:
		case AP_SIG_GRACEFUL:
		case SIGKILL:
			apr_snprintf(signal_info, HUGE_STRING_LEN - 1,
						 "get stop signal %d", signum);
			break;

		default:
			if (APR_PROC_CHECK_CORE_DUMP(exitwhy)) {
				apr_snprintf(signal_info, HUGE_STRING_LEN - 1,
							 "get signal %d, possible coredump generated",
							 signum);
			} else {
				apr_snprintf(signal_info, HUGE_STRING_LEN - 1,
							 "get unexpected signal %d", signum);
			}
		}
	} else if (APR_PROC_CHECK_EXIT(exitwhy)) {
		apr_snprintf(signal_info, HUGE_STRING_LEN - 1,
					 "terminated by calling exit(), return code: %d",
					 exitcode);
		if (procnode->diewhy == FCGID_DIE_CONNECT_ERROR)
			diewhy = "server exited";
	}

	/* Print log now */
	if (cgipath)
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
					 "mod_fcgid: process %s(%d) exit(%s), %s",
					 cgipath, procnode->proc_id->pid, diewhy, signal_info);
	else
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
					 "mod_fcgid: can't get cgi name while exiting, exitcode: %d",
					 exitcode);
}
