#include <sys/un.h>
#include <netinet/tcp.h>		/* For TCP_NODELAY */
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

	rv = apr_proc_wait(procnode->proc_id, &exitcode, &exitwhy, APR_NOWAIT);
	if (rv == APR_CHILD_DONE || rv == APR_EGENERAL) {
		/* Log why and how it die */
		proc_print_exit_info(procnode, exitcode, exitwhy, main_server);

		/* Register the death */
		register_termination(main_server, procnode);

		/* Destroy pool */
		apr_pool_destroy(procnode->proc_pool);
		procnode->proc_pool = NULL;

		return APR_CHILD_DONE;
	}

	return rv;
}

static apr_status_t ipc_handle_cleanup(void *thesocket)
{
	fcgid_namedpipe_handle *handle_info =
		(fcgid_namedpipe_handle *) thesocket;

	if (handle_info) {
		if (handle_info->handle_socket != -1) {
			close(handle_info->handle_socket);
		}
	}

	return APR_SUCCESS;
}

static apr_status_t set_socket_nonblock(int sd)
{
#ifndef BEOS
	int fd_flags;

	fd_flags = fcntl(sd, F_GETFL, 0);
#if defined(O_NONBLOCK)
	fd_flags |= O_NONBLOCK;
#elif defined(O_NDELAY)
	fd_flags |= O_NDELAY;
#elif defined(FNDELAY)
	fd_flags |= FNDELAY;
#else
#error Please teach APR how to make sockets non-blocking on your platform.
#endif
	if (fcntl(sd, F_SETFL, fd_flags) == -1) {
		return errno;
	}
#else
	int on = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_NONBLOCK, &on, sizeof(int)) < 0)
		return errno;
#endif							/* BEOS */
	return APR_SUCCESS;
}

apr_status_t
proc_connect_ipc(server_rec * main_server,
				 fcgid_procnode * procnode, fcgid_ipc * ipc_handle)
{
	fcgid_namedpipe_handle *handle_info;
	struct sockaddr_un unix_addr;
	apr_status_t rv;
	apr_int32_t on = 1;

	/* Alloc memory for unix domain socket */
	ipc_handle->ipc_handle_info
		= (fcgid_namedpipe_handle *) apr_pcalloc(ipc_handle->request->pool,
												 sizeof
												 (fcgid_namedpipe_handle));
	if (!ipc_handle->ipc_handle_info)
		return APR_ENOMEM;
	handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	handle_info->handle_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	apr_pool_cleanup_register(ipc_handle->request->pool,
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
		apr_pool_cleanup_run(ipc_handle->request->pool,
							 ipc_handle->ipc_handle_info,
							 ipc_handle_cleanup);
		return APR_ECONNREFUSED;
	}

	/* Set no delay option */
	setsockopt(handle_info->handle_socket, IPPROTO_TCP, TCP_NODELAY,
			   (char *) &on, sizeof(on));

	/* Set nonblock option */
	if ((rv =
		 set_socket_nonblock(handle_info->handle_socket)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, main_server,
					 "mod_fcgid: can't set nonblock unix domain socket");
		return rv;
	}

	return APR_SUCCESS;
}

apr_status_t proc_read_ipc(server_rec * main_server,
						   fcgid_ipc * ipc_handle, const char *buffer,
						   apr_size_t * size)
{
	fd_set rset;
	struct timeval tv;
	int retcode, unix_socket;
	fcgid_namedpipe_handle *handle_info;

	handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	unix_socket = handle_info->handle_socket;

	do {
		if ((retcode = read(unix_socket, buffer, *size)) > 0) {
			*size = retcode;
			return APR_SUCCESS;
		}
	} while (retcode == -1 && APR_STATUS_IS_EINTR(errno));
	if (retcode == -1 && !APR_STATUS_IS_EAGAIN(errno)) {
		ap_log_error(APLOG_MARK, APLOG_INFO, errno,
					 main_server,
					 "mod_fcgid: read data from fastcgi server error");
		return errno;
	}

	/* I have to wait a while */
	FD_ZERO(&rset);
	FD_SET(unix_socket, &rset);
	do {
		tv.tv_usec = 0;
		tv.tv_sec = ipc_handle->communation_timeout;
		retcode = select(unix_socket + 1, &rset, NULL, NULL, &tv);
	} while (retcode == -1 && APR_STATUS_IS_EINTR(errno));
	if (retcode == -1) {
		ap_log_error(APLOG_MARK, APLOG_INFO, errno,
					 main_server,
					 "mod_fcgid: select unix domain socket error");
		return errno;
	} else if (retcode == 0) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0,
					 main_server,
					 "mod_fcgid: read data timeout in %d seconds",
					 ipc_handle->communation_timeout);
		return APR_ETIMEDOUT;
	}

	/* Read again after select() */
	do {
		if ((retcode = read(unix_socket, buffer, *size)) > 0) {
			*size = retcode;
			return APR_SUCCESS;
		}
	} while (retcode == -1 && APR_STATUS_IS_EINTR(errno));

	if (retcode == 0) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0,
					 main_server,
					 "mod_fcgid: Read data error, fastcgi server has close connection");
		return APR_EPIPE;
	}

	ap_log_error(APLOG_MARK, APLOG_INFO, errno,
				 main_server,
				 "mod_fcgid: read data from fastcgi server error.");
	return errno;
}

static apr_status_t socket_writev(fcgid_ipc * ipc_handle,
								  struct iovec *vec, int nvec,
								  int *writecnt)
{
	fd_set wset;
	struct timeval tv;
	int retcode, unix_socket;
	fcgid_namedpipe_handle *handle_info;

	handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
	unix_socket = handle_info->handle_socket;

	/* Try nonblock write */
	do {
		if ((retcode = writev(unix_socket, vec, nvec)) > 0) {
			*writecnt = retcode;
			return APR_SUCCESS;
		}
	} while (retcode == -1 && APR_STATUS_IS_EINTR(errno));
	if (!APR_STATUS_IS_EAGAIN(errno))
		return errno;

	/* Select() */
	FD_ZERO(&wset);
	FD_SET(unix_socket, &wset);
	do {
		tv.tv_usec = 0;
		tv.tv_sec = ipc_handle->communation_timeout;
		retcode = select(unix_socket + 1, NULL, &wset, NULL, &tv);
	} while (retcode == -1 && APR_STATUS_IS_EINTR(errno));
	if (retcode == -1)
		return errno;

	/* Write again */
	do {
		if ((retcode = writev(unix_socket, vec, nvec)) > 0) {
			*writecnt = retcode;
			return APR_SUCCESS;
		}
	} while (retcode == -1 && APR_STATUS_IS_EINTR(errno));

	if (retcode == 0) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0,
					 ipc_handle->request->server,
					 "mod_fcgid: Write data error, fastcgi server has close connection");
		return APR_EPIPE;
	}

	return errno;
}

static apr_status_t writev_it_all(fcgid_ipc * ipc_handle,
								  struct iovec *vec, int nvec)
{
	apr_size_t bytes_written = 0;
	apr_status_t rv;
	apr_size_t len = 0;
	int i = 0;
	int writecnt = 0;

	/* Calculate the total size */
	for (i = 0; i < nvec; i++) {
		len += vec[i].iov_len;
	}

	i = 0;
	while (bytes_written != len) {
		rv = socket_writev(ipc_handle, vec + i, nvec - i, &writecnt);
		if (rv != APR_SUCCESS)
			return rv;
		bytes_written += writecnt;

		if (bytes_written < len) {
			/* Skip over the vectors that have already been written */
			apr_size_t cnt = vec[i].iov_len;

			while (writecnt >= cnt && i + 1 < nvec) {
				i++;
				cnt += vec[i].iov_len;
			}

			if (writecnt < cnt) {
				/* Handle partial write of vec i */
				vec[i].iov_base = (char *) vec[i].iov_base +
					(vec[i].iov_len - (cnt - writecnt));
				vec[i].iov_len = cnt - writecnt;
			}
		}
	}

	return APR_SUCCESS;
}

#define FCGID_VEC_COUNT 8
apr_status_t proc_write_ipc(server_rec * main_server,
							fcgid_ipc * ipc_handle,
							apr_bucket_brigade * output_brigade)
{
	apr_status_t rv;
	struct iovec vec[FCGID_VEC_COUNT];
	int nvec = 0;
	apr_bucket *e;

	for (e = APR_BRIGADE_FIRST(output_brigade);
		 e != APR_BRIGADE_SENTINEL(output_brigade);
		 e = APR_BUCKET_NEXT(e)) {
		/* Read bucket */
		if ((rv = apr_bucket_read(e, (const char **) &vec[nvec].iov_base,
								  &vec[nvec].iov_len,
								  APR_BLOCK_READ)) != APR_SUCCESS)
			return rv;

		if (nvec == (FCGID_VEC_COUNT - 1)) {
			/* It's time to write now */
			if ((rv =
				 writev_it_all(ipc_handle, vec,
							   FCGID_VEC_COUNT)) != APR_SUCCESS)
				return rv;
			nvec = 0;
		} else
			nvec++;
	}

	/* There are something left */
	if (nvec != 0) {
		if ((rv = writev_it_all(ipc_handle, vec, nvec)) != APR_SUCCESS)
			return rv;
	}

	return APR_SUCCESS;
}

apr_status_t proc_close_ipc(fcgid_ipc * ipc_handle)
{
	apr_status_t rv = apr_pool_cleanup_run(ipc_handle->request->pool,
										   ipc_handle->ipc_handle_info,
										   ipc_handle_cleanup);

	ipc_handle->ipc_handle_info = NULL;
	return rv;
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
