/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/tcp.h>        /* For TCP_NODELAY */
#include <sys/poll.h>
#include <sys/stat.h>
#define CORE_PRIVATE
#include "httpd.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "apr_network_io.h"
#include "ap_mpm.h"
#include "http_config.h"
#include "mpm_common.h"
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
#include "fcgid_spawn_ctl.h"

#if MODULE_MAGIC_NUMBER_MAJOR < 20081201
#define ap_unixd_config unixd_config
// #define ap_unixd_setup_child unixd_setup_child
// #define ap_unixd_set_global_mutex_perms unixd_set_global_mutex_perms
#endif

#define DEFAULT_FCGID_LISTENBACKLOG 5

typedef struct {
    int handle_socket;
} fcgid_namedpipe_handle;

static int g_process_counter = 0;
static apr_pool_t *g_inode_cginame_map = NULL;

static apr_status_t ap_unix_create_privileged_process(apr_proc_t * newproc,
                                                      const char *progname,
                                                      const char *const
                                                      *args, const char *const
                                                      *env,
                                                      apr_procattr_t *
                                                      attr,
                                                      ap_unix_identity_t *
                                                      ugid, apr_pool_t * p)
{
    int i = 0;
    const char **newargs;
    const char *newprogname;
    const char *execuser, *execgroup;
    const char *argv0;

    if (!ap_unixd_config.suexec_enabled) {
        return apr_proc_create(newproc, progname, args, env, attr, p);
    }

    argv0 = ap_strrchr_c(progname, '/');
    /* Allow suexec's "/" check to succeed */
    if (argv0 != NULL) {
        argv0++;
    } else {
        argv0 = progname;
    }


    if (ugid->userdir) {
        execuser = apr_psprintf(p, "~%ld", (long) ugid->uid);
    } else {
        execuser = apr_psprintf(p, "%ld", (long) ugid->uid);
    }
    execgroup = apr_psprintf(p, "%ld", (long) ugid->gid);

    if (!execuser || !execgroup) {
        return APR_ENOMEM;
    }

    i = 0;
    if (args) {
        while (args[i]) {
            i++;
        }
    }
    /* allocate space for 4 new args, the input args, and a null terminator */
    newargs = apr_palloc(p, sizeof(char *) * (i + 4));
    newprogname = SUEXEC_BIN;
    newargs[0] = SUEXEC_BIN;
    newargs[1] = execuser;
    newargs[2] = execgroup;
    newargs[3] = apr_pstrdup(p, argv0);

    /*
     ** using a shell to execute suexec makes no sense thus
     ** we force everything to be APR_PROGRAM, and never
     ** APR_SHELLCMD
     */
    if (apr_procattr_cmdtype_set(attr, APR_PROGRAM) != APR_SUCCESS) {
        return APR_EGENERAL;
    }

    i = 1;
    do {
        newargs[i + 3] = args[i];
    } while (args[i++]);

    return apr_proc_create(newproc, newprogname, newargs, env, attr, p);
}

static apr_status_t fcgid_create_privileged_process(apr_proc_t * newproc,
                                                    const char *progname,
                                                    const char *const
                                                    *args,
                                                    const char *const *env,
                                                    apr_procattr_t * attr,
                                                    fcgid_proc_info *
                                                    procinfo,
                                                    apr_pool_t * p)
{
    ap_unix_identity_t ugid;

    if (!ap_unixd_config.suexec_enabled
        || (procinfo->uid == (uid_t) - 1
            && procinfo->gid == (gid_t) - 1)) {
        return apr_proc_create(newproc, progname, args, env, attr, p);
    }

    ugid.gid = procinfo->gid;
    ugid.uid = procinfo->uid;
    ugid.userdir = procinfo->userdir;
    return ap_unix_create_privileged_process(newproc, progname, args, env,
                                             attr, &ugid, p);
}

static apr_status_t socket_file_cleanup(void *theprocnode)
{
    fcgid_procnode *procnode = (fcgid_procnode *) theprocnode;

    unlink(procnode->socket_path);
    return APR_SUCCESS;
}

static apr_status_t exec_setuid_cleanup(void *dummy)
{
    seteuid(0);
    setuid(ap_unixd_config.user_id);
    return APR_SUCCESS;
}

apr_status_t
proc_spawn_process(char *lpszwapper, fcgid_proc_info * procinfo,
                   fcgid_procnode * procnode)
{
    server_rec *main_server = procinfo->main_server;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);
    apr_status_t rv = APR_SUCCESS;
    apr_file_t *file;
    int omask, retcode, unix_socket;
    char **proc_environ;
    struct sockaddr_un unix_addr;
    apr_procattr_t *procattr = NULL;
    char key_name[_POSIX_PATH_MAX];
    void *dummy;
    int argc;
    const char *wargv[APACHE_ARG_MAX];
    const char *word; /* For wrapper */
    const char *tmp;
    const char *argv[2];

    /* Build wrapper args */
    argc = 0;
    tmp = lpszwapper;
    while (1) {
        word = ap_getword_white(procnode->proc_pool, &tmp);
        if (word == NULL || *word == '\0')
            break;
        if (argc >= APACHE_ARG_MAX)
            break;
        wargv[argc++] = word;
    }
    wargv[argc] = NULL;

    /* Initialize the variables */
    if (!g_inode_cginame_map) {
        rv = apr_pool_create(&g_inode_cginame_map,
                             procinfo->main_server->process->pconf);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                         procinfo->main_server,
                         "mod_fcgid: can't create CGI name map table");
            return APR_ENOMEM;
        }
    }

    /* 
       Create UNIX domain socket before spawn 
     */

    /* Generate a UNIX domain socket file path */
    /* XXX It's nothing I can do if the socket dir is too long... */
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    apr_snprintf(unix_addr.sun_path, sizeof(unix_addr.sun_path) - 1,
                 "%s/%" APR_PID_T_FMT ".%d", sconf->sockname_prefix,
                 getpid(), g_process_counter++);
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
    if (ap_unixd_config.suexec_enabled) {
        apr_pool_cleanup_register(procnode->proc_pool,
                                  procnode, socket_file_cleanup,
                                  exec_setuid_cleanup);
    } else {
        apr_pool_cleanup_register(procnode->proc_pool,
                                  procnode, socket_file_cleanup,
                                  apr_pool_cleanup_null);
    }

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
        if (chown(unix_addr.sun_path, ap_unixd_config.user_id, -1) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
                         "mod_fcgid: couldn't change owner of unix domain socket %s",
                         unix_addr.sun_path);
            close(unix_socket);
            return errno;
        }
    }

    {
        int oldflags = fcntl(unix_socket, F_GETFD, 0);

        if (oldflags < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                         procinfo->main_server,
                         "mod_fcgid: fcntl F_GETFD failed");
            close(unix_socket);
            return errno;
        }

        oldflags |= FD_CLOEXEC;
        if (fcntl(unix_socket, F_SETFD, oldflags) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                         procinfo->main_server,
                         "mod_fcgid: fcntl F_SETFD failed");
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
    procnode->proc_id = apr_pcalloc(procnode->proc_pool, 
                                    sizeof(apr_proc_t));
    if (
   (rv =
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
                                               (lpszwapper != NULL
                                                && lpszwapper[0] !=
                                                '\0') ? wargv[0] :
                                               procinfo->cgipath))) !=
APR_SUCCESS
|| (rv = apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) != APR_SUCCESS
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
    if (lpszwapper != NULL && lpszwapper[0] != '\0') {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, procinfo->main_server,
                     "mod_fcgid: call %s with wrapper %s",
                     procinfo->cgipath, lpszwapper);
        if ((rv =
             fcgid_create_privileged_process(procnode->proc_id,
                                             wargv[0], wargv,
                                             (const char *const *)
                                             proc_environ, procattr,
                                             procinfo,
                                             procnode->proc_pool)) !=
            APR_SUCCESS) {
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
             fcgid_create_privileged_process(procnode->proc_id,
                                             procinfo->cgipath,
                                             argv,
                                             (const char *const *)
                                             proc_environ, procattr,
                                             procinfo,
                                             procnode->proc_pool)) !=
            APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
                         "mod_fcgid: can't create process");
            close(unix_socket);
            return rv;
        }
    }

    /* Set the (deviceid, inode) -> fastcgi path map for log */
    apr_snprintf(key_name, _POSIX_PATH_MAX, "%lX%lX",
                 (unsigned long) procnode->inode,
                 (unsigned long) procnode->deviceid);
    dummy = NULL;
    apr_pool_userdata_get(&dummy, key_name, g_inode_cginame_map);
    if (!dummy) {
        /* Insert a new item if key not found */
        const char *put_key = apr_psprintf(g_inode_cginame_map, "%lX%lX",
                                           (unsigned long) procnode->inode,
                                           (unsigned long) procnode->deviceid);
        const char *fcgipath = apr_psprintf(g_inode_cginame_map, "%s",
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

    /* su as root before sending kill signal, for suEXEC */
    apr_status_t rv;

    if (ap_unixd_config.suexec_enabled && seteuid(0) != 0) {

        /* It's fatal error */
        kill(getpid(), SIGTERM);
        return APR_EACCES;
    }
    rv = apr_proc_kill(procnode->proc_id, SIGTERM);
    if (ap_unixd_config.suexec_enabled && seteuid(ap_unixd_config.user_id) != 0)
    {
        kill(getpid(), SIGTERM);
        return APR_EACCES;
    }
    return rv;
}

apr_status_t proc_kill_force(fcgid_procnode * procnode,
                             server_rec * main_server)
{
    apr_status_t rv;

    if (ap_unixd_config.suexec_enabled && seteuid(0) != 0) {

        /* It's fatal error */
        kill(getpid(), SIGTERM);
        return APR_EACCES;
    }
    rv = apr_proc_kill(procnode->proc_id, SIGKILL);
    if (ap_unixd_config.suexec_enabled && seteuid(ap_unixd_config.user_id) != 0)
    {
        kill(getpid(), SIGTERM);
        return APR_EACCES;
    }
    return rv;
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
            handle_info->handle_socket = -1;
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
#endif                          /* BEOS */
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
    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
    handle_info->handle_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    apr_pool_cleanup_register(ipc_handle->request->pool,
                              handle_info, ipc_handle_cleanup,
                              apr_pool_cleanup_null);

    /* Connect to fastcgi server */
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    apr_cpystrn(unix_addr.sun_path, procnode->socket_path,
                sizeof(unix_addr.sun_path));

    /* I am the only one who connecting the server
       So I don't have to worry about ECONNREFUSED(listen queue overflow) problem,
       and I will never retry on error */
    if (connect(handle_info->handle_socket, (struct sockaddr *) &unix_addr,
                sizeof(unix_addr)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, apr_get_os_error(),
                     main_server,
                     "mod_fcgid: can't connect unix domain socket: %s",
                     procnode->socket_path);
        return APR_ECONNREFUSED;
    }

    /* Set no delay option */
    setsockopt(handle_info->handle_socket, IPPROTO_TCP, TCP_NODELAY,
               (char *) &on, sizeof(on));

    /* Set nonblock option */
    if ((rv =
         set_socket_nonblock(handle_info->handle_socket)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, main_server,
                     "mod_fcgid: can't make unix domain socket nonblocking");
        return rv;
    }

    return APR_SUCCESS;
}

apr_status_t proc_close_ipc(server_rec * main_server,
                            fcgid_ipc * ipc_handle)
{
    apr_status_t rv;

    rv = apr_pool_cleanup_run(ipc_handle->request->pool,
                              ipc_handle->ipc_handle_info,
                              ipc_handle_cleanup);
    ipc_handle->ipc_handle_info = NULL;
    return rv;
}

apr_status_t proc_read_ipc(server_rec * main_server,
                           fcgid_ipc * ipc_handle, const char *buffer,
                           apr_size_t * size)
{
    int retcode, unix_socket;
    fcgid_namedpipe_handle *handle_info;
    struct pollfd pollfds[1];

    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;
    unix_socket = handle_info->handle_socket;

    do {
        if ((retcode = read(unix_socket, (void *) buffer, *size)) > 0) {
            *size = retcode;
            return APR_SUCCESS;
        }
    } while (retcode == -1 && APR_STATUS_IS_EINTR(errno));
    if (retcode == -1 && !APR_STATUS_IS_EAGAIN(errno)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno,
                     main_server,
                     "mod_fcgid: error reading data from FastCGI server");
        return errno;
    }

    /* I have to wait a while */

    pollfds[0].fd = unix_socket;
    pollfds[0].events = POLLIN;
    do {
        retcode = poll(pollfds, 1, ipc_handle->communation_timeout * 1000);
    } while (retcode <= 0 && APR_STATUS_IS_EINTR(errno));
    if (retcode == -1) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno,
                     main_server,
                     "mod_fcgid: error polling unix domain socket");
        return errno;
    } else if (retcode == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                     main_server,
                     "mod_fcgid: read data timeout in %d seconds",
                     ipc_handle->communation_timeout);
        return APR_ETIMEDOUT;
    }

    do {
        if ((retcode = read(unix_socket, (void *) buffer, *size)) > 0) {
            *size = retcode;
            return APR_SUCCESS;
        }
    } while (retcode == -1 && APR_STATUS_IS_EINTR(errno));

    if (retcode == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                     main_server,
                     "mod_fcgid: error reading data, FastCGI server closed connection");
        return APR_EPIPE;
    }

    ap_log_error(APLOG_MARK, APLOG_WARNING, errno,
                 main_server,
                 "mod_fcgid: error reading data from FastCGI server");
    return errno;
}

static apr_status_t socket_writev(fcgid_ipc * ipc_handle,
                                  struct iovec *vec, int nvec,
                                  int *writecnt)
{
    int retcode, unix_socket;
    fcgid_namedpipe_handle *handle_info;
    struct pollfd pollfds[1];

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

    /* poll() */
    pollfds[0].fd = unix_socket;
    pollfds[0].events = POLLOUT;
    do {
        retcode = poll(pollfds, 1, ipc_handle->communation_timeout * 1000);
    } while (retcode <= 0 && APR_STATUS_IS_EINTR(errno));
    if (retcode == -1)
        return errno;

    /* Write again */
    do {
        if ((retcode = writev(unix_socket, vec, nvec)) > 0) {
            *writecnt = retcode;
            return APR_SUCCESS;
        }
    } while (retcode == -1 && APR_STATUS_IS_EINTR(errno));

    if (retcode == -1) {
        ap_log_error(APLOG_MARK, APLOG_INFO, apr_get_os_error(),
                     ipc_handle->request->server,
                     "mod_fcgid: error writing data, FastCGI server closed connection");
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
        apr_size_t len;
        const char* base;
        if ((rv = apr_bucket_read(e, &base, &len,
                                  APR_BLOCK_READ)) != APR_SUCCESS)
            return rv;

        vec[nvec].iov_len = len;
        vec[nvec].iov_base = (char*) base;
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

void
proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
                     apr_exit_why_e exitwhy, server_rec * main_server)
{
    const char *cgipath = NULL;
    const char *diewhy = NULL;
    char signal_info[HUGE_STRING_LEN];
    char key_name[_POSIX_PATH_MAX];
    int signum = exitcode;
    void* tmp;

    memset(signal_info, 0, HUGE_STRING_LEN);

    /* Get the file name infomation base on inode and deviceid */
    apr_snprintf(key_name, _POSIX_PATH_MAX, "%lX%lX",
                 (unsigned long) procnode->inode,
                 (unsigned long) procnode->deviceid);
    apr_pool_userdata_get(&tmp, key_name,
                          g_inode_cginame_map);
    cgipath = tmp;

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
                     "mod_fcgid: process %s(%" APR_PID_T_FMT ") exit(%s), %s",
                     cgipath, procnode->proc_id->pid, diewhy, signal_info);
    else
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
                     "mod_fcgid: can't get CGI name while exiting, exitcode: %d",
                     exitcode);
}
