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


#include "httpd.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "util_script.h"
#include "mod_core.h"
#include "mod_cgi.h"
#include "apr_tables.h"
#include "fcgid_proc.h"
#include "fcgid_proctbl.h"
#include "fcgid_protocol.h"
#include "fcgid_conf.h"
#include "fcgid_pm.h"
#include "fcgid_spawn_ctl.h"
#define SHUTDOWN_EVENT_NAME "_FCGI_SHUTDOWN_EVENT_"
#define FINISH_EVENT_DATA_NAME "finish_event"
#ifndef SIGKILL
#define SIGKILL 9
#endif

/* It's tested on WinNT ONLY, if it work on the other MS platform, let me know */
#if WINVER < 0x0400
#error It is tested on WinNT only
#endif

typedef struct {
    HANDLE handle_pipe;
    OVERLAPPED overlap_read;
    OVERLAPPED overlap_write;
} fcgid_namedpipe_handle;

static int g_process_counter = 0;
static apr_pool_t *g_inode_cginame_map = NULL;

static apr_status_t close_finish_event(void *finishevent)
{
    HANDLE *finish_event = finishevent;

    CloseHandle(*finish_event);
    return APR_SUCCESS;
}

apr_status_t proc_spawn_process(char *wrapper_cmdline, fcgid_proc_info *procinfo,
                                fcgid_procnode *procnode)
{
    HANDLE *finish_event, listen_handle;
    int bufused = 0;
    SECURITY_ATTRIBUTES SecurityAttributes;
    apr_procattr_t *proc_attr;
    apr_status_t rv;
    apr_file_t *file;
    char **proc_environ;
    char key_name[_POSIX_PATH_MAX];
    char sock_path[_POSIX_PATH_MAX];
    char *dummy;
    char *argv[2];
    int argc;
    char *wargv[APACHE_ARG_MAX], *word; /* For wrapper */
    const char *tmp;

    /* Build wrapper args */
    argc = 0;
    tmp = wrapper_cmdline;
    while (1) {
        word = ap_getword_white(procnode->proc_pool, &tmp);
        if (word == NULL || *word == '\0')
            break;
        if (argc >= APACHE_ARG_MAX)
            break;
        wargv[argc++] = word;
    }
    wargv[argc] = NULL;

    memset(&SecurityAttributes, 0, sizeof(SecurityAttributes));

    /* Create the pool if necessary */
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

    /* Prepare finish event */
    finish_event = apr_palloc(procnode->proc_pool, sizeof(HANDLE));
    *finish_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (*finish_event == NULL
        || !SetHandleInformation(*finish_event, HANDLE_FLAG_INHERIT, TRUE))
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     procinfo->main_server,
                     "mod_fcgid: can't create mutex for subprocess");
        return APR_ENOLOCK;
    }
    apr_pool_cleanup_register(procnode->proc_pool, finish_event,
                              close_finish_event, apr_pool_cleanup_null);

    /* For proc_kill_gracefully() */
    apr_pool_userdata_set(finish_event, FINISH_EVENT_DATA_NAME,
                          NULL, procnode->proc_pool);

    /* Pass the finish event id to subprocess */
    apr_table_setn(procinfo->proc_environ, SHUTDOWN_EVENT_NAME,
                   apr_ltoa(procnode->proc_pool, (long) *finish_event));

    /* Prepare the listen namedpipe file name */
    apr_snprintf(sock_path, _POSIX_PATH_MAX - 1,
                 "\\\\.\\pipe\\fcgidpipe-%u.%lu",
                 GetCurrentProcessId(), g_process_counter++);

    /* Prepare the listen namedpipe handle */
    SecurityAttributes.bInheritHandle = TRUE;
    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL;
    listen_handle = CreateNamedPipe(sock_path,
                                    PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                                    PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                                    8192, 8192, 0, &SecurityAttributes);
    if (listen_handle == INVALID_HANDLE_VALUE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     procinfo->main_server,
                     "mod_fcgid: can't create namedpipe for subprocess");
        return APR_ENOSOCKET;
    }
    apr_cpystrn(procnode->socket_path, sock_path, _POSIX_PATH_MAX);

    /* Build environment variables */
    proc_environ = ap_create_environment(procnode->proc_pool,
                                         procinfo->proc_environ);
    if (!proc_environ) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     procinfo->main_server,
                     "mod_fcgid: can't build environment variables");
        return APR_ENOMEM;
    }

    /* Create process now */
    procnode->proc_id = apr_pcalloc(procnode->proc_pool,
                                    sizeof(apr_proc_t));
    if ((rv = apr_procattr_create(&proc_attr, procnode->proc_pool))
               != APR_SUCCESS
        || (rv = apr_procattr_dir_set(proc_attr,
                     ap_make_dirstr_parent(procnode->proc_pool,
                         (wrapper_cmdline && wrapper_cmdline[0] != '\0') 
                              ? wargv[0] : procinfo->cgipath))) != APR_SUCCESS
        || (rv = apr_procattr_cmdtype_set(proc_attr, APR_PROGRAM))
               != APR_SUCCESS
        || (rv = apr_procattr_detach_set(proc_attr, 1)) != APR_SUCCESS
        || (rv = apr_procattr_io_set(proc_attr, APR_NO_PIPE, 
                                     APR_NO_FILE, APR_NO_FILE)) != APR_SUCCESS
        || (rv = apr_os_file_put(&file, &listen_handle, 0,
                                 procnode->proc_pool)) != APR_SUCCESS
        || (rv = apr_procattr_child_in_set(proc_attr, file, NULL))
               != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, procinfo->main_server,
                     "mod_fcgid: can't create FastCGI process attribute");
        CloseHandle(listen_handle);
        return APR_ENOPROC;
    }

    /* fork and exec now */
    if (wrapper_cmdline != NULL && wrapper_cmdline[0] != '\0') {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, procinfo->main_server,
                     "mod_fcgid: call %s with wrapper %s",
                     procinfo->cgipath, wrapper_cmdline);
        if ((rv = apr_proc_create(procnode->proc_id, wargv[0],
                                  wargv, proc_environ, proc_attr,
                                  procnode->proc_pool)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
                         "mod_fcgid: can't create wrapper process for %s",
                         procinfo->cgipath);
            CloseHandle(listen_handle);
            return rv;
        }
    } else {
        argv[0] = procinfo->cgipath;
        argv[1] = NULL;
        if ((rv =
             apr_proc_create(procnode->proc_id, procinfo->cgipath,
                             argv, proc_environ, proc_attr,
                             procnode->proc_pool)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, procinfo->main_server,
                         "mod_fcgid: can't create process");
            CloseHandle(listen_handle);
            return rv;
        }
    }

    /* OK, I created the process, now put it back to idle list */
    CloseHandle(listen_handle);

    /* Set the (deviceid, inode, shareid) -> fastcgi path map for log */
    apr_snprintf(key_name, _POSIX_PATH_MAX, "%lX%lX%lX",
                 procnode->inode, procnode->deviceid,
                 procnode->share_grp_id);
    dummy = NULL;
    apr_pool_userdata_get(&dummy, key_name, g_inode_cginame_map);
    if (!dummy) {
        /* Insert a new item if key not found */
        char *put_key = apr_psprintf(g_inode_cginame_map, "%lX%lX%lX",
                                     procnode->inode, procnode->deviceid,
                                     procnode->share_grp_id);
        char *fcgipath = apr_psprintf(g_inode_cginame_map, "%s",
                                      procinfo->cgipath);

        if (put_key && fcgipath)
            apr_pool_userdata_set(fcgipath, put_key, NULL,
                                  g_inode_cginame_map);
    }

    return APR_SUCCESS;
}

apr_status_t proc_kill_gracefully(fcgid_procnode *procnode,
                                  server_rec *main_server)
{
    HANDLE *finish_event = NULL;

    apr_pool_userdata_get((void **) &finish_event,
                          FINISH_EVENT_DATA_NAME, procnode->proc_pool);

    if (finish_event != NULL)
        SetEvent(*finish_event);
    return APR_SUCCESS;
}

apr_status_t proc_kill_force(fcgid_procnode *procnode,
                             server_rec *main_server)
{
    return apr_proc_kill(procnode->proc_id, SIGKILL);
}

apr_status_t proc_wait_process(server_rec *main_server,
                               fcgid_procnode *procnode)
{
    apr_status_t rv;
    int exitcode;
    apr_exit_why_e exitwhy;

    if ((rv = apr_proc_wait(procnode->proc_id, &exitcode, &exitwhy,
                            APR_NOWAIT)) == APR_CHILD_DONE) {
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

static apr_status_t ipc_handle_cleanup(void *thehandle)
{
    fcgid_namedpipe_handle *handle = thehandle;

    /* Sanity check */
    if (handle) {
        if (handle->handle_pipe != INVALID_HANDLE_VALUE)
            CloseHandle(handle->handle_pipe);
        if (handle->overlap_read.hEvent != NULL)
            CloseHandle(handle->overlap_read.hEvent);
        if (handle->overlap_write.hEvent != NULL)
            CloseHandle(handle->overlap_write.hEvent);
        handle->handle_pipe = INVALID_HANDLE_VALUE;
        handle->overlap_read.hEvent = NULL;
        handle->overlap_write.hEvent = NULL;
    }

    return APR_SUCCESS;
}

apr_status_t proc_connect_ipc(fcgid_procnode *procnode, fcgid_ipc *ipc_handle)
{
    /* Prepare the ipc struct */
    fcgid_namedpipe_handle *handle_info;

    ipc_handle->ipc_handle_info =
        (fcgid_namedpipe_handle *) apr_pcalloc(ipc_handle->request->pool,
                                               sizeof
                                               (fcgid_namedpipe_handle));
    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

    /* Prepare OVERLAPPED struct for non-block I/O */
    handle_info->overlap_read.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    handle_info->overlap_write.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    handle_info->handle_pipe = INVALID_HANDLE_VALUE;

    apr_pool_cleanup_register(ipc_handle->request->pool,
                              handle_info,
                              ipc_handle_cleanup, apr_pool_cleanup_null);

    if (handle_info->overlap_read.hEvent == NULL
            || handle_info->overlap_write.hEvent == NULL)
        return APR_ENOMEM;

    /* Connect to name pipe */
    handle_info->handle_pipe = CreateFile(procnode->socket_path,
                                          GENERIC_READ | GENERIC_WRITE,
                                          0, NULL, OPEN_EXISTING,
                                          FILE_FLAG_OVERLAPPED, NULL);

    if (handle_info->handle_pipe == INVALID_HANDLE_VALUE
        && ipc_handle->connect_timeout != 0
        && GetLastError() == ERROR_PIPE_BUSY)
    {
        /* XXX - there appears to be a race, here
         * Wait for pipe to be ready for connect, and try again
         */
        if (WaitNamedPipe(procnode->socket_path, ipc_handle->connect_timeout))
        {
            handle_info->handle_pipe = CreateFile(procnode->socket_path,
                                                  GENERIC_READ | GENERIC_WRITE,
                                                  0, NULL, OPEN_EXISTING,
                                                  FILE_FLAG_OVERLAPPED, NULL);
        }
    }

    if (handle_info->handle_pipe == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) /* The process has exited */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ipc_handle->request,
                          "mod_fcgid: can't connect to named pipe, FastCGI"
                          " server %" APR_PID_T_FMT " has been terminated",
                          procnode->proc_id->pid);
        else
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, apr_get_os_error(), 
                          ipc_handle->request,
                          "mod_fcgid: can't connect to named pipe, FastCGI"
                          " server pid %" APR_PID_T_FMT,
                          procnode->proc_id->pid);
        return APR_ESPIPE;
    }

    /* Now named pipe connected */
    return APR_SUCCESS;
}

apr_status_t proc_close_ipc(fcgid_ipc * ipc_handle)
{
    apr_status_t rv;

    rv = apr_pool_cleanup_run(ipc_handle->request->pool,
                              ipc_handle->ipc_handle_info,
                              ipc_handle_cleanup);
    ipc_handle->ipc_handle_info = NULL;
    return rv;
}

apr_status_t proc_read_ipc(fcgid_ipc * ipc_handle, const char *buffer,
                           apr_size_t * size)
{
    apr_status_t rv;
    fcgid_namedpipe_handle *handle_info;
    DWORD bytesread;

    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

    if (ReadFile(handle_info->handle_pipe, (LPVOID) buffer,
                 *size, &bytesread, &handle_info->overlap_read)) {
        *size = bytesread;
        return APR_SUCCESS;
    } else if ((rv = GetLastError()) != ERROR_IO_PENDING) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_FROM_OS_ERROR(rv),
                      ipc_handle->request,
                      "mod_fcgid: can't read from pipe");
        return rv;
    } else {
        /* it's ERROR_IO_PENDING */
        DWORD transferred;
        DWORD dwWaitResult
            = WaitForSingleObject(handle_info->overlap_read.hEvent,
                                  ipc_handle->communation_timeout * 1000);

        if (dwWaitResult == WAIT_OBJECT_0) {
            if (!GetOverlappedResult(handle_info->handle_pipe,
                                     &handle_info->overlap_read,
                                     &transferred, FALSE /* don't wait */ )
                || transferred == 0) {
                rv = apr_get_os_error();
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, 
                              ipc_handle->request,
                              "mod_fcgid: get overlap result error");
                return rv;
            }

            *size = transferred;
            return APR_SUCCESS;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, ipc_handle->request,
                          "mod_fcgid: read timeout from pipe");
            return APR_ETIMEDOUT;
        }
    }
}

apr_status_t proc_write_ipc(fcgid_ipc * ipc_handle,
                            apr_bucket_brigade * birgade_send)
{
    fcgid_namedpipe_handle *handle_info;
    apr_bucket *bucket_request;
    apr_status_t rv;
    DWORD transferred;

    handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

    for (bucket_request = APR_BRIGADE_FIRST(birgade_send);
         bucket_request != APR_BRIGADE_SENTINEL(birgade_send);
         bucket_request = APR_BUCKET_NEXT(bucket_request))
    {
        char *write_buf;
        apr_size_t write_buf_len;
        apr_size_t has_write;

        if (APR_BUCKET_IS_EOS(bucket_request))
            break;

        if (APR_BUCKET_IS_FLUSH(bucket_request))
            continue;

        if ((rv = apr_bucket_read(bucket_request, &write_buf, &write_buf_len,
                                  APR_BLOCK_READ)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, ipc_handle->request,
                          "mod_fcgid: can't read request from bucket");
            return rv;
        }

        /* Write the buffer to fastcgi server */
        has_write = 0;
        while (has_write < write_buf_len) {
            DWORD byteswrite;

            if (WriteFile(handle_info->handle_pipe,
                          write_buf + has_write,
                          write_buf_len - has_write,
                          &byteswrite, &handle_info->overlap_write)) {
                has_write += byteswrite;
                continue;
            } else if ((rv = GetLastError()) != ERROR_IO_PENDING) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING,
                              APR_FROM_OS_ERROR(rv), ipc_handle->request,
                              "mod_fcgid: can't write to pipe");
                return rv;
            } else {
                /* 
                   it's ERROR_IO_PENDING on write
                 */
                DWORD dwWaitResult =
                    WaitForSingleObject(handle_info->overlap_write.hEvent,
                                        ipc_handle->communation_timeout * 1000);
                if (dwWaitResult == WAIT_OBJECT_0) {
                    if (!GetOverlappedResult(handle_info->handle_pipe,
                                             &handle_info->overlap_write,
                                             &transferred,
                                             FALSE /* don't wait */ )
                        || transferred == 0)
                    {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING,
                                      apr_get_os_error(), ipc_handle->request,
                                      "mod_fcgid: get overlap result error");
                        return APR_ESPIPE;
                    }
                    has_write += transferred;
                    continue;
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0,
                                  ipc_handle->request,
                                  "mod_fcgid: write timeout to pipe");
                    return APR_ESPIPE;
                }
            }
        }
    }

    return APR_SUCCESS;
}

void proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
                          apr_exit_why_e exitwhy, server_rec * main_server)
{
    char *cgipath = NULL;
    char *diewhy = NULL;
    char key_name[_POSIX_PATH_MAX];

    /* Get the file name infomation base on inode and deviceid */
    apr_snprintf(key_name, _POSIX_PATH_MAX, "%lX%lX%lX",
                 procnode->inode, procnode->deviceid,
                 procnode->share_grp_id);
    apr_pool_userdata_get(&cgipath, key_name, g_inode_cginame_map);

    /* Reasons to exit */
    switch (procnode->diewhy) {
    case FCGID_DIE_KILLSELF:
        if (exitwhy == APR_PROC_EXIT)
            diewhy = "normal exit";
        else
            diewhy = "access violation";
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
        diewhy = "connect error, server may has exited";
        break;
    case FCGID_DIE_COMM_ERROR:
        diewhy = "communication error";
        break;
    case FCGID_DIE_SHUTDOWN:
        diewhy = "shutting down";
        break;
    default:
        diewhy = "unknown";
    }

    /* Print log now */
    if (cgipath)
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
                     "mod_fcgid: process %s(%" APR_PID_T_FMT ") exit(%s), return code %d",
                     cgipath, procnode->proc_id->pid, diewhy, exitcode);
    else
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                     "mod_fcgid: can't get CGI name while exiting, exitcode: %d",
                     exitcode);
}
