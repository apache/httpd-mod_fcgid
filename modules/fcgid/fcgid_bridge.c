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
#include "http_request.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "apr_file_io.h"
#include "util_script.h"
#include "fcgid_bridge.h"
#include "fcgid_pm.h"
#include "fcgid_proctbl.h"
#include "fcgid_proc.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#include "fcgid_protocol.h"
#include "fcgid_bucket.h"
#define FCGID_APPLY_TRY_COUNT 2
#define FCGID_REQUEST_COUNT 32

static int g_variables_inited = 0;
static int g_busy_timeout;
static int g_connect_timeout;
static int g_comm_timeout;
static int g_max_requests_per_process;

static fcgid_procnode *apply_free_procnode(server_rec * main_server,
                                           fcgid_command * command)
{
    /* Scan idle list, find a node match inode, deviceid and groupid
       If there is no one there, return NULL */
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *busy_list_header, *proc_table;
    apr_ino_t inode = command->inode;
    apr_dev_t deviceid = command->deviceid;
    uid_t uid = command->uid;
    gid_t gid = command->gid;
    apr_size_t share_grp_id = command->share_grp_id;
    const char *virtualhost = command->virtualhost;

    proc_table = proctable_get_table_array();
    previous_node = proctable_get_idle_list();
    busy_list_header = proctable_get_busy_list();

    safe_lock(main_server);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        if (current_node->inode == inode
            && current_node->deviceid == deviceid
            && current_node->share_grp_id == share_grp_id
            && current_node->virtualhost == virtualhost
            && current_node->uid == uid && current_node->gid == gid) {
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
count_busy_processes(server_rec * main_server, fcgid_command * command)
{
    int result = 0;
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *proc_table = proctable_get_table_array();
    fcgid_procnode *busy_list_header = proctable_get_busy_list();

    safe_lock(main_server);

    previous_node = busy_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        if (current_node->inode == command->inode
            && current_node->deviceid == command->deviceid
            && current_node->share_grp_id == command->share_grp_id
            && current_node->virtualhost == command->virtualhost
            && current_node->uid == command->uid
            && current_node->gid == command->gid) {
            result++;
        }
        next_node = &proc_table[current_node->next_index];
        current_node = next_node;
    }

    safe_unlock(main_server);

    return result;
}

apr_status_t bucket_ctx_cleanup(void *thectx)
{
    /* Cleanup jobs:
       1. Free bucket buffer
       2. Return procnode
       NOTE: ipc will be clean when request pool cleanup, so I don't need to close it here
     */
    fcgid_bucket_ctx *ctx = (fcgid_bucket_ctx *) thectx;
    server_rec *main_server = ctx->ipc.request->server;

    /* Free bucket buffer */
    if (ctx->buffer) {
        apr_bucket_destroy(ctx->buffer);
        ctx->buffer = NULL;
    }

    proc_close_ipc(main_server, &ctx->ipc);

    if (ctx->procnode) {
        /* Return procnode
           I will return this slot to idle(or error) list except:
           I take too much time on this request( greater than get_busy_timeout() ),
           so the process manager may have put this slot from busy list to error
           list, and the contain of this slot may have been modified
           In this case I will do nothing and return, let the process manager 
           do the job   
         */
        int dt = (int)
            (apr_time_sec(apr_time_now()) - apr_time_sec(ctx->active_time));
        if (dt > g_busy_timeout) {
            /* Do nothing but print log */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         main_server,
                         "mod_fcgid: process busy timeout, take %d seconds for this request",
                         dt);
        } else if (ctx->has_error) {
            ctx->procnode->diewhy = FCGID_DIE_COMM_ERROR;
            return_procnode(main_server, ctx->procnode,
                            1 /* communication error */ );
        } else if (g_max_requests_per_process != -1
                   && ++ctx->procnode->requests_handled >=
                   g_max_requests_per_process) {
            ctx->procnode->diewhy = FCGID_DIE_LIFETIME_EXPIRED;
            return_procnode(main_server, ctx->procnode,
                            1 /* handled all requests */ );
        } else
            return_procnode(main_server, ctx->procnode,
                            0 /* communication ok */ );

        ctx->procnode = NULL;
    }

    return APR_SUCCESS;
}

static int getsfunc_fcgid_BRIGADE(char *buf, int len, void *arg)
{
    apr_bucket_brigade *bb = (apr_bucket_brigade *) arg;
    const char *dst_end = buf + len - 1;    /* leave room for terminating null */
    char *dst = buf;
    apr_bucket *e = APR_BRIGADE_FIRST(bb);
    apr_status_t rv;
    int done = 0;
    int getLF = 0;
    int getColon = 0;

    while ((dst < dst_end) && !done && !APR_BUCKET_IS_EOS(e)) {
        const char *bucket_data;
        apr_size_t bucket_data_len;
        const char *src;
        const char *src_end;
        apr_bucket *next;

        rv = apr_bucket_read(e, &bucket_data, &bucket_data_len,
                             APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return 0;
        }

        /* Move on to next bucket if it's fastcgi header bucket */
        if (e->type == &ap_bucket_type_fcgid_header
            || e->type == &apr_bucket_type_immortal) {
            next = APR_BUCKET_NEXT(e);
            apr_bucket_delete(e);
            e = next;
            if (getLF) {
                done = 1;
            }
            continue;
        }

        if (bucket_data_len == 0)
            return 0;

        /* Base on RFC2616 section 4.2 */
        src = bucket_data;
        src_end = bucket_data + bucket_data_len;
        while ((src < src_end) && (dst < dst_end) && !done) {
            if (*src == ':')
                getColon = 1;

            if (getLF && ((*src != ' ' && *src != '\t') || !getColon)) {
                done = 1;
                getColon = 0;
                break;
            } else if (getLF && (*src == ' ' || *src == '\t')) {
                *dst++ = '\r';
                *dst++ = '\n';
                getLF = 0;
            }

            if (*src == '\n') {
                getLF = 1;
            } else if (*src != '\r') {
                *dst++ = *src;
            }
            src++;
        }

        if (src < src_end) {
            apr_bucket_split(e, src - bucket_data);
        }
        next = APR_BUCKET_NEXT(e);
        apr_bucket_delete(e);
        e = next;
    }
    *dst = 0;
    return 1;
}

static int
handle_request(request_rec * r, int role, const char *argv0,
               fcgid_wrapper_conf * wrapper_conf,
               apr_bucket_brigade * output_brigade)
{
    apr_pool_t *request_pool = r->main ? r->main->pool : r->pool;
    server_rec *main_server = r->server;
    fcgid_command fcgi_request;
    fcgid_bucket_ctx *bucket_ctx;
    int i, j, cond_status;
    apr_status_t rv;
    apr_bucket_brigade *brigade_stdout;
    char sbuf[MAX_STRING_LEN];
    const char *location;

    if (!g_variables_inited) {
        g_connect_timeout = get_ipc_connect_timeout(r->server);
        g_comm_timeout = get_ipc_comm_timeout(r->server);
        g_busy_timeout = get_busy_timeout(r->server);
        g_max_requests_per_process =
            get_max_requests_per_process(r->server);
        if (g_comm_timeout == 0)
            g_comm_timeout = 1;
        g_variables_inited = 1;
    }

    bucket_ctx = apr_pcalloc(request_pool, sizeof(*bucket_ctx));
    if (!bucket_ctx) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     r->server,
                     "mod_fcgid: apr_calloc bucket_ctx failed in handle_request function");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    bucket_ctx->ipc.connect_timeout = g_connect_timeout;
    bucket_ctx->ipc.communation_timeout = g_comm_timeout;
    bucket_ctx->ipc.request = r;
    apr_pool_cleanup_register(request_pool, bucket_ctx,
                              bucket_ctx_cleanup, apr_pool_cleanup_null);

    /* Try to get a connected ipc handle */
    for (i = 0; i < FCGID_REQUEST_COUNT; i++) {
        /* Apply a free process slot, send a spawn request if I can't get one */
        for (j = 0; j < FCGID_APPLY_TRY_COUNT; j++) {
            apr_ino_t inode =
                wrapper_conf ? wrapper_conf->inode : r->finfo.inode;
            apr_dev_t deviceid =
                wrapper_conf ? wrapper_conf->deviceid : r->finfo.device;
            apr_size_t shareid =
                wrapper_conf ? wrapper_conf->share_group_id : 0;

            /* Init spawn request */
            procmgr_init_spawn_cmd(&fcgi_request, r, argv0, deviceid,
                                   inode, shareid);

            /* Apply a process slot */
            bucket_ctx->procnode =
                apply_free_procnode(r->server, &fcgi_request);
            if (bucket_ctx->procnode)
                break;

            /* Avoid sleeping the very first time through if there are no
               busy processes; the problem is just that we haven't spawned
               anything yet, so waiting is pointless */
            if (i > 0 || j > 0
                || count_busy_processes(r->server, &fcgi_request)) {
                apr_sleep(apr_time_from_sec(1));

                bucket_ctx->procnode =
                    apply_free_procnode(r->server, &fcgi_request);
                if (bucket_ctx->procnode)
                    break;
            }

            /* Send a spawn request if I can't get a process slot */
            procmgr_post_spawn_cmd(&fcgi_request, r);
        }

        /* Connect to the fastcgi server */
        if (bucket_ctx->procnode) {
            if (proc_connect_ipc
                (r->server, bucket_ctx->procnode,
                 &bucket_ctx->ipc) != APR_SUCCESS) {
                proc_close_ipc(r->server, &bucket_ctx->ipc);
                bucket_ctx->procnode->diewhy = FCGID_DIE_CONNECT_ERROR;
                return_procnode(r->server, bucket_ctx->procnode,
                                1 /* has error */ );
                bucket_ctx->procnode = NULL;
            } else
                break;
        }
    }

    /* Now I get a connected ipc handle */
    if (!bucket_ctx->procnode) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                     "mod_fcgid: can't apply process slot for %s", argv0);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    bucket_ctx->active_time = bucket_ctx->procnode->last_active_time =
        apr_time_now();

    /* Write output_brigade to fastcgi server */
    if ((rv =
         proc_write_ipc(main_server, &bucket_ctx->ipc,
                        output_brigade)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
                     "mod_fcgid: write data to fastcgi server error");
        bucket_ctx->has_error = 1;
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create brigade */
    brigade_stdout =
        apr_brigade_create(request_pool, r->connection->bucket_alloc);
    if (!brigade_stdout) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
                     "mod_fcgid: apr_brigade_create failed in handle_request function");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_BRIGADE_INSERT_TAIL(brigade_stdout,
                            ap_bucket_fcgid_header_create(r->connection->
                                                          bucket_alloc,
                                                          bucket_ctx));
    /*APR_BRIGADE_INSERT_TAIL(brigade_stdout, apr_bucket_flush_create(r->connection->bucket_alloc)); */

    /* Check the script header first. If got error, return immediately */
    if ((cond_status = ap_scan_script_header_err_core
         (r, sbuf, getsfunc_fcgid_BRIGADE, brigade_stdout)) >= 400)
        return cond_status;

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

        ap_internal_redirect_handler(location, r);
        return HTTP_OK;
    } else if (location && r->status == 200) {
        /* XX Note that if a script wants to produce its own Redirect 
         * body, it now has to explicitly *say* "Status: 302" 
         */
        return HTTP_MOVED_TEMPORARILY;
    }

    /* Now pass to output filter */
    if (role == FCGI_RESPONDER && (rv =
                                   ap_pass_brigade(r->output_filters,
                                                   brigade_stdout)) !=
        APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
                     "mod_fcgid: ap_pass_brigade failed in handle_request function");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Retrun condition status */
    return cond_status;
}

int bridge_request(request_rec * r, int role, const char *argv0,
                   fcgid_wrapper_conf * wrapper_conf)
{
    apr_pool_t *request_pool = r->main ? r->main->pool : r->pool;
    server_rec *main_server = r->server;
    apr_status_t rv = APR_SUCCESS;
    int seen_eos;
    size_t request_size = 0;
    apr_file_t *fd = NULL;
    int need_truncate = 1;
    apr_off_t cur_pos = 0;
    FCGI_Header *stdin_request_header;
    apr_bucket_brigade *output_brigade;
    apr_bucket *bucket_input, *bucket_header, *bucket_eos;
    size_t max_request_len = get_max_request_len(main_server);
    size_t max_mem_request_len = get_max_mem_request_len(main_server);
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
        (role, r->server, r->connection->bucket_alloc, output_brigade)
        || !build_env_block(r->server, envp, r->connection->bucket_alloc,
                            output_brigade)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                     main_server,
                     "mod_fcgid: can't build begin or env request");
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
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                         main_server,
                         "mod_fcgid: can't get data from http client");
            apr_brigade_destroy(output_brigade);
            if (input_brigade)
                apr_brigade_destroy(input_brigade);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        request_size = 0;
        for (bucket_input = APR_BRIGADE_FIRST(input_brigade);
             bucket_input != APR_BRIGADE_SENTINEL(input_brigade);
             bucket_input = APR_BUCKET_NEXT(bucket_input)) {
            const char *data;
            apr_size_t len;
            apr_bucket *bucket_stdin;

            if (APR_BUCKET_IS_EOS(bucket_input)) {
                seen_eos = 1;
                break;
            }

            if (APR_BUCKET_IS_METADATA(bucket_input))
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

            request_size += len;
            if (request_size > max_request_len) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                             main_server,
                             "mod_fcgid: http request length %" APR_SIZE_T_FMT " > %" APR_SIZE_T_FMT,
                             request_size, max_request_len);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (request_size > max_mem_request_len) {
                apr_size_t wrote_len;
                static const char *fd_key = "fcgid_fd";

                if (fd == NULL){
                    void *tmp;
                    apr_pool_userdata_get(&tmp, fd_key,
                                          r->connection->pool);
                    fd = tmp;
                }

                if (fd == NULL) {
                    const char *tempdir = NULL;
                    char *template;

                    rv = apr_temp_dir_get(&tempdir, r->pool);
                    if (rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_WARNING,
                                     apr_get_os_error(), main_server,
                                     "mod_fcigd: can't get tmp dir");
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }

                    apr_filepath_merge(&template, tempdir,
                                       "fcgid.tmp.XXXXXX",
                                       APR_FILEPATH_NATIVE, r->pool);
                    rv = apr_file_mktemp(&fd, template, 0,
                                         r->connection->pool);
                    if (rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_WARNING,
                                     apr_get_os_error(), main_server,
                                     "mod_fcgid: can't open tmp file fot stdin request");
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    apr_pool_userdata_set((const void *) fd, fd_key,
                                          apr_pool_cleanup_null,
                                          r->connection->pool);
                } else if (need_truncate) {
                    need_truncate = 0;
                    apr_file_trunc(fd, 0);
                    cur_pos = 0;
                }
                // Write request to tmp file
                if ((rv =
                     apr_file_write_full(fd, (const void *) data, len,
                                         &wrote_len)) != APR_SUCCESS
                    || len != wrote_len) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING,
                                 apr_get_os_error(), main_server,
                                 "mod_fcgid: can't write tmp file for stdin request");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                // Create file bucket
                bucket_stdin =
                    apr_bucket_file_create(fd, cur_pos, len, r->pool,
                                           r->connection->bucket_alloc);
                cur_pos += len;
            } else {
                if (APR_BUCKET_IS_HEAP(bucket_input))
                    apr_bucket_copy(bucket_input, &bucket_stdin);
                else {
                    /* mod_ssl have a bug? */
                    char *pcopydata =
                        apr_bucket_alloc(len, r->connection->bucket_alloc);
                    memcpy(pcopydata, data, len);
                    bucket_stdin =
                        apr_bucket_heap_create(pcopydata, len,
                                               apr_bucket_free,
                                               r->connection->
                                               bucket_alloc);
                }
            }

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
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_header);

    /* The eos bucket now */
    bucket_eos = apr_bucket_eos_create(r->connection->bucket_alloc);
    if (!bucket_eos) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_os_error(),
                     main_server,
                     "mod_fcgid: can't alloc memory for eos bucket");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_BRIGADE_INSERT_TAIL(output_brigade, bucket_eos);

    /* Bridge the request */
    return handle_request(r, role, argv0, wrapper_conf, output_brigade);
}
