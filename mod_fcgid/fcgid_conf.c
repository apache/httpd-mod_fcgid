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

#include "ap_config.h"
#include "ap_mmn.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_tables.h"
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
#define DEFAULT_SHM_PATH "logs/fcgid_shm"
#define DEFAULT_SPAWNSOCRE_UPLIMIT 10
#define DEFAULT_SPAWN_SCORE 1
#define DEFAULT_TERMINATION_SCORE 2
#define DEFAULT_TIME_SCORE 1
#define DEFAULT_MAX_PROCESS_COUNT 1000
#define DEFAULT_MAX_CLASS_PROCESS_COUNT 100
#define DEFAULT_MIN_CLASS_PROCESS_COUNT 3
#define DEFAULT_IPC_CONNECT_TIMEOUT 3
#define DEFAULT_IPC_COMM_TIMEOUT 40
#define DEFAULT_OUTPUT_BUFFERSIZE 65536
#define DEFAULT_MAX_REQUESTS_PER_PROCESS -1
#define DEFAULT_MAX_REQUEST_LEN (1024*1024*1024)    /* 1G */
#define DEFAULT_MAX_MEM_REQUEST_LEN (1024*64)   /* 64k */

static void init_server_config(apr_pool_t * p, fcgid_server_conf * config)
{
    config->default_init_env = NULL;
    config->pass_headers = NULL;
    config->sockname_prefix =
        ap_server_root_relative(p, DEFAULT_SOCKET_PREFIX);
    config->shmname_path = ap_server_root_relative(p, DEFAULT_SHM_PATH);
    config->idle_timeout = DEFAULT_IDLE_TIMEOUT;
    config->idle_scan_interval = DEFAULT_IDLE_SCAN_INTERVAL;
    config->busy_scan_interval = DEFAULT_BUSY_SCAN_INTERVAL;
    config->proc_lifetime = DEFAULT_PROC_LIFETIME;
    config->error_scan_interval = DEFAULT_ERROR_SCAN_INTERVAL;
    config->zombie_scan_interval = DEFAULT_ZOMBIE_SCAN_INTERVAL;
    config->spawn_score = DEFAULT_SPAWN_SCORE;
    config->spawnscore_uplimit = DEFAULT_SPAWNSOCRE_UPLIMIT;
    config->termination_score = DEFAULT_TERMINATION_SCORE;
    config->time_score = DEFAULT_TIME_SCORE;
    config->max_class_process_count = DEFAULT_MAX_CLASS_PROCESS_COUNT;
    config->min_class_process_count = DEFAULT_MIN_CLASS_PROCESS_COUNT;
    config->max_process_count = DEFAULT_MAX_PROCESS_COUNT;
    config->output_buffersize = DEFAULT_OUTPUT_BUFFERSIZE;
    config->ipc_comm_timeout = DEFAULT_IPC_COMM_TIMEOUT;
    config->ipc_connect_timeout = DEFAULT_IPC_CONNECT_TIMEOUT;
    config->busy_timeout = DEFAULT_BUSY_TIMEOUT;
    config->php_fix_pathinfo_enable = 0;
    config->max_requests_per_process = DEFAULT_MAX_REQUESTS_PER_PROCESS;
    config->max_request_len = DEFAULT_MAX_REQUEST_LEN;
    config->max_mem_request_len = DEFAULT_MAX_MEM_REQUEST_LEN;
}

void *create_fcgid_server_config(apr_pool_t * p, server_rec * s)
{
    fcgid_server_conf *config = apr_pcalloc(p, sizeof(*config));

    init_server_config(p, config);
    return config;
}

void *merge_fcgid_server_config(apr_pool_t * p, void *basev, void *locv)
{
    int i;
    fcgid_server_conf *merged_config =
        (fcgid_server_conf *) apr_pcalloc(p, sizeof(fcgid_server_conf));
    fcgid_server_conf *base = (fcgid_server_conf *) basev;
    fcgid_server_conf *local = (fcgid_server_conf *) locv;
    const apr_array_header_t *baseenv_array, *locenv_array;

    init_server_config(p, merged_config);

    /* Merge environment variables */
    baseenv_array = apr_table_elts(base->default_init_env);
    locenv_array = apr_table_elts(local->default_init_env);

    if (baseenv_array != NULL || locenv_array != NULL) {
        merged_config->default_init_env = apr_table_make(p, 20);

        if (locenv_array != NULL) {
            const apr_table_entry_t *locenv_entry =
                (apr_table_entry_t *) locenv_array->elts;

            for (i = 0; i < locenv_array->nelts; ++i) {
                apr_table_set(merged_config->default_init_env,
                              locenv_entry[i].key, locenv_entry[i].val);
            }
        }

        if (baseenv_array != NULL) {
            const apr_table_entry_t *baseenv_entry =
                (apr_table_entry_t *) baseenv_array->elts;

            for (i = 0; i < baseenv_array->nelts; ++i) {
                if (apr_table_get
                    (merged_config->default_init_env,
                     baseenv_entry[i].key))
                    continue;
                apr_table_set(merged_config->default_init_env,
                              baseenv_entry[i].key, baseenv_entry[i].val);
            }
        }
    }

    /* Merge pass headers */
    if (local->pass_headers != NULL || base->pass_headers != NULL) {
        merged_config->pass_headers =
            apr_array_make(p, 10, sizeof(const char *));
        if (base->pass_headers != NULL)
            apr_array_cat(merged_config->pass_headers, base->pass_headers);
        if (local->pass_headers != NULL)
            apr_array_cat(merged_config->pass_headers,
                          local->pass_headers);
    }
    // Merge the other configurations
    merged_config->ipc_comm_timeout = base->ipc_comm_timeout;
    merged_config->ipc_comm_timeout = local->ipc_comm_timeout;

    merged_config->ipc_connect_timeout = base->ipc_connect_timeout;
    merged_config->ipc_connect_timeout = local->ipc_connect_timeout;

    merged_config->busy_timeout = base->busy_timeout;
    merged_config->busy_timeout = local->busy_timeout;

    return merged_config;
}

void *create_fcgid_dir_config(apr_pool_t * p, char *dummy)
{
    fcgid_dir_conf *config = apr_pcalloc(p, sizeof(fcgid_dir_conf));

    config->wrapper_info_hash = apr_hash_make(p);
    config->authenticator_info = NULL;
    config->authenticator_authoritative = 1;
    config->authorizer_info = NULL;
    config->authorizer_authoritative = 1;
    config->access_info = NULL;
    config->access_authoritative = 1;
    return (void *) config;
}

const char *set_idle_timeout(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->idle_timeout = atol(arg);
    return NULL;
}

int get_idle_timeout(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->idle_timeout : DEFAULT_IDLE_TIMEOUT;
}

const char *set_idle_scan_interval(cmd_parms * cmd, void *dummy,
                                   const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->idle_scan_interval = atol(arg);
    return NULL;
}

int get_idle_scan_interval(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->idle_scan_interval : DEFAULT_IDLE_TIMEOUT;
}

const char *set_busy_timeout(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->busy_timeout = atol(arg);
    return NULL;
}

int get_busy_timeout(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->busy_timeout : DEFAULT_BUSY_TIMEOUT;
}

const char *set_busy_scan_interval(cmd_parms * cmd, void *dummy,
                                   const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->busy_scan_interval = atol(arg);
    return NULL;
}

int get_busy_scan_interval(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        busy_scan_interval : DEFAULT_BUSY_SCAN_INTERVAL;
}

const char *set_proc_lifetime(cmd_parms * cmd, void *dummy,
                              const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->proc_lifetime = atol(arg);
    return NULL;
}

int get_proc_lifetime(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->proc_lifetime : DEFAULT_PROC_LIFETIME;
}

const char *set_error_scan_interval(cmd_parms * cmd, void *dummy,
                                    const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->error_scan_interval = atol(arg);
    return NULL;
}

int get_error_scan_interval(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        error_scan_interval : DEFAULT_ERROR_SCAN_INTERVAL;
}

const char *set_zombie_scan_interval(cmd_parms * cmd, void *dummy,
                                     const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->zombie_scan_interval = atol(arg);
    return NULL;
}

int get_zombie_scan_interval(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        zombie_scan_interval : DEFAULT_ZOMBIE_SCAN_INTERVAL;
}

const char *set_socketpath(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->sockname_prefix = ap_server_root_relative(cmd->pool, arg);
    if (!config->sockname_prefix)
        return "Invalid socket path";

    return NULL;
}

const char *get_socketpath(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config->sockname_prefix;
}

const char *set_shmpath(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->shmname_path = ap_server_root_relative(cmd->pool, arg);
    if (!config->shmname_path)
        return "Invalid shmname path";

    return NULL;
}

const char *get_shmpath(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config->shmname_path;
}

const char *set_spawnscore_uplimit(cmd_parms * cmd, void *dummy,
                                   const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->spawnscore_uplimit = atol(arg);
    return NULL;
}

int get_spawnscore_uplimit(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        spawnscore_uplimit : DEFAULT_SPAWNSOCRE_UPLIMIT;
}

const char *set_max_request_len(cmd_parms * cmd, void *dummy,
                                const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->max_request_len = atol(arg);
    return NULL;
}

int get_max_request_len(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->max_request_len : DEFAULT_MAX_REQUEST_LEN;
}

const char *set_max_mem_request_len(cmd_parms * cmd, void *dummy,
                                    const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->max_mem_request_len = atol(arg);
    return NULL;
}

int get_max_mem_request_len(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        max_mem_request_len : DEFAULT_MAX_MEM_REQUEST_LEN;
}

const char *set_spawn_score(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->spawn_score = atol(arg);
    return NULL;
}

int get_spawn_score(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->spawn_score : DEFAULT_SPAWN_SCORE;
}

const char *set_time_score(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->time_score = atol(arg);
    return NULL;
}

int get_time_score(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->time_score : DEFAULT_TIME_SCORE;
}

const char *set_termination_score(cmd_parms * cmd, void *dummy,
                                  const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->termination_score = atol(arg);
    return NULL;
}

int get_termination_score(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->termination_score : DEFAULT_TERMINATION_SCORE;
}

const char *set_max_process(cmd_parms * cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->max_process_count = atol(arg);
    return NULL;
}

int get_max_process(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->max_process_count : DEFAULT_MAX_PROCESS_COUNT;
}

const char *set_output_buffersize(cmd_parms * cmd, void *dummy,
                                  const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->output_buffersize = atol(arg);
    return NULL;
}

int get_output_buffersize(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->output_buffersize : DEFAULT_OUTPUT_BUFFERSIZE;
}

const char *set_max_class_process(cmd_parms * cmd, void *dummy,
                                  const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->max_class_process_count = atol(arg);
    return NULL;
}

int get_max_class_process(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        max_class_process_count : DEFAULT_MAX_CLASS_PROCESS_COUNT;
}

const char *set_min_class_process(cmd_parms * cmd, void *dummy,
                                  const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->min_class_process_count = atol(arg);
    return NULL;
}

int get_min_class_process(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        min_class_process_count : DEFAULT_MIN_CLASS_PROCESS_COUNT;
}

const char *set_php_fix_pathinfo_enable(cmd_parms * cmd, void *dummy,
                                        const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->php_fix_pathinfo_enable = atol(arg);
    return NULL;
}

const char *set_max_requests_per_process(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->max_requests_per_process = atol(arg);
    return NULL;
}

int get_max_requests_per_process(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        max_requests_per_process : DEFAULT_MAX_REQUESTS_PER_PROCESS;
}

int get_php_fix_pathinfo_enable(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->php_fix_pathinfo_enable : 0;
}

const char *set_ipc_connect_timeout(cmd_parms * cmd, void *dummy,
                                    const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->ipc_connect_timeout = atol(arg);
    return NULL;
}

int get_ipc_connect_timeout(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->
        ipc_connect_timeout : DEFAULT_IPC_CONNECT_TIMEOUT;
}

const char *set_ipc_comm_timeout(cmd_parms * cmd, void *dummy,
                                 const char *arg)
{
    server_rec *s = cmd->server;
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    config->ipc_comm_timeout = atol(arg);
    return NULL;
}

int get_ipc_comm_timeout(server_rec * s)
{
    fcgid_server_conf *config =
        ap_get_module_config(s->module_config, &fcgid_module);
    return config ? config->ipc_comm_timeout : DEFAULT_IPC_COMM_TIMEOUT;
}

const char *add_default_env_vars(cmd_parms * cmd, void *dummy,
                                 const char *name, const char *value)
{
    fcgid_server_conf *config =
        ap_get_module_config(cmd->server->module_config, &fcgid_module);;
    if (config->default_init_env == NULL)
        config->default_init_env = apr_table_make(cmd->pool, 20);

    apr_table_set(config->default_init_env, name, value ? value : "");
    return NULL;
}

apr_table_t *get_default_env_vars(request_rec * r)
{
    fcgid_server_conf *config =
        ap_get_module_config(r->server->module_config, &fcgid_module);
    return config->default_init_env;
}

const char *add_pass_headers(cmd_parms * cmd, void *dummy,
                             const char *names)
{
    const char **header;
    fcgid_server_conf *config =
        ap_get_module_config(cmd->server->module_config, &fcgid_module);
    if (config->pass_headers == NULL)
        config->pass_headers =
            apr_array_make(cmd->pool, 10, sizeof(const char *));

    header = (const char **) apr_array_push(config->pass_headers);
    *header = ap_getword_conf(cmd->pool, &names);

    return header ? NULL : "Invalid PassHeaders";
}

apr_array_header_t *get_pass_headers(request_rec * r)
{
    fcgid_server_conf *config =
        ap_get_module_config(r->server->module_config, &fcgid_module);
    return config->pass_headers;
}

const char *set_authenticator_info(cmd_parms * cmd, void *config,
                                   const char *authenticator)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    fcgid_dir_conf *dirconfig = (fcgid_dir_conf *) config;

    /* Is the wrapper exist? */
    if ((rv = apr_stat(&finfo, authenticator, APR_FINFO_NORM,
                       cmd->temp_pool)) != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "can't get authenticator file info: %s, errno: %d",
                            authenticator, apr_get_os_error());
    }

    /* Create the wrapper node */
    dirconfig->authenticator_info =
        apr_pcalloc(cmd->server->process->pconf,
                    sizeof(*dirconfig->authenticator_info));
    if (!dirconfig->authenticator_info)
        return "Can't alloc memory for authenticator_info";
    apr_cpystrn(dirconfig->authenticator_info->path, authenticator,
                _POSIX_PATH_MAX);
    dirconfig->authenticator_info->inode = finfo.inode;
    dirconfig->authenticator_info->deviceid = finfo.device;
    dirconfig->authenticator_info->share_group_id = (apr_size_t) - 1;
    return NULL;
}

const char *set_authenticator_authoritative(cmd_parms * cmd,
                                            void *config, int arg)
{
    fcgid_dir_conf *dirconfig = (fcgid_dir_conf *) config;

    dirconfig->authenticator_authoritative = arg;
    return NULL;
}

auth_conf *get_authenticator_info(request_rec * r, int *authoritative)
{
    fcgid_dir_conf *config =
        ap_get_module_config(r->per_dir_config, &fcgid_module);

    if (config != NULL && config->authenticator_info != NULL) {
        *authoritative = config->authenticator_authoritative;
        return config->authenticator_info;
    }

    return NULL;
}

const char *set_authorizer_info(cmd_parms * cmd, void *config,
                                const char *authorizer)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    fcgid_dir_conf *dirconfig = (fcgid_dir_conf *) config;

    /* Is the wrapper exist? */
    if ((rv = apr_stat(&finfo, authorizer, APR_FINFO_NORM,
                       cmd->temp_pool)) != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "can't get authorizer file info: %s, errno: %d",
                            authorizer, apr_get_os_error());
    }

    /* Create the wrapper node */
    dirconfig->authorizer_info =
        apr_pcalloc(cmd->server->process->pconf,
                    sizeof(*dirconfig->authorizer_info));
    if (!dirconfig->authorizer_info)
        return "Can't alloc memory for authorizer";
    apr_cpystrn(dirconfig->authorizer_info->path, authorizer,
                _POSIX_PATH_MAX);
    dirconfig->authorizer_info->inode = finfo.inode;
    dirconfig->authorizer_info->deviceid = finfo.device;
    dirconfig->authorizer_info->share_group_id = (apr_size_t) - 1;
    return NULL;
}

const char *set_authorizer_authoritative(cmd_parms * cmd,
                                         void *config, int arg)
{
    fcgid_dir_conf *dirconfig = (fcgid_dir_conf *) config;

    dirconfig->authorizer_authoritative = arg;
    return NULL;
}

auth_conf *get_authorizer_info(request_rec * r, int *authoritative)
{
    fcgid_dir_conf *config =
        ap_get_module_config(r->per_dir_config, &fcgid_module);

    if (config != NULL && config->authorizer_info != NULL) {
        *authoritative = config->authorizer_authoritative;
        return config->authorizer_info;
    }

    return NULL;
}

const char *set_access_info(cmd_parms * cmd, void *config,
                            const char *access)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    fcgid_dir_conf *dirconfig = (fcgid_dir_conf *) config;

    /* Is the wrapper exist? */
    if ((rv = apr_stat(&finfo, access, APR_FINFO_NORM,
                       cmd->temp_pool)) != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "can't get authorizer file info: %s, errno: %d",
                            access, apr_get_os_error());
    }

    /* Create the wrapper node */
    dirconfig->access_info =
        apr_pcalloc(cmd->server->process->pconf,
                    sizeof(*dirconfig->access_info));
    if (!dirconfig->access_info)
        return "Can't alloc memory for access";
    apr_cpystrn(dirconfig->access_info->path, access, _POSIX_PATH_MAX);
    dirconfig->access_info->inode = finfo.inode;
    dirconfig->access_info->deviceid = finfo.device;
    dirconfig->access_info->share_group_id = (apr_size_t) - 1;
    return NULL;
}

const char *set_access_authoritative(cmd_parms * cmd,
                                     void *config, int arg)
{
    fcgid_dir_conf *dirconfig = (fcgid_dir_conf *) config;

    dirconfig->access_authoritative = arg;
    return NULL;
}

auth_conf *get_access_info(request_rec * r, int *authoritative)
{
    fcgid_dir_conf *config =
        ap_get_module_config(r->per_dir_config, &fcgid_module);

    if (config != NULL && config->access_info != NULL) {
        *authoritative = config->access_authoritative;
        return config->access_info;
    }

    return NULL;
}

typedef struct {
    apr_hash_t *wrapper_id_hash;
    apr_size_t cur_id;
} wrapper_id_info;

const char *set_wrapper_config(cmd_parms * cmd, void *dirconfig,
                               const char *wrapperpath,
                               const char *extension)
{
    const char *path, *tmp;
    apr_status_t rv;
    apr_finfo_t finfo;
    const char *userdata_key = "fcgid_wrapper_id";
    wrapper_id_info *id_info;
    apr_size_t *wrapper_id;
    fcgid_wrapper_conf *wrapper = NULL;
    fcgid_dir_conf *config = (fcgid_dir_conf *) dirconfig;

    /* Sanity check */
    if (wrapperpath == NULL || extension == NULL
        || *extension != '.' || *(extension + 1) == '\0'
        || ap_strchr_c(extension, '/') || ap_strchr_c(extension, '\\'))
        return "Invalid wrapper file extension";

    /* Get wrapper_id base on wrapperpath */
    {
        void *id_info_vp;
        apr_pool_userdata_get(&id_info_vp, userdata_key,
                              cmd->server->process->pool);
        id_info = id_info_vp;
    }
    
    if (!id_info) {
        id_info =
            apr_pcalloc(cmd->server->process->pool, sizeof(*id_info));
        id_info->wrapper_id_hash =
            apr_hash_make(cmd->server->process->pool);
        apr_pool_userdata_set((const void *) id_info, userdata_key,
                              apr_pool_cleanup_null,
                              cmd->server->process->pool);
    }
    if ((wrapper_id =
         apr_hash_get(id_info->wrapper_id_hash, wrapperpath,
                      strlen(wrapperpath))) == NULL) {
        wrapper_id =
            apr_pcalloc(cmd->server->process->pool, sizeof(*wrapper_id));
        *wrapper_id = id_info->cur_id++;
        apr_hash_set(id_info->wrapper_id_hash, wrapperpath,
                     strlen(wrapperpath), wrapper_id);
    }

    wrapper = apr_pcalloc(cmd->server->process->pconf, sizeof(*wrapper));
    if (!wrapper)
        return "Can't alloc memory for wrapper";

    /* Get wrapper path */
    tmp = wrapperpath;
    path = ap_getword_white(cmd->temp_pool, &tmp);
    if (path == NULL || *path == '\0')
        return "Invalid wrapper config";

    /* Is the wrapper exist? */
    if ((rv = apr_stat(&finfo, path, APR_FINFO_NORM,
                       cmd->temp_pool)) != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "can't get fastcgi file info: %s(%s), errno: %d",
                            wrapperpath, path, apr_get_os_error());
    }

    apr_cpystrn(wrapper->args, wrapperpath, _POSIX_PATH_MAX);
    wrapper->inode = finfo.inode;
    wrapper->deviceid = finfo.device;
    wrapper->share_group_id = *wrapper_id;
    (*wrapper_id)++;

    /* Add the node now */
    apr_hash_set(config->wrapper_info_hash, extension, strlen(extension),
                 wrapper);

    return NULL;
}

fcgid_wrapper_conf *get_wrapper_info(const char *cgipath, request_rec * r)
{
    const char *extension;
    fcgid_wrapper_conf *wrapper;
    fcgid_dir_conf *config =
        ap_get_module_config(r->per_dir_config, &fcgid_module);

    /* Get file name extension */
    extension = ap_strrchr_c(cgipath, '.');
    if (extension == NULL)
        return NULL;

    /* Search file name extension in per_dir_config */
    if (config
        && (wrapper =
            apr_hash_get(config->wrapper_info_hash, extension,
                         strlen(extension))))
        return wrapper;

    return NULL;
}
