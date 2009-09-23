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

#ifndef FCGID_CONF_H
#define FCGID_CONF_H

#include "apr_general.h" /* stringify */

#define MODFCGID_COPYRIGHT \
  "Copyright 2009 The Apache Software Foundation."

#define MODFCGID_VERSION_MAJOR  2
#define MODFCGID_VERSION_MINOR  3
#define MODFCGID_VERSION_SUBVER 2
#define MODFCGID_VERSION_DEV    1

#if MODFCGID_VERSION_DEV
#define MODFCGID_VERSION_DEVSTR "-dev"
#else
#define MODFCGID_VERSION_DEVSTR ""
#endif

#define MODFCGID_REVISION      APR_STRINGIFY(MODFCGID_VERSION_MAJOR) \
                           "." APR_STRINGIFY(MODFCGID_VERSION_MINOR) \
                           "." APR_STRINGIFY(MODFCGID_VERSION_SUBVER)
#define MODFCGID_VERSION       MODFCGID_REVISION MODFCGID_VERSION_DEVSTR

#define MODFCGID_PRODUCT       "mod_fcgid/" MODFCGID_VERSION

#ifndef VERSION_ONLY

#include "apr_user.h"
#include "fcgid_global.h"

typedef struct {
    char path[_POSIX_PATH_MAX];
    apr_ino_t inode;
    apr_dev_t deviceid;
    apr_size_t share_group_id;
} auth_conf;

typedef struct {
    char args[_POSIX_PATH_MAX];
    apr_ino_t inode;
    apr_dev_t deviceid;
    apr_size_t share_group_id;
    int virtual;
} fcgid_wrapper_conf;

typedef struct {
    /* global only */
    int busy_scan_interval;
    int busy_timeout;
    int max_class_process_count;
    int min_class_process_count;
    int error_scan_interval;
    int idle_scan_interval;
    int idle_timeout;
    int max_process_count;
    int php_fix_pathinfo_enable;
    int proc_lifetime;
    char *shmname_path;
    char *sockname_prefix;
    int spawn_score;
    int spawnscore_uplimit;
    int termination_score;
    int time_score;
    int zombie_scan_interval;
    /* global or vhost
     * scalar values have corresponding _set field to aid merging
     */
    apr_table_t *default_init_env;
    int ipc_comm_timeout;
    int ipc_comm_timeout_set;
    int ipc_connect_timeout;
    int ipc_connect_timeout_set;
    int max_mem_request_len;
    int max_mem_request_len_set;
    apr_off_t max_request_len;
    int max_request_len_set;
    int max_requests_per_process;
    int max_requests_per_process_set;
    int output_buffersize;
    int output_buffersize_set;
    apr_array_header_t *pass_headers;
} fcgid_server_conf;

typedef struct {
    /* scalar values have corresponding _set field to aid merging */

    /* wrapper */
    apr_hash_t *wrapper_info_hash;

    /* authenticator */
    auth_conf *authenticator_info;
    int authenticator_authoritative;
    int authenticator_authoritative_set;

    /* authorizer */
    auth_conf *authorizer_info;
    int authorizer_authoritative;
    int authorizer_authoritative_set;

    /* access check */
    auth_conf *access_info;
    int access_authoritative;
    int access_authoritative_set;
} fcgid_dir_conf;

void *create_fcgid_server_config(apr_pool_t * p, server_rec * s);
void *merge_fcgid_server_config(apr_pool_t * p, void *basev,
                                void *overridesv);

void *create_fcgid_dir_config(apr_pool_t * p, char *dummy);
void *merge_fcgid_dir_config(apr_pool_t * p, void *basev,
                             void *overridesv);

const char *set_idle_timeout(cmd_parms * cmd, void *dummy,
                             const char *arg);

const char *set_idle_scan_interval(cmd_parms * cmd, void *dummy,
                                   const char *arg);

const char *set_busy_timeout(cmd_parms * cmd, void *dummy,
                             const char *arg);

const char *set_busy_scan_interval(cmd_parms * cmd, void *dummy,
                                   const char *arg);

const char *set_proc_lifetime(cmd_parms * cmd, void *dummy,
                              const char *arg);

const char *set_error_scan_interval(cmd_parms * cmd, void *dummy,
                                    const char *arg);

const char *set_zombie_scan_interval(cmd_parms * cmd, void *dummy,
                                     const char *arg);

const char *set_socketpath(cmd_parms * cmd, void *dummy, const char *arg);

const char *set_shmpath(cmd_parms * cmd, void *dummy, const char *arg);

const char *set_time_score(cmd_parms * cmd, void *dummy, const char *arg);

const char *set_max_request_len(cmd_parms * cmd, void *dummy,
                                const char *arg);

const char *set_max_mem_request_len(cmd_parms * cmd, void *dummy,
                                    const char *arg);

const char *set_termination_score(cmd_parms * cmd, void *dummy,
                                  const char *arg);

const char *set_spawn_score(cmd_parms * cmd, void *dummy, const char *arg);

const char *set_spawnscore_uplimit(cmd_parms * cmd, void *dummy,
                                   const char *arg);

const char *set_max_process(cmd_parms * cmd, void *dummy, const char *arg);

const char *set_max_class_process(cmd_parms * cmd, void *dummy,
                                  const char *arg);

const char *set_min_class_process(cmd_parms * cmd, void *dummy,
                                  const char *arg);

const char *set_ipc_connect_timeout(cmd_parms * cmd, void *dummy,
                                    const char *arg);

const char *set_ipc_comm_timeout(cmd_parms * cmd, void *dummy,
                                 const char *arg);

const char *set_output_buffersize(cmd_parms * cmd, void *dummy,
                                  const char *arg);

const char *add_default_env_vars(cmd_parms * cmd, void *sconf,
                                 const char *name, const char *value);
apr_table_t *get_default_env_vars(request_rec * r);

const char *add_pass_headers(cmd_parms * cmd, void *sconf,
                             const char *name);

apr_array_header_t *get_pass_headers(request_rec * r);

const char *set_wrapper_config(cmd_parms * cmd, void *dummy,
                               const char *wrapper, const char *extension, const char* virtual);
fcgid_wrapper_conf *get_wrapper_info(const char *cgipath, request_rec * r);

const char *set_authenticator_info(cmd_parms * cmd, void *config,
                                   const char *arg);
const char *set_authenticator_authoritative(cmd_parms * cmd,
                                            void *config, int arg);
auth_conf *get_authenticator_info(request_rec * r, int *authoritative);

const char *set_authorizer_info(cmd_parms * cmd, void *config,
                                const char *arg);
const char *set_authorizer_authoritative(cmd_parms * cmd,
                                         void *config, int arg);
auth_conf *get_authorizer_info(request_rec * r, int *authoritative);

const char *set_access_info(cmd_parms * cmd, void *config,
                            const char *arg);
const char *set_access_authoritative(cmd_parms * cmd,
                                     void *config, int arg);
auth_conf *get_access_info(request_rec * r, int *authoritative);

const char *set_php_fix_pathinfo_enable(cmd_parms * cmd, void *dummy,
                                        const char *arg);

const char *set_max_requests_per_process(cmd_parms * cmd, void *dummy,
                                         const char *arg);

AP_DECLARE_DATA extern module fcgid_module;

#endif

#endif
