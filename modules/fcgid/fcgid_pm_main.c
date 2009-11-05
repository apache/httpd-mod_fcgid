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

/* For DEFAULT_PATH */
#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"

#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_proctbl.h"
#include "fcgid_proc.h"
#include "fcgid_spawn_ctl.h"

#define HAS_GRACEFUL_KILL "Gracefulkill"

static void
link_node_to_list(server_rec * main_server,
                  fcgid_procnode * header,
                  fcgid_procnode * node, fcgid_procnode * table_array)
{
    proctable_pm_lock(main_server);
    node->next_index = header->next_index;
    header->next_index = node - table_array;
    proctable_pm_unlock(main_server);
}

static apr_time_t lastidlescan = 0;
static void scan_idlelist(server_rec * main_server)
{
    /* 
       Scan the idle list 
       1. move all processes idle timeout to error list
       2. move all processes lifetime expired to error list
     */
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *error_list_header;
    fcgid_procnode *proc_table;
    apr_time_t last_active_time, start_time;
    apr_time_t now = apr_time_now();
    int idle_timeout, proc_lifetime;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    /* Should I check the idle list now? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lastidlescan) <=
        sconf->idle_scan_interval)
        return;
    lastidlescan = now;

    /* Check the list */
    proc_table = proctable_get_table_array();
    previous_node = proctable_get_idle_list();
    error_list_header = proctable_get_error_list();

    proctable_pm_lock(main_server);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];
        last_active_time = current_node->last_active_time;
        start_time = current_node->start_time;
        idle_timeout = current_node->cmdopts.idle_timeout;
        proc_lifetime = current_node->cmdopts.proc_lifetime;
        if (((idle_timeout && 
              (apr_time_sec(now) - apr_time_sec(last_active_time) > idle_timeout))
             || (proc_lifetime && 
              (apr_time_sec(now) - apr_time_sec(start_time) > proc_lifetime)))
            && is_kill_allowed(main_server, current_node)) {
            /* Set die reason for log */
            if (idle_timeout &&
                (apr_time_sec(now) - apr_time_sec(last_active_time) > idle_timeout))
                current_node->diewhy = FCGID_DIE_IDLE_TIMEOUT;
            else if (proc_lifetime && 
                     (apr_time_sec(now) - apr_time_sec(start_time) > proc_lifetime))
                current_node->diewhy = FCGID_DIE_LIFETIME_EXPIRED;

            /* Unlink from idle list */
            previous_node->next_index = current_node->next_index;

            /* Link to error list */
            current_node->next_index = error_list_header->next_index;
            error_list_header->next_index = current_node - proc_table;
        } else
            previous_node = current_node;

        current_node = next_node;
    }
    proctable_pm_unlock(main_server);
}

static apr_time_t lastbusyscan = 0;
static void scan_busylist(server_rec * main_server)
{
    /*
       Scan the busy list
       1. move all expired node to error list
     */
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *error_list_header;
    fcgid_procnode *proc_table;
    apr_time_t last_active_time;
    apr_time_t now = apr_time_now();
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    /* Should I check the busy list? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lastbusyscan) <=
        sconf->busy_scan_interval)
        return;
    lastbusyscan = now;

    /* Check the list */
    proc_table = proctable_get_table_array();
    previous_node = proctable_get_busy_list();
    error_list_header = proctable_get_error_list();

    proctable_pm_lock(main_server);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        last_active_time = current_node->last_active_time;
        /* FIXME See BZ #47483 */
        if (apr_time_sec(now) - apr_time_sec(last_active_time) >
            (current_node->cmdopts.busy_timeout + 10)) {
            /* Set dir reason for log */
            current_node->diewhy = FCGID_DIE_BUSY_TIMEOUT;

            /* Unlink from busy list */
            previous_node->next_index = current_node->next_index;

            /* Link to error list */
            current_node->next_index = error_list_header->next_index;
            error_list_header->next_index = current_node - proc_table;
        } else
            previous_node = current_node;

        current_node = next_node;
    }
    proctable_pm_unlock(main_server);
}

static apr_time_t lastzombiescan = 0;
static void scan_idlelist_zombie(server_rec * main_server)
{
    /* 
       Scan the idle list 
       1. pick up the node for scan(now-last_activ>g_zombie_scan_interval)
       2. check if it's zombie process
       3. if it's zombie process, wait() and return to free list
       4. return to idle list if it's not zombie process
     */
    pid_t thepid;
    fcgid_procnode *previous_node, *current_node, *next_node;
    fcgid_procnode *check_list_header;
    fcgid_procnode *proc_table;
    apr_time_t last_active_time;
    apr_time_t now = apr_time_now();
    fcgid_procnode temp_header;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    memset(&temp_header, 0, sizeof(temp_header));

    /* Should I check zombie processes in idle list now? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lastzombiescan) <=
        sconf->zombie_scan_interval)
        return;
    lastzombiescan = now;

    /* 
       Check the list 
     */
    proc_table = proctable_get_table_array();
    previous_node = proctable_get_idle_list();
    check_list_header = &temp_header;

    proctable_pm_lock(main_server);
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        /* Is it time for zombie check? */
        last_active_time = current_node->last_active_time;
        if (apr_time_sec(now) - apr_time_sec(last_active_time) >
            sconf->zombie_scan_interval) {
            /* Unlink from idle list */
            previous_node->next_index = current_node->next_index;

            /* Link to check list */
            current_node->next_index = check_list_header->next_index;
            check_list_header->next_index = current_node - proc_table;
        } else
            previous_node = current_node;

        current_node = next_node;
    }
    proctable_pm_unlock(main_server);

    /* 
       Now check every node in check list
       1) If it's zombie process, wait() and return to free list
       2) If it's not zombie process, link it to the tail of idle list
     */
    previous_node = check_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        /* Is it zombie process? */
        thepid = current_node->proc_id->pid;
        if (proc_wait_process(main_server, current_node) == APR_CHILD_DONE) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                         "mod_fcgid: cleanup zombie process %"
                         APR_PID_T_FMT, thepid);

            /* Unlink from check list */
            previous_node->next_index = current_node->next_index;

            /* Link to free list */
            link_node_to_list(main_server, proctable_get_free_list(),
                              current_node, proc_table);
        } else
            previous_node = current_node;

        current_node = next_node;
    }

    /* 
       Now link the check list back to the tail of idle list 
     */
    if (check_list_header->next_index) {
        proctable_pm_lock(main_server);
        previous_node = proctable_get_idle_list();
        current_node = &proc_table[previous_node->next_index];

        /* Find the tail of idle list */
        while (current_node != proc_table) {
            previous_node = current_node;
            current_node = &proc_table[current_node->next_index];
        }

        /* Link check list to the tail of idle list */
        previous_node->next_index = check_list_header->next_index;
        proctable_pm_unlock(main_server);
    }
}

static apr_time_t lasterrorscan = 0;
static void scan_errorlist(server_rec * main_server)
{
    /* 
       kill() and wait() every node in error list
       put them back to free list after that
     */
    void *dummy;
    fcgid_procnode *previous_node, *current_node, *next_node;
    apr_time_t now = apr_time_now();
    fcgid_procnode *error_list_header = proctable_get_error_list();
    fcgid_procnode *free_list_header = proctable_get_free_list();
    fcgid_procnode *proc_table = proctable_get_table_array();
    fcgid_procnode temp_error_header;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    /* Should I check the busy list? */
    if (procmgr_must_exit()
        || apr_time_sec(now) - apr_time_sec(lasterrorscan) <=
        sconf->error_scan_interval)
        return;
    lasterrorscan = now;

    /* Try wait dead processes, restore to free list */
    /* Note: I can't keep the lock during the scan */
    proctable_pm_lock(main_server);
    temp_error_header.next_index = error_list_header->next_index;
    error_list_header->next_index = 0;
    proctable_pm_unlock(main_server);

    previous_node = &temp_error_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        next_node = &proc_table[current_node->next_index];

        if (proc_wait_process(main_server, current_node) !=
            APR_CHILD_NOTDONE) {
            /* Unlink from error list */
            previous_node->next_index = current_node->next_index;

            /* Link to free list */
            current_node->next_index = free_list_header->next_index;
            free_list_header->next_index = current_node - proc_table;
        } else
            previous_node = current_node;

        current_node = next_node;
    }

    /* Kill the left processes, wait() them in the next round */
    for (current_node = &proc_table[temp_error_header.next_index];
         current_node != proc_table;
         current_node = &proc_table[current_node->next_index]) {
        /* Try gracefully first */
        dummy = NULL;
        apr_pool_userdata_get(&dummy, HAS_GRACEFUL_KILL,
                              current_node->proc_pool);
        if (!dummy) {
            proc_kill_gracefully(current_node, main_server);
            apr_pool_userdata_set("set", HAS_GRACEFUL_KILL,
                                  apr_pool_cleanup_null,
                                  current_node->proc_pool);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                         "mod_fcgid: process %" APR_PID_T_FMT
                         " graceful kill fail, sending SIGKILL",
                         current_node->proc_id->pid);
            proc_kill_force(current_node, main_server);
        }
    }

    /* Link the temp error list back */
    proctable_pm_lock(main_server);
    /* Find the tail of error list */
    previous_node = error_list_header;
    current_node = &proc_table[previous_node->next_index];
    while (current_node != proc_table) {
        previous_node = current_node;
        current_node = &proc_table[current_node->next_index];
    }
    previous_node->next_index = temp_error_header.next_index;
    proctable_pm_unlock(main_server);
}

static void kill_all_subprocess(server_rec * main_server)
{
    size_t i;
    int exitcode;
    apr_exit_why_e exitwhy;
    fcgid_procnode *proc_table = proctable_get_table_array();

    /* Kill gracefully */
    for (i = 0; i < proctable_get_table_size(); i++) {
        if (proc_table[i].proc_pool)
            proc_kill_gracefully(&proc_table[i], main_server);
    }
    apr_sleep(apr_time_from_sec(1));

    /* Kill with SIGKILL if it doesn't work */
    for (i = 0; i < proctable_get_table_size(); i++) {
        if (proc_table[i].proc_pool) {
            if (apr_proc_wait(proc_table[i].proc_id, &exitcode, &exitwhy,
                              APR_NOWAIT) != APR_CHILD_NOTDONE) {
                proc_table[i].diewhy = FCGID_DIE_SHUTDOWN;
                proc_print_exit_info(&proc_table[i], exitcode, exitwhy,
                                     main_server);
                apr_pool_destroy(proc_table[i].proc_pool);
                proc_table[i].proc_pool = NULL;
            } else
                proc_kill_force(&proc_table[i], main_server);
        }
    }

    /* Wait again */
    for (i = 0; i < proctable_get_table_size(); i++) {
        if (proc_table[i].proc_pool) {
            if (apr_proc_wait(proc_table[i].proc_id, &exitcode, &exitwhy,
                              APR_WAIT) != APR_CHILD_NOTDONE) {
                proc_table[i].diewhy = FCGID_DIE_SHUTDOWN;
                proc_print_exit_info(&proc_table[i], exitcode, exitwhy,
                                     main_server);
                apr_pool_destroy(proc_table[i].proc_pool);
                proc_table[i].proc_pool = NULL;
            }
        }
    }
}

/* This should be proposed as a stand-alone improvement to the httpd module,
 * either in the arch/ platform-specific modules or util_script.c from whence
 * it came.
 */
static void default_proc_env(apr_table_t *e)
{
    const char *env_temp;

    if (!(env_temp = getenv("PATH"))) {
        env_temp = DEFAULT_PATH;
    }
    apr_table_addn(e, "PATH", env_temp);

#ifdef WIN32
    if ((env_temp = getenv("SYSTEMROOT"))) {
        apr_table_addn(e, "SYSTEMROOT", env_temp);
    }
    if ((env_temp = getenv("COMSPEC"))) {
        apr_table_addn(e, "COMSPEC", env_temp);
    }
    if ((env_temp = getenv("PATHEXT"))) {
        apr_table_addn(e, "PATHEXT", env_temp);
    }
    if ((env_temp = getenv("WINDIR"))) {
        apr_table_addn(e, "WINDIR", env_temp);
    }
#elif defined(OS2)
    if ((env_temp = getenv("COMSPEC")) != NULL) {
        apr_table_addn(e, "COMSPEC", env_temp);
    }
    if ((env_temp = getenv("ETC")) != NULL) {
        apr_table_addn(e, "ETC", env_temp);
    }
    if ((env_temp = getenv("DPATH")) != NULL) {
        apr_table_addn(e, "DPATH", env_temp);
    }
    if ((env_temp = getenv("PERLLIB_PREFIX")) != NULL) {
        apr_table_addn(e, "PERLLIB_PREFIX", env_temp);
    }
#elif defined(BEOS)
    if ((env_temp = getenv("LIBRARY_PATH")) != NULL) {
        apr_table_addn(e, "LIBRARY_PATH", env_temp);
    }
#elif defined (AIX)
    if ((env_temp = getenv("LIBPATH"))) {
        apr_table_addn(e, "LIBPATH", env_temp);
    }
#else
/* DARWIN, HPUX vary depending on circumstance */
#if defined (DARWIN)
    if ((env_temp = getenv("DYLD_LIBRARY_PATH"))) {
        apr_table_addn(e, "DYLD_LIBRARY_PATH", env_temp);
    }
#elif defined (HPUX11) || defined (HPUX10) || defined (HPUX)
    if ((env_temp = getenv("SHLIB_PATH"))) {
        apr_table_addn(e, "SHLIB_PATH", env_temp);
    }
#endif
    if ((env_temp = getenv("LD_LIBRARY_PATH"))) {
        apr_table_addn(e, "LD_LIBRARY_PATH", env_temp);
    }
#endif
}
/* End of common to util_script.c */

static void
fastcgi_spawn(fcgid_command * command, server_rec * main_server,
              apr_pool_t * configpool)
{
    fcgid_procnode *free_list_header, *proctable_array,
        *procnode, *idle_list_header;
    fcgid_proc_info procinfo;
    apr_status_t rv;
    int i;

    free_list_header = proctable_get_free_list();
    idle_list_header = proctable_get_idle_list();
    proctable_array = proctable_get_table_array();

    /* Apply a slot from free list */
    proctable_pm_lock(main_server);
    if (free_list_header->next_index == 0) {
        proctable_pm_unlock(main_server);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
                     "mod_fcgid: too much processes, please increase FCGID_MAX_APPLICATION");
        return;
    }
    procnode = &proctable_array[free_list_header->next_index];
    free_list_header->next_index = procnode->next_index;
    procnode->next_index = 0;
    proctable_pm_unlock(main_server);

    /* Prepare to spawn */
    procnode->deviceid = command->deviceid;
    procnode->inode = command->inode;
    procnode->share_grp_id = command->share_grp_id;
    procnode->virtualhost = command->virtualhost;
    procnode->uid = command->uid;
    procnode->gid = command->gid;
    procnode->start_time = procnode->last_active_time = apr_time_now();
    procnode->requests_handled = 0;
    procnode->diewhy = FCGID_DIE_KILLSELF;
    procnode->proc_pool = NULL;
    procnode->cmdopts = command->cmdopts;

    procinfo.cgipath = command->cgipath;
    procinfo.configpool = configpool;
    procinfo.main_server = main_server;
    procinfo.uid = command->uid;
    procinfo.gid = command->gid;
    procinfo.userdir = command->userdir;
    if ((rv = apr_pool_create(&procnode->proc_pool, configpool)) != APR_SUCCESS
        || (procinfo.proc_environ =
            apr_table_make(procnode->proc_pool, INITENV_CNT)) == NULL) {
        /* Link the node back to free list in this case */
        if (procnode->proc_pool)
            apr_pool_destroy(procnode->proc_pool);
        link_node_to_list(main_server, free_list_header, procnode,
                          proctable_array);

        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, main_server,
                     "mod_fcgid: can't create pool for process");
        return;
    }
    /* Set up longer, system defaults before falling into parsing fixed-limit
     * request-by-request variables, so if any are overriden, they preempt
     * any system default assumptions
     */
    default_proc_env(procinfo.proc_environ);        
    for (i = 0; i < INITENV_CNT; i++) {
        if (command->cmdenv.initenv_key[i][0] == '\0')
            break;
        apr_table_set(procinfo.proc_environ, command->cmdenv.initenv_key[i],
                      command->cmdenv.initenv_val[i]);
    }

    /* Spawn the process now */
    /* XXX Spawn uses wrapper_cmdline, but log uses cgipath ? */
    if ((rv =
        proc_spawn_process(command->wrapper_cmdline, &procinfo,
                           procnode)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, main_server,
                     "mod_fcgid: spawn process %s error",
                     command->cgipath);

        apr_pool_destroy(procnode->proc_pool);
        link_node_to_list(main_server, free_list_header,
                          procnode, proctable_array);
        return;
    } else {
        /* The job done */
        link_node_to_list(main_server, idle_list_header,
                          procnode, proctable_array);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
                     "mod_fcgid: server %s:%s(%" APR_PID_T_FMT ") started",
                     command->virtualhost, command->cgipath, procnode->proc_id->pid);
        register_spawn(main_server, procnode);
    }
}

apr_status_t pm_main(server_rec * main_server, apr_pool_t * configpool)
{
    fcgid_command command;

    while (1) {
        if (procmgr_must_exit())
            break;

        /* Wait for command */
        if (procmgr_peek_cmd(&command, main_server) == APR_SUCCESS) {
            if (is_spawn_allowed(main_server, &command))
                fastcgi_spawn(&command, main_server, configpool);

            procmgr_finish_notify(main_server);
        }

        /* Move matched node to error list */
        scan_idlelist_zombie(main_server);
        scan_idlelist(main_server);
        scan_busylist(main_server);

        /* Kill() and wait() nodes in error list */
        scan_errorlist(main_server);
    }

    /* Stop all processes */
    kill_all_subprocess(main_server);

    return APR_SUCCESS;
}
