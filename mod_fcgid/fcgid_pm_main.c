#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_proctbl.h"
#include "fcgid_proc.h"
#include "fcgid_spawn_ctl.h"
#define HAS_GRACEFUL_KILL "Gracefulkill"

static int g_idle_timeout;
static int g_idle_scan_interval;
static int g_busy_timeout;
static int g_busy_scan_interval;
static int g_proc_lifetime;
static int g_error_scan_interval;
static int g_zombie_scan_interval;

static void
link_node_to_list(server_rec * main_server,
				  fcgid_procnode * header,
				  fcgid_procnode * node, fcgid_procnode * table_array)
{
	safe_lock(main_server);
	node->next_index = header->next_index;
	header->next_index = node - table_array;
	safe_unlock(main_server);
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

	/* Should I check the idle list now? */
	if (procmgr_must_exit()
		|| apr_time_sec(now) - apr_time_sec(lastidlescan) <=
		g_idle_scan_interval)
		return;
	lastidlescan = now;

	/* Check the list */
	proc_table = proctable_get_table_array();
	previous_node = proctable_get_idle_list();
	error_list_header = proctable_get_error_list();

	safe_lock(main_server);
	current_node = &proc_table[previous_node->next_index];
	while (current_node != proc_table) {
		next_node = &proc_table[current_node->next_index];
		last_active_time = current_node->last_active_time;
		start_time = current_node->start_time;
		if ((apr_time_sec(now) - apr_time_sec(last_active_time) >
			 g_idle_timeout
			 || apr_time_sec(now) - apr_time_sec(start_time) >
			 g_proc_lifetime)
			&& is_kill_allowed(current_node)) {
			/* Set die reason for log */
			if (apr_time_sec(now) - apr_time_sec(last_active_time) >
				g_idle_timeout)
				current_node->diewhy = FCGID_DIE_IDLE_TIMEOUT;
			else if (apr_time_sec(now) - apr_time_sec(start_time) >
					 g_proc_lifetime)
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
	safe_unlock(main_server);
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

	/* Should I check the busy list? */
	if (procmgr_must_exit()
		|| apr_time_sec(now) - apr_time_sec(lastbusyscan) <=
		g_busy_scan_interval)
		return;
	lastbusyscan = now;

	/* Check the list */
	proc_table = proctable_get_table_array();
	previous_node = proctable_get_busy_list();
	error_list_header = proctable_get_error_list();

	safe_lock(main_server);
	current_node = &proc_table[previous_node->next_index];
	while (current_node != proc_table) {
		next_node = &proc_table[current_node->next_index];

		last_active_time = current_node->last_active_time;
		if (apr_time_sec(now) - apr_time_sec(last_active_time) >
			g_busy_timeout) {
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
	safe_unlock(main_server);
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
	fcgid_procnode *error_list_header, *check_list_header;
	fcgid_procnode *proc_table;
	apr_time_t last_active_time;
	apr_time_t now = apr_time_now();
	fcgid_procnode temp_header;

	memset(&temp_header, 0, sizeof(temp_header));

	/* Should I check zombie processes in idle list now? */
	if (procmgr_must_exit()
		|| apr_time_sec(now) - apr_time_sec(lastzombiescan) <=
		g_zombie_scan_interval)
		return;
	lastzombiescan = now;

	/* 
	   Check the list 
	 */
	proc_table = proctable_get_table_array();
	previous_node = proctable_get_idle_list();
	error_list_header = proctable_get_error_list();
	check_list_header = &temp_header;

	safe_lock(main_server);
	current_node = &proc_table[previous_node->next_index];
	while (current_node != proc_table) {
		next_node = &proc_table[current_node->next_index];

		/* Is it time for zombie check? */
		last_active_time = current_node->last_active_time;
		if (apr_time_sec(now) - apr_time_sec(last_active_time) >
			g_zombie_scan_interval) {
			/* Unlink from idle list */
			previous_node->next_index = current_node->next_index;

			/* Link to check list */
			current_node->next_index = check_list_header->next_index;
			check_list_header->next_index = current_node - proc_table;
		} else
			previous_node = current_node;

		current_node = next_node;
	}
	safe_unlock(main_server);

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
		safe_lock(main_server);
		previous_node = proctable_get_idle_list();
		current_node = &proc_table[previous_node->next_index];

		/* Find the tail of idle list */
		while (current_node != proc_table) {
			previous_node = current_node;
			current_node = &proc_table[current_node->next_index];
		}

		/* Link check list to the tail of idle list */
		previous_node->next_index = check_list_header->next_index;
		safe_unlock(main_server);
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

	/* Should I check the busy list? */
	if (procmgr_must_exit()
		|| apr_time_sec(now) - apr_time_sec(lasterrorscan) <=
		g_error_scan_interval)
		return;
	lasterrorscan = now = apr_time_now();

	/* Try wait dead processes, restore to free list */
	/* Note: I can't keep the lock during the scan */
	safe_lock(main_server);
	temp_error_header.next_index = error_list_header->next_index;
	error_list_header->next_index = 0;
	safe_unlock(main_server);

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
	safe_lock(main_server);
	/* Find the tail of error list */
	previous_node = error_list_header;
	current_node = &proc_table[previous_node->next_index];
	while (current_node != proc_table) {
		previous_node = current_node;
		current_node = &proc_table[current_node->next_index];
	}
	previous_node->next_index = temp_error_header.next_index;
	safe_unlock(main_server);
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
	safe_lock(main_server);
	if (free_list_header->next_index == 0) {
		safe_unlock(main_server);
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
					 "mod_fcgid: too much processes, please increase FCGID_MAX_APPLICATION");
		return;
	}
	procnode = &proctable_array[free_list_header->next_index];
	free_list_header->next_index = procnode->next_index;
	procnode->next_index = 0;
	safe_unlock(main_server);

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

	procinfo.cgipath = command->cgipath;
	procinfo.configpool = configpool;
	procinfo.main_server = main_server;
	procinfo.uid = command->uid;
	procinfo.gid = command->gid;
	procinfo.userdir = command->userdir;
	if (apr_pool_create(&procnode->proc_pool, configpool) != APR_SUCCESS
		|| (procinfo.proc_environ =
			apr_table_make(procnode->proc_pool, INITENV_CNT)) == NULL) {
		/* Link the node back to free list in this case */
		if (procnode->proc_pool)
			apr_pool_destroy(procnode->proc_pool);
		link_node_to_list(main_server, free_list_header, procnode,
						  proctable_array);

		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
					 "mod_fcgid: can't create pool for process");
		return;
	}
	for (i = 0; i < INITENV_CNT; i++) {
		if (command->initenv_key[i][0] == '\0')
			break;
		apr_table_set(procinfo.proc_environ, command->initenv_key[i],
					  command->initenv_val[i]);
	}

	/* Spawn the process now */
	if ((rv =
		 proc_spawn_process(command->wrapperpath, &procinfo,
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

	/* Initialize the variables from configuration */
	g_idle_timeout = get_idle_timeout(main_server);
	g_idle_scan_interval = get_idle_scan_interval(main_server);
	g_busy_scan_interval = get_busy_scan_interval(main_server);
	g_proc_lifetime = get_proc_lifetime(main_server);
	g_error_scan_interval = get_error_scan_interval(main_server);
	g_zombie_scan_interval = get_zombie_scan_interval(main_server);
	g_busy_timeout = get_busy_timeout(main_server);
	g_busy_timeout += 10;

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
