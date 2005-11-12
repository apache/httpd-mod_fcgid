#include "fcgid_proctbl.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "fcgid_global.h"
#include "unixd.h"
#include <unistd.h>

static apr_shm_t *g_sharemem = NULL;
static apr_global_mutex_t *g_sharelock = NULL;
char g_sharelock_name[L_tmpnam];
static fcgid_procnode *g_proc_array = NULL;	/* Contain all process slot */
static fcgid_procnode *g_free_list_header = NULL;	/* Attach to no process list */
static fcgid_procnode *g_busy_list_header = NULL;	/* Attach to a working process list */
static fcgid_procnode *g_idle_list_header = NULL;	/* Attach to an idle process list */
static fcgid_procnode *g_error_list_header = NULL;	/* Attach to an error process list */
static fcgid_share *_global_memory = NULL;
static fcgid_global_share *g_global_share = NULL;	/* global information */
static size_t g_table_size = FCGID_PROC_TABLE_SIZE;

apr_status_t
proctable_post_config(server_rec * main_server, apr_pool_t * configpool)
{
	size_t shmem_size = sizeof(fcgid_share);
	fcgid_procnode *ptmpnode = NULL;
	int i;
	apr_status_t rv;
	char tempname[L_tmpnam];

	/* Create share memory */
	if ((rv = apr_shm_create(&g_sharemem, shmem_size, tmpnam(tempname),
							 main_server->process->pconf)) != APR_SUCCESS)
	{
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't create share memory for size %d byte",
					 shmem_size);
		exit(1);
	}
	if ((_global_memory = apr_shm_baseaddr_get(g_sharemem)) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, apr_get_os_error(),
					 main_server,
					 "mod_fcgid: Can't get base address of share memory");
		exit(1);
	}

	/* Create global mutex */
	if ((rv =
		 apr_global_mutex_create(&g_sharelock, tmpnam(g_sharelock_name),
								 APR_LOCK_DEFAULT,
								 main_server->process->pconf)) !=
		APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't create global mutex");
		exit(1);
	}
	if ((rv = unixd_set_global_mutex_perms(g_sharelock)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't set global mutex perms");
		exit(1);
	}

	memset(_global_memory, 0, shmem_size);
	g_proc_array = _global_memory->procnode_array;
	g_global_share = &_global_memory->global;

	g_global_share->must_exit = 0;

	/* Init the array */
	g_idle_list_header = g_proc_array;
	g_busy_list_header = g_idle_list_header + 1;
	g_error_list_header = g_busy_list_header + 1;
	g_free_list_header = g_error_list_header + 1;
	ptmpnode = g_free_list_header;
	for (i = 0; i < FCGID_MAX_APPLICATION; i++) {
		ptmpnode->next_index = ptmpnode - g_proc_array + 1;
		ptmpnode++;
	}

	return APR_SUCCESS;
}

apr_status_t
proctable_child_init(server_rec * main_server, apr_pool_t * configpool)
{
	apr_status_t rv;

	if ((rv = apr_global_mutex_child_init(&g_sharelock,
										  g_sharelock_name,
										  main_server->process->pconf)) !=
		APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: apr_global_mutex_child_init error");
		exit(1);
	}

	return rv;
}

apr_status_t proctable_lock_table(void)
{
	return apr_global_mutex_lock(g_sharelock);
}

apr_status_t proctable_unlock_table(void)
{
	return apr_global_mutex_unlock(g_sharelock);
}

fcgid_procnode *proctable_get_free_list(void)
{
	return g_free_list_header;
}

fcgid_procnode *proctable_get_busy_list(void)
{
	return g_busy_list_header;
}

fcgid_procnode *proctable_get_idle_list(void)
{
	return g_idle_list_header;
}

fcgid_procnode *proctable_get_table_array(void)
{
	return g_proc_array;
}

fcgid_procnode *proctable_get_error_list(void)
{
	return g_error_list_header;
}

fcgid_global_share *proctable_get_globalshare(void)
{
	return g_global_share;
}

size_t proctable_get_table_size(void)
{
	return g_table_size;
}

void safe_lock(server_rec * main_server)
{
	apr_status_t rv;

	if (g_global_share->must_exit) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, main_server,
					 "mod_fcgid: server is restarted, %d must exit",
					 getpid());
		kill(getpid(), SIGTERM);
	}

	/* Lock error is a fatal error */
	if ((rv = proctable_lock_table()) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: can't get lock, pid: %d", getpid());
		exit(1);
	}
}

void safe_unlock(server_rec * main_server)
{
	/* Lock error is a fatal error */
	apr_status_t rv;

	if ((rv = proctable_unlock_table()) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: can't unlock, pid: %d", getpid());
		exit(1);
	}
}

void proctable_print_debug_info(server_rec * main_server)
{
	int freecount = 0;
	fcgid_procnode *current_node;

	for (current_node = &g_proc_array[g_free_list_header->next_index];
		 current_node != g_proc_array;
		 current_node = &g_proc_array[current_node->next_index])
		freecount++;

	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
				 "mod_fcgid: total node count: %d, free node count: %d",
				 FCGID_MAX_APPLICATION, freecount);

	for (current_node = &g_proc_array[g_idle_list_header->next_index];
		 current_node != g_proc_array;
		 current_node = &g_proc_array[current_node->next_index]) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
					 "mod_fcgid: idle node index: %d",
					 current_node - g_proc_array);
	}

	for (current_node = &g_proc_array[g_busy_list_header->next_index];
		 current_node != g_proc_array;
		 current_node = &g_proc_array[current_node->next_index]) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
					 "mod_fcgid: busy node index: %d",
					 current_node - g_proc_array);
	}

	for (current_node = &g_proc_array[g_error_list_header->next_index];
		 current_node != g_proc_array;
		 current_node = &g_proc_array[current_node->next_index]) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
					 "mod_fcgid: error node index: %d",
					 current_node - g_proc_array);
	}
}
