#include "fcgid_proctbl.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "fcgid_global.h"

static apr_thread_mutex_t* g_sharelock = NULL;

static fcgid_procnode* g_proc_array = NULL;		/* Contain all process slot */
static fcgid_procnode* g_free_list_header = NULL;	/* Attach to no process list */
static fcgid_procnode* g_busy_list_header = NULL;	/* Attach to a working process list */
static fcgid_procnode* g_idle_list_header = NULL;	/* Attach to an idle process list */
static fcgid_procnode* g_error_list_header = NULL;	/* Attach to an error process list */
static fcgid_share* _global_memory = NULL;
static fcgid_global_share* g_global_share = NULL;	/* global information */
static size_t g_table_size = FCGID_PROC_TABLE_SIZE;

apr_status_t proctable_post_config(server_rec *main_server, apr_pool_t* pconf)
{
	long shmem_size = sizeof(fcgid_share);
	fcgid_procnode* ptmpnode = NULL;
	int i;
	apr_status_t rv = APR_SUCCESS;

    if( (rv=apr_thread_mutex_create(&g_sharelock, 
                    APR_THREAD_MUTEX_DEFAULT, pconf))!=APR_SUCCESS )
	{
		/* Fatal error */
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					"mod_fcgid: Can't create global mutex");
        exit(1);
    }
	
	/* There is only one process in WinNT mpm, share memory is not necessary */
	if( (_global_memory=((fcgid_share*)apr_pcalloc(pconf, 
					shmem_size)))==NULL )
	{
		/* Fatal error */
		ap_log_error(APLOG_MARK, APLOG_EMERG, apr_get_os_error(), main_server,
					"mod_fcgid: can't alloc memory for size %ld", shmem_size);
		exit(1);
	}
	
	g_proc_array = _global_memory->procnode_array;
	g_global_share = &_global_memory->global;
	g_global_share->must_exit = 0;

	/* Init the array */
	g_idle_list_header = g_proc_array;
	g_busy_list_header = g_idle_list_header+1;
	g_error_list_header = g_busy_list_header+1;
	g_free_list_header = g_error_list_header+1;
	ptmpnode = g_free_list_header;
	for( i=0; i<FCGID_MAX_APPLICATION; i++ )
	{
		ptmpnode->next_index = ptmpnode-g_proc_array+1;
		ptmpnode++;
	}

	return APR_SUCCESS;
}

apr_status_t proctable_child_init(server_rec *main_server, apr_pool_t* pchild)
{
	return APR_SUCCESS;
}

apr_status_t proctable_lock_table()
{
	return apr_thread_mutex_lock(g_sharelock);
}

apr_status_t proctable_unlock_table()
{
	return apr_thread_mutex_unlock(g_sharelock);
}

fcgid_procnode* proctable_get_free_list()
{
	return g_free_list_header;
}

fcgid_procnode* proctable_get_busy_list()
{
	return g_busy_list_header;
}

fcgid_procnode* proctable_get_idle_list()
{
	return g_idle_list_header;
}

fcgid_procnode* proctable_get_table_array()
{
	return g_proc_array;
}

fcgid_procnode* proctable_get_error_list()
{
	return g_error_list_header;
}

fcgid_global_share* proctable_get_globalshare()
{
	return g_global_share;
}

size_t proctable_get_table_size()
{
	return g_table_size;
}

void safe_lock(server_rec* main_server)
{
	/* Lock error is a fatal error */
	apr_status_t rv;
	if( (rv=proctable_lock_table())!=APR_SUCCESS )
	{
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
				"mod_fcgid: can't get lock");
		exit(1);
	}
}

void safe_unlock(server_rec* main_server)
{
	/* Lock error is a fatal error */
	apr_status_t rv;
	if( (rv=proctable_unlock_table())!=APR_SUCCESS )
	{
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
				"mod_fcgid: can't unlock");
		exit(1);
	}
}

void proctable_print_debug_info(server_rec* main_server)
{
	int freecount = 0;
	fcgid_procnode* current_node;

	for( current_node=&g_proc_array[g_free_list_header->next_index];
			current_node!=g_proc_array;
			current_node=&g_proc_array[current_node->next_index] )
		freecount++;

	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
		"mod_fcgid: total node count: %d, free node count: %d",
				FCGID_MAX_APPLICATION, freecount);

	for( current_node=&g_proc_array[g_idle_list_header->next_index];
			current_node!=g_proc_array;
			current_node=&g_proc_array[current_node->next_index] )
	{
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
			"mod_fcgid: idle node index: %d", current_node-g_proc_array);
	}

	for( current_node=&g_proc_array[g_busy_list_header->next_index];
			current_node!=g_proc_array;
			current_node=&g_proc_array[current_node->next_index] )
	{
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
			"mod_fcgid: busy node index: %d", current_node-g_proc_array);
	}

	for( current_node=&g_proc_array[g_error_list_header->next_index];
			current_node!=g_proc_array;
			current_node=&g_proc_array[current_node->next_index] )
	{
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, main_server,
			"mod_fcgid: error node index: %d", current_node-g_proc_array);
	}
}
