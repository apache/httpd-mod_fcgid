#ifndef FCGID_PM_PROC_H
#define FCGID_PM_PROC_H
#include "httpd.h"
#include "apr_pools.h"
#include "apr_file_io.h"
#include "fcgid_proctbl.h"

typedef struct {
	apr_table_t *proc_environ;
	server_rec *main_server;
	apr_pool_t *configpool;
	char *cgipath;
} fcgid_proc_info;

typedef struct {
	apr_pool_t *request_pool;
	int connect_timeout;		/* in second */
	int communation_timeout;	/* in second */
	void *ipc_handle_info;
} fcgid_ipc;

apr_status_t proc_spawn_process(fcgid_proc_info * procinfo,
								fcgid_procnode * procnode);

apr_status_t proc_kill_gracefully(fcgid_procnode * procnode,
								  server_rec * main_server);

apr_status_t proc_wait_process(server_rec * main_server,
							   fcgid_procnode * procnode);

apr_status_t proc_connect_ipc(server_rec * main_server,
							  fcgid_procnode * procnode,
							  fcgid_ipc * ipc_handle);

apr_status_t proc_bridge_request(server_rec * main_server,
								 fcgid_ipc * ipc_handle,
								 apr_bucket_brigade * birgade_send,
								 apr_bucket_brigade * brigade_recv,
								 apr_bucket_alloc_t * alloc);

apr_status_t proc_close_ipc(fcgid_ipc * ipc_handle);

void proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
						  apr_exit_why_e exitwhy,
						  server_rec * main_server);
#endif
