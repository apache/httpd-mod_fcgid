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
	uid_t uid;					/* For suEXEC */
	gid_t gid;					/* For suEXEC */
	int userdir;				/* For suEXEC */
} fcgid_proc_info;

typedef struct {
	int connect_timeout;		/* in second */
	int communation_timeout;	/* in second */
	void *ipc_handle_info;
	request_rec *request;
} fcgid_ipc;

apr_status_t proc_spawn_process(fcgid_proc_info * procinfo,
								fcgid_procnode * procnode);

apr_status_t proc_kill_gracefully(fcgid_procnode * procnode,
								  server_rec * main_server);
apr_status_t proc_kill_force(fcgid_procnode * procnode,
							 server_rec * main_server);
apr_status_t proc_wait_process(server_rec * main_server,
							   fcgid_procnode * procnode);

apr_status_t proc_connect_ipc(server_rec * main_server,
							  fcgid_procnode * procnode,
							  fcgid_ipc * ipc_handle);

apr_status_t proc_read_ipc(server_rec * main_server,
						   fcgid_ipc * ipc_handle, const char *buffer,
						   apr_size_t * size);

apr_status_t proc_write_ipc(server_rec * main_server,
							fcgid_ipc * ipc_handle,
							apr_bucket_brigade * output_brigade);

void proc_print_exit_info(fcgid_procnode * procnode, int exitcode,
						  apr_exit_why_e exitwhy,
						  server_rec * main_server);
#endif
