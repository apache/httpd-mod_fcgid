#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_queue.h"
#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#define FCGID_MSGQUEUE_SIZE 10

static apr_thread_t *g_thread = NULL;
static apr_queue_t *g_msgqueue = NULL;
static apr_thread_t *g_wakeup_thread = NULL;
static int g_must_exit = 0;
static int g_wakeup_timeout = 3;

static void *APR_THREAD_FUNC wakeup_thread(apr_thread_t * thd, void *data)
{
	while (!g_must_exit) {
		/* Wake up every second to check g_must_exit flag */
		int i;

		for (i = 0; i < g_wakeup_timeout; i++) {
			if (g_must_exit)
				break;
			apr_sleep(apr_time_from_sec(1));
		}

		/* Send a wake up message to procmgr_peek_cmd() */
		if (!g_must_exit && g_msgqueue)
			apr_queue_trypush(g_msgqueue, NULL);
	}
	return NULL;
}

static void *APR_THREAD_FUNC worker_thread(apr_thread_t * thd, void *data)
{
	server_rec *main_server = data;

	pm_main(main_server, main_server->process->pconf);
	return NULL;
}

apr_status_t
procmgr_post_config(server_rec * main_server, apr_pool_t * pconf)
{
	apr_status_t rv;
	int error_scan_interval, busy_scan_interval, idle_scan_interval;

	/* Initialize spawn controler */
	spawn_control_init(main_server, pconf);

	/* Create a message queue */
	if ((rv = apr_queue_create(&g_msgqueue, FCGID_MSGQUEUE_SIZE,
							   pconf)) != APR_SUCCESS) {
		/* Fatal error */
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: can't create message queue");
		exit(1);
	}

	/* Calculate procmgr_peek_cmd wake up interval */
	error_scan_interval = get_error_scan_interval(main_server);
	busy_scan_interval = get_busy_scan_interval(main_server);
	idle_scan_interval = get_idle_scan_interval(main_server);
	g_wakeup_timeout = min(error_scan_interval, busy_scan_interval);
	g_wakeup_timeout = min(idle_scan_interval, g_wakeup_timeout);
	if (g_wakeup_timeout == 0)
		g_wakeup_timeout = 1;	/* Make it reasonable */

	/* Create process manager worker thread */
	if ((rv = apr_thread_create(&g_thread, NULL, worker_thread,
								main_server, pconf)) != APR_SUCCESS) {
		/* It's a fatal error */
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: can't create process manager thread");
		exit(1);
	}

	/* Create wake up thread */
	/* XXX If there was a function such like apr_queue_pop_timedwait(), 
	   then I don't need such an ugly thread to do the wake up job */
	if ((rv = apr_thread_create(&g_wakeup_thread, NULL, wakeup_thread,
								NULL, pconf)) != APR_SUCCESS) {
		/* It's a fatal error */
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: can't create wake up thread");
		exit(1);
	}

	return APR_SUCCESS;
}

apr_status_t procmgr_post_spawn_cmd(const fcgid_command * command)
{
	if (g_thread && g_msgqueue && !g_must_exit) {
		apr_status_t rv;

		/* 
		   Prepare the message send to another thread
		   destroy the message if I can't push to message
		 */
		fcgid_command *postcmd =
			(fcgid_command *) malloc(sizeof(fcgid_command));
		if (!postcmd)
			return APR_ENOMEM;
		memcpy(postcmd, command, sizeof(*command));

		/* Try push the message */
		if ((rv = apr_queue_trypush(g_msgqueue, postcmd)) != APR_SUCCESS) {
			free(postcmd);
			return rv;
		}
	}

	return APR_SUCCESS;
}

apr_status_t procmgr_peek_cmd(fcgid_command * command)
{
	apr_status_t rv = APR_SUCCESS;
	fcgid_command *peakcmd = NULL;

	if (!g_must_exit && g_msgqueue) {
		if (apr_queue_pop(g_msgqueue, &peakcmd) == APR_SUCCESS) {
			if (!peakcmd)
				return APR_TIMEUP;	/* This a wake up message */
			else {
				/* Copy the command, and then free the memory */
				memcpy(command, peakcmd, sizeof(*peakcmd));
				free(peakcmd);
				return APR_SUCCESS;
			}
		}
	}

	return APR_TIMEUP;
}

apr_status_t
procmgr_child_init(server_rec * main_server, apr_pool_t * pchild)
{
	apr_pool_cleanup_register(pchild, main_server,
							  procmgr_stop_procmgr, apr_pool_cleanup_null);
	return APR_SUCCESS;
}

int procmgr_must_exit()
{
	return g_must_exit;
}

apr_status_t procmgr_stop_procmgr(void *server)
{
	apr_status_t status;

	/* Tell the world to die */
	g_must_exit = 1;
	if (g_msgqueue)
		apr_queue_push(g_msgqueue, NULL);

	/* Wait */
	if (g_thread && apr_thread_join(&status, g_thread) == APR_SUCCESS) {
		/* Free the memory left in queue */
		fcgid_command *peakcmd = NULL;

		while (apr_queue_trypop(g_msgqueue, &peakcmd) == APR_SUCCESS) {
			if (peakcmd)
				free(peakcmd);
		}
	}

	if (g_wakeup_thread)
		return apr_thread_join(&status, g_wakeup_thread);

	return APR_SUCCESS;
}
