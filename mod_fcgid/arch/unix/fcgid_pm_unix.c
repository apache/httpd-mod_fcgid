#include "unixd.h"
#include "ap_mpm.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_queue.h"
#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_proctbl.h"
#define fcgid_min(a,b)    (((a) < (b)) ? (a) : (b))
static apr_status_t create_process_manager(server_rec * main_server,
										   apr_pool_t * configpool);

static int g_wakeup_timeout = 3;
static apr_proc_t *g_process_manager = NULL;
static apr_file_t *g_read_pipe = NULL;
static apr_file_t *g_write_pipe = NULL;
static server_rec *g_main_server = NULL;

static int g_nProcIdleTimeOut = 0;
static int volatile g_caughtSigTerm = 0;
static void signal_handler(int signo)
{
	if ((signo == SIGTERM) || (signo == SIGUSR1) || (signo == SIGHUP)) {
		g_caughtSigTerm = 1;
		/* Tell the world it's time to die */
		proctable_get_globalshare()->must_exit = 1;
	}
}

static apr_status_t init_signal(server_rec * main_server)
{
	struct sigaction sa;
	apr_status_t rv;

	/* Setup handlers */
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGTERM handler");
		return errno;
	}

	/* Httpd restart */
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGHUP handler");
		return errno;
	}

	/* Httpd graceful restart */
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGUSR1 handler");
		return errno;
	}

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGPIPE handler");
		return errno;
	}

	return APR_SUCCESS;
}

static void fcgid_maint(int reason, void *data, apr_wait_t status)
{
	apr_proc_t *proc = data;
	int mpm_state;
	int stopping;

	switch (reason) {
	case APR_OC_REASON_DEATH:
		apr_proc_other_child_unregister(data);
		if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
			&& mpm_state != AP_MPMQ_STOPPING) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
						 "mod_fcgid: fcgid process manager died, restarting the server");

			/* HACK: I can't just call create_process_manager() to
			   restart a process manager, because it will use the dirty
			   share memory, I have to kill myself a SIGHUP, to make
			   a clean restart */
			if (kill(getpid(), SIGHUP) < 0) {
				ap_log_error(APLOG_MARK, APLOG_EMERG,
							 apr_get_os_error(), NULL,
							 "mod_fcgid: can' kill myself a signal SIGHUP");
				exit(0);
			}
		}
		break;
	case APR_OC_REASON_RESTART:
		apr_proc_other_child_unregister(data);
		break;
	case APR_OC_REASON_LOST:
		apr_proc_other_child_unregister(data);
		/* It hack here too, a note above */
		if (kill(getpid(), SIGHUP) < 0) {
			ap_log_error(APLOG_MARK, APLOG_EMERG,
						 apr_get_os_error(), NULL,
						 "mod_fcgid: can' kill myself a signal SIGHUP");
			exit(0);
		}
		break;
	case APR_OC_REASON_UNREGISTER:
		/* I don't think it's going to happen */
		kill(proc->pid, SIGHUP);
		break;
	}
}

static apr_status_t
create_process_manager(server_rec * main_server, apr_pool_t * configpool)
{
	apr_status_t rv;

	g_process_manager =
		(apr_proc_t *) apr_pcalloc(configpool, sizeof(*g_process_manager));
	rv = apr_proc_fork(g_process_manager, configpool);
	if (rv == APR_INCHILD) {
		/* I am the child */
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
					 "mod_fcgid: Process manager %d started", getpid());

		if ((rv = init_signal(main_server)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, LOG_EMERG, rv, main_server,
						 "mod_fcgid: can't intall signal handler, exit now");
			exit(1);
		}

		/* if running as root, switch to configured user/group */
		unixd_setup_child();

		apr_file_pipe_timeout_set(g_read_pipe,
								  apr_time_from_sec(g_wakeup_timeout));
		apr_file_close(g_write_pipe);

		/* Initialize spawn controler */
		spawn_control_init(main_server, configpool);

		pm_main(main_server, configpool);

		ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
					 "mod_fcgid: Process manager %d stopped", getpid());
		exit(0);
	} else if (rv != APR_INPARENT) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, errno, main_server,
					 "mod_fcgid: Create process manager error");
		exit(1);
	}

	/* I am the parent
	   I will send the stop signal in procmgr_stop_procmgr() */
	apr_pool_note_subprocess(configpool, g_process_manager,
							 APR_KILL_ONLY_ONCE);
	apr_proc_other_child_register(g_process_manager, fcgid_maint,
								  g_process_manager, NULL, configpool);

	return APR_SUCCESS;
}

apr_status_t
procmgr_child_init(server_rec * main_server, apr_pool_t * configpool)
{
	/* Do nothing on *NIX platform */
	return APR_SUCCESS;
}

apr_status_t
procmgr_post_config(server_rec * main_server, apr_pool_t * configpool)
{
	apr_status_t rv;
	int error_scan_interval, busy_scan_interval, idle_scan_interval;

	g_main_server = main_server;

	/* Calculate procmgr_peek_cmd wake up interval */
	error_scan_interval = get_error_scan_interval(main_server);
	busy_scan_interval = get_busy_scan_interval(main_server);
	idle_scan_interval = get_idle_scan_interval(main_server);
	g_wakeup_timeout = fcgid_min(error_scan_interval, busy_scan_interval);
	g_wakeup_timeout = fcgid_min(idle_scan_interval, g_wakeup_timeout);
	if (g_wakeup_timeout == 0)
		g_wakeup_timeout = 1;	/* Make it reasonable */

	/* Make dir for unix domain socket */
	if ((rv = apr_dir_make_recursive(get_socketpath(main_server),
									 APR_UREAD | APR_UWRITE | APR_UEXECUTE,
									 configpool)) != APR_SUCCESS
		|| chown(get_socketpath(main_server), unixd_config.user_id,
				 -1) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, main_server,
					 "mod_fcgid: Can't create unix socket dir");
		exit(1);
	}

	/* Create pipes to communicate between process manager and stub */
	if ((rv = apr_file_pipe_create(&g_read_pipe, &g_write_pipe,
								   configpool)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, main_server,
					 "mod_fcgid: Can't create pipe between PM and stub");
		return rv;
	}

	/* Create process manager process */
	return create_process_manager(main_server, configpool);
}

apr_status_t procmgr_post_spawn_cmd(const fcgid_command * command)
{
	apr_status_t rv;
	apr_size_t nbytes = sizeof(*command);

	if (!g_caughtSigTerm && g_write_pipe)
		rv = apr_file_write(g_write_pipe, command, &nbytes);

	if (nbytes != sizeof(*command)) {
		/* XXX If nbytes neither sizeof(*command) nor 0,
		   What will the server side get??
		 */
		if (g_main_server)
			ap_log_error(APLOG_MARK, LOG_WARNING, rv, g_main_server,
						 "mod_fcgid: can't write to pipe, write byte: %d",
						 nbytes);
		return rv;
	}

	return APR_SUCCESS;
}

#define FOR_READ 1
apr_status_t procmgr_peek_cmd(fcgid_command * command)
{
	apr_status_t rv;

	/* Sanity check */
	if (!g_read_pipe)
		return APR_EPIPE;

	/* Wait for next command */
	rv = apr_wait_for_io_or_timeout(g_read_pipe, NULL, FOR_READ);

	/* Log any unexpect result */
	if (rv != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(rv)) {
		if (g_main_server)
			ap_log_error(APLOG_MARK, LOG_WARNING, rv, g_main_server,
						 "mod_fcgid: wait io error while getting message from pipe");
		return rv;
	}

	/* Timeout */
	if (rv != APR_SUCCESS)
		return rv;

	return apr_file_read_full(g_read_pipe, command, sizeof(*command),
							  NULL);
}

int procmgr_must_exit()
{
	return g_caughtSigTerm;
}

apr_status_t procmgr_stop_procmgr(void *server)
{
	return APR_SUCCESS;
}
