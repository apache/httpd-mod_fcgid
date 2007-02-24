#include "unixd.h"
#include "ap_mpm.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_queue.h"
#include "apr_global_mutex.h"
#include "apr_support.h"
#include "fcgid_pm.h"
#include "fcgid_pm_main.h"
#include "fcgid_conf.h"
#include "fcgid_proctbl.h"
#include "fcgid_spawn_ctl.h"
#include <unistd.h>
static apr_status_t create_process_manager(server_rec * main_server,
										   apr_pool_t * configpool);

static int g_wakeup_timeout = 3;
static apr_proc_t *g_process_manager = NULL;
static apr_file_t *g_pm_read_pipe = NULL;
static apr_file_t *g_pm_write_pipe = NULL;
static apr_file_t *g_ap_write_pipe = NULL;
static apr_file_t *g_ap_read_pipe = NULL;
static apr_global_mutex_t *g_pipelock = NULL;
char g_pipelock_name[L_tmpnam];

static int volatile g_caughtSigTerm = 0;
static pid_t g_pm_pid;
static void signal_handler(int signo)
{
	/* Sanity check, Make sure I am not the subprocess. A subprocess may
	   get signale after fork() and before execve() */
	if (getpid() != g_pm_pid) {
		exit(0);
		return;
	}

	if ((signo == SIGTERM) || (signo == SIGUSR1) || (signo == SIGHUP)) {
		g_caughtSigTerm = 1;
		/* Tell the world it's time to die */
		proctable_get_globalshare()->must_exit = 1;
	}
}

static apr_status_t init_signal(server_rec * main_server)
{
	struct sigaction sa;

	/* Setup handlers */
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGTERM handler");
		return APR_EGENERAL;
	}

	/* Httpd restart */
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGHUP handler");
		return APR_EGENERAL;
	}

	/* Httpd graceful restart */
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGUSR1 handler");
		return APR_EGENERAL;
	}

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
					 "mod_fcgid: Can't install SIGPIPE handler");
		return APR_EGENERAL;
	}

	return APR_SUCCESS;
}

static void fcgid_maint(int reason, void *data, apr_wait_t status)
{
	apr_proc_t *proc = data;
	int mpm_state;

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
static int set_group_privs(void)
{
	if (!geteuid()) {
		const char *name;


		/* Get username if passed as a uid */
		if (unixd_config.user_name[0] == '#') {
			struct passwd *ent;

			uid_t uid = atoi(&unixd_config.user_name[1]);

			if ((ent = getpwuid(uid)) == NULL) {
				ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
							 "getpwuid: couldn't determine user name from uid %u, "
							 "you probably need to modify the User directive",
							 (unsigned) uid);
				return -1;
			}
			name = ent->pw_name;
		}

		else
			name = unixd_config.user_name;

#if !defined(OS2) && !defined(TPF)
		/* OS/2 and TPF don't support groups. */

		/*
		 * Set the GID before initgroups(), since on some platforms
		 * setgid() is known to zap the group list.
		 */
		if (setgid(unixd_config.group_id) == -1) {
			ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
						 "setgid: unable to set group id to Group %u",
						 (unsigned) unixd_config.group_id);
			return -1;
		}

		/* Reset `groups' attributes. */
		if (initgroups(name, unixd_config.group_id) == -1) {
			ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
						 "initgroups: unable to set groups for User %s "
						 "and Group %u", name,
						 (unsigned) unixd_config.group_id);
			return -1;
		}
#endif							/* !defined(OS2) && !defined(TPF) */
	}
	return 0;
}


/* Base on unixd_setup_child() */
static int suexec_setup_child(void)
{
	if (set_group_privs()) {
		exit(-1);
	}

	/* Only try to switch if we're running as root */
	if (!geteuid() && (seteuid(unixd_config.user_id) == -1)) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
					 "setuid: unable to change to uid: %ld",
					 (long) unixd_config.user_id);
		exit(-1);
	}
	return 0;
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
		g_pm_pid = getpid();
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
					 "mod_fcgid: Process manager %d started", getpid());

		if ((rv = init_signal(main_server)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, LOG_EMERG, rv, main_server,
						 "mod_fcgid: can't intall signal handler, exit now");
			exit(1);
		}

		/* if running as root, switch to configured user */
		if (unixd_config.suexec_enabled) {
			if (getuid() != 0) {
				ap_log_error(APLOG_MARK, LOG_EMERG, rv, main_server,
							 "mod_fcgid: current user is not root while suexec is enabled, exit now");
				exit(1);
			}
			suexec_setup_child();
		} else
			unixd_setup_child();
		apr_file_pipe_timeout_set(g_pm_read_pipe,
								  apr_time_from_sec(g_wakeup_timeout));
		apr_file_close(g_ap_write_pipe);
		apr_file_close(g_ap_read_pipe);

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
	apr_status_t rv;

	if ((rv = apr_global_mutex_child_init(&g_pipelock,
										  g_pipelock_name,
										  main_server->process->pconf)) !=
		APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: apr_global_mutex_child_init error for pipe mutex");
		exit(1);
	}

	return APR_SUCCESS;
}

apr_status_t
procmgr_post_config(server_rec * main_server, apr_pool_t * configpool)
{
	apr_status_t rv;
	apr_finfo_t finfo;
	int error_scan_interval, busy_scan_interval, idle_scan_interval;

	/* Calculate procmgr_peek_cmd wake up interval */
	error_scan_interval = get_error_scan_interval(main_server);
	busy_scan_interval = get_busy_scan_interval(main_server);
	idle_scan_interval = get_idle_scan_interval(main_server);
	g_wakeup_timeout = fcgid_min(error_scan_interval, busy_scan_interval);
	g_wakeup_timeout = fcgid_min(idle_scan_interval, g_wakeup_timeout);
	if (g_wakeup_timeout == 0)
		g_wakeup_timeout = 1;	/* Make it reasonable */

	rv = apr_stat(&finfo, get_socketpath(main_server), APR_FINFO_USER,
				  configpool);
	if (rv != APR_SUCCESS || !(finfo.valid & APR_FINFO_USER)
		|| finfo.user != unixd_config.user_id) {
		/* Make dir for unix domain socket */
		if ((rv = apr_dir_make_recursive(get_socketpath(main_server),
										 APR_UREAD | APR_UWRITE |
										 APR_UEXECUTE,
										 configpool)) != APR_SUCCESS
			|| chown(get_socketpath(main_server), unixd_config.user_id,
					 -1) < 0) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, main_server,
						 "mod_fcgid: Can't create unix socket dir");
			exit(1);
		}
	}

	/* Create pipes to communicate between process manager and apache */
	if ((rv = apr_file_pipe_create(&g_pm_read_pipe, &g_ap_write_pipe,
								   configpool)) != APR_SUCCESS
		|| (rv = apr_file_pipe_create(&g_ap_read_pipe, &g_pm_write_pipe,
									  configpool))) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, main_server,
					 "mod_fcgid: Can't create pipe between PM and stub");
		return rv;
	}

	/* Create mutex for pipe reading and writing */
	if ((rv =
		 apr_global_mutex_create(&g_pipelock, tmpnam(g_pipelock_name),
								 APR_LOCK_DEFAULT,
								 main_server->process->pconf)) !=
		APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't create global pipe mutex");
		exit(1);
	}
	if ((rv = unixd_set_global_mutex_perms(g_pipelock)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: Can't set global pipe mutex perms");
		exit(1);
	}

	/* Create process manager process */
	return create_process_manager(main_server, configpool);
}

void procmgr_init_spawn_cmd(fcgid_command * command, request_rec * r,
							const char *argv0, dev_t deviceid,
							apr_ino_t inode, apr_size_t share_grp_id)
{
	server_rec *main_server = r->server;
	ap_unix_identity_t *ugid;
	apr_table_t *initenv;
	const apr_array_header_t *initenv_arr;
	const apr_table_entry_t *initenv_entry;
	fcgid_wrapper_conf *wrapperconf;
	int i;

	memset(command, 0, sizeof(*command));

	/* suEXEC check */
	if ((ugid = ap_run_get_suexec_identity(r))) {
		command->uid = ugid->uid;
		command->gid = ugid->gid;
		command->userdir = ugid->userdir;
	} else {
		command->uid = (uid_t) - 1;
		command->gid = (gid_t) - 1;
		command->userdir = 0;
	}

	/* Environment variables */
	initenv = get_default_env_vars(r);
	if (initenv) {
		initenv_arr = apr_table_elts(initenv);
		initenv_entry = (apr_table_entry_t *) initenv_arr->elts;
		if (initenv_arr->nelts > INITENV_CNT)
			ap_log_error(APLOG_MARK, LOG_WARNING, 0, main_server,
						 "mod_fcgid: too much environment variables, Please increase INITENV_CNT in fcgid_pm.h and recompile module mod_fcgid");

		for (i = 0; i < initenv_arr->nelts && i < INITENV_CNT; ++i) {
			if (initenv_entry[i].key == NULL
				|| initenv_entry[i].key[0] == '\0')
				break;
			strncpy(command->initenv_key[i], initenv_entry[i].key,
					INITENV_KEY_LEN);
			command->initenv_key[i][INITENV_KEY_LEN - 1] = '\0';
			strncpy(command->initenv_val[i], initenv_entry[i].val,
					INITENV_VAL_LEN);
			command->initenv_val[i][INITENV_VAL_LEN - 1] = '\0';
		}
	}

	strncpy(command->cgipath, argv0, _POSIX_PATH_MAX);
	command->cgipath[_POSIX_PATH_MAX - 1] = '\0';
	command->deviceid = deviceid;
	command->inode = inode;
	command->share_grp_id = share_grp_id;

	/* Update fcgid_command with wrapper info */
	command->wrapperpath[0] = '\0';
	if ((wrapperconf = get_wrapper_info(argv0, r))) {
		strncpy(command->wrapperpath, wrapperconf->args, _POSIX_PATH_MAX);
		command->wrapperpath[_POSIX_PATH_MAX - 1] = '\0';
		command->deviceid = wrapperconf->deviceid;
		command->inode = wrapperconf->inode;
		command->share_grp_id = wrapperconf->share_group_id;
	}
}

apr_status_t procmgr_post_spawn_cmd(fcgid_command * command,
									request_rec * r)
{
	apr_status_t rv;
	char notifybyte;
	apr_size_t nbytes = sizeof(*command);
	server_rec *main_server = r->server;

	/* Sanity check first */
	if (g_caughtSigTerm || !g_ap_write_pipe)
		return APR_SUCCESS;

	/* Get the global mutex before posting the request */
	if ((rv = apr_global_mutex_lock(g_pipelock)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, LOG_WARNING, rv, main_server,
					 "mod_fcgid: can't get pipe mutex");
		exit(0);
	}

	if ((rv =
		 apr_file_write_full(g_ap_write_pipe, command, nbytes,
							 NULL)) != APR_SUCCESS) {
		/* Just print some error log and fall through */
		ap_log_error(APLOG_MARK, LOG_WARNING, rv, main_server,
					 "mod_fcgid: can't write spawn command");
	} else {
		/* Wait the finish notify while send the request successfully */
		nbytes = sizeof(notifybyte);
		if ((rv =
			 apr_file_read(g_ap_read_pipe, &notifybyte,
						   &nbytes)) != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, LOG_WARNING, rv, main_server,
						 "mod_fcgid: can't get notify from process manager");
		}
	}

	/* Release the lock */
	if ((rv = apr_global_mutex_unlock(g_pipelock)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, LOG_WARNING, rv, main_server,
					 "mod_fcgid: can't release pipe mutex");
		exit(0);
	}

	return APR_SUCCESS;
}

apr_status_t procmgr_finish_notify(server_rec * main_server)
{
	apr_status_t rv;
	char notifybyte = 'p';
	apr_size_t nbytes = sizeof(notifybyte);

	if ((rv =
		 apr_file_write(g_pm_write_pipe, &notifybyte,
						&nbytes)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, LOG_WARNING, rv, main_server,
					 "mod_fcgid: can't send notify from process manager");
	}

	return rv;
}

#define FOR_READ 1
apr_status_t procmgr_peek_cmd(fcgid_command * command,
							  server_rec * main_server)
{
	apr_status_t rv;

	/* Sanity check */
	if (!g_pm_read_pipe)
		return APR_EPIPE;

	/* Wait for next command */
	rv = apr_wait_for_io_or_timeout(g_pm_read_pipe, NULL, FOR_READ);

	/* Log any unexpect result */
	if (rv != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(rv)) {
		ap_log_error(APLOG_MARK, LOG_WARNING, rv, main_server,
					 "mod_fcgid: wait io error while getting message from pipe");
		return rv;
	}

	/* Timeout */
	if (rv != APR_SUCCESS)
		return rv;

	return apr_file_read_full(g_pm_read_pipe, command, sizeof(*command),
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
