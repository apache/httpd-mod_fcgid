#include "fcgid_spawn_ctl.h"
#include "fcgid_conf.h"
#define REGISTER_LIFE 1
#define REGISTER_DEATH 2

struct fcgid_stat_node {
	apr_ino_t inode;
	dev_t deviceid;
	uid_t uid;
	gid_t gid;
	apr_size_t share_grp_id;
	int score;
	int process_counter;
	apr_time_t last_stat_time;
	struct fcgid_stat_node *next;
};

static apr_pool_t *g_stat_pool = NULL;
static struct fcgid_stat_node *g_stat_list_header = NULL;
static int g_termination_score;
static int g_spawn_score;
static int g_score_uplimit;
static int g_max_process;
static int g_total_process;
static int g_max_class_process;
static int g_min_class_process;

static void
register_life_death(server_rec * main_server,
					fcgid_procnode * procnode, int life_or_death)
{
	struct fcgid_stat_node *previous_node, *current_node;

	if (!g_stat_pool || !procnode)
		abort();

	/* Can I find the node base on inode, device id and share group id? */
	previous_node = g_stat_list_header;
	for (current_node = previous_node;
		 current_node != NULL; current_node = current_node->next) {
		if (current_node->inode == procnode->inode
			&& current_node->deviceid == procnode->deviceid
			&& current_node->share_grp_id == procnode->share_grp_id
			&& current_node->uid == procnode->uid
			&& current_node->gid == procnode->gid)
			break;
		previous_node = current_node;
	}

	if (current_node) {
		/* Found the node */
		apr_time_t now = apr_time_now();

		/* Increase the score first */
		if (life_or_death == REGISTER_LIFE) {
			current_node->score += g_spawn_score;
			current_node->process_counter++;
		} else {
			current_node->score += g_termination_score;
			current_node->process_counter--;
		}

		/* Decrease the score base on the time passing */
		current_node->score -= (int) (apr_time_sec(now)
									  -
									  apr_time_sec(current_node->
												   last_stat_time));

		/* Make score reasonable */
		if (current_node->score < 0)
			current_node->score = 0;

		current_node->last_stat_time = now;
	} else {
		/* I can't find it, create one */
		current_node = apr_pcalloc(g_stat_pool, sizeof(*current_node));
		if (!current_node)
			return;
		current_node->deviceid = procnode->deviceid;
		current_node->inode = procnode->inode;
		current_node->share_grp_id = procnode->share_grp_id;
		current_node->uid = procnode->uid;
		current_node->gid = procnode->gid;
		current_node->last_stat_time = apr_time_now();
		current_node->score = 0;
		current_node->process_counter = 1;
		current_node->next = NULL;

		/* append it to stat list for next search */
		if (!previous_node)
			g_stat_list_header = current_node;
		else
			previous_node->next = current_node;
	}
}

void spawn_control_init(server_rec * main_server, apr_pool_t * configpool)
{
	apr_status_t rv;

	if ((rv = apr_pool_create(&g_stat_pool, configpool)) != APR_SUCCESS) {
		/* Fatal error */
		ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
					 "mod_fcgid: can't create stat pool");
		exit(1);
	}

	/* Initialize the variables from configuration */
	g_termination_score = get_termination_score(main_server);
	g_spawn_score = get_spawn_score(main_server);
	g_score_uplimit = get_spawnscore_uplimit(main_server);
	g_max_process = get_max_process(main_server);
	g_max_class_process = get_max_class_process(main_server);
	g_min_class_process = get_min_class_process(main_server);
}

void
register_termination(server_rec * main_server, fcgid_procnode * procnode)
{
	register_life_death(main_server, procnode, REGISTER_DEATH);
	g_total_process--;
}

void register_spawn(server_rec * main_server, fcgid_procnode * procnode)
{
	register_life_death(main_server, procnode, REGISTER_LIFE);
	g_total_process++;
}

/* 
	Spawn control is base on such strategy:
	1. Increate score if application is terminated
	2. Increate score if application is spawned
	3. Decrease one score per second while score is positive
	4. Negative spawn request if score is higher than up limit
	5. Negative spawn request if total process count higher than up limit
	6. Negative spawn request if process count of this class higher than up limit
*/
int is_spawn_allowed(server_rec * main_server, fcgid_command * command)
{
	struct fcgid_stat_node *current_node;

	if (!command || !g_stat_pool)
		return 1;

	/* Can I find the node base on inode, device id and share group id? */
	for (current_node = g_stat_list_header;
		 current_node != NULL; current_node = current_node->next) {
		if (current_node->inode == command->inode
			&& current_node->deviceid == command->deviceid
			&& current_node->share_grp_id == command->share_grp_id
			&& current_node->uid == command->uid
			&& current_node->gid == command->gid)
			break;
	}

	if (!current_node)
		return 1;
	else {
		apr_time_t now = apr_time_now();

		current_node->score -= (int) (apr_time_sec(now)
									  -
									  apr_time_sec(current_node->
												   last_stat_time));
		current_node->last_stat_time = now;
		if (current_node->score < 0)
			current_node->score = 0;

		/* Score is higher than up limit? */
		if (current_node->score >= g_score_uplimit) {
			ap_log_error(APLOG_MARK, APLOG_INFO, 0, main_server,
						 "mod_fcgid: %s spawn score %d >= %d, skip the spawn request",
						 command->cgipath, current_node->score,
						 g_score_uplimit);
			return 0;
		}

		/* Total process count higher than up limit? */
		if (g_total_process >= g_max_process) {
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
						 "mod_fcgid: %s total process count %d >= %d, skip the spawn request",
						 command->cgipath, g_total_process, g_max_process);
			return 0;
		}

		/* 
		   Process count of this class higher than up limit?
		 */
		/* I need max class proccess count */
		if (current_node->process_counter >= g_max_class_process) {
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, main_server,
						 "mod_fcgid: too much %s process(current:%d, max:%d), skip the spawn request",
						 command->cgipath, current_node->process_counter,
						 g_max_class_process);
			return 0;
		}

		return 1;
	}
}

int is_kill_allowed(fcgid_procnode * procnode)
{
	struct fcgid_stat_node *previous_node, *current_node;

	if (!g_stat_pool || !procnode)
		return 0;

	/* Can I find the node base on inode, device id and share group id? */
	previous_node = g_stat_list_header;
	for (current_node = previous_node;
		 current_node != NULL; current_node = current_node->next) {
		if (current_node->inode == procnode->inode
			&& current_node->deviceid == procnode->deviceid
			&& current_node->share_grp_id == procnode->share_grp_id
			&& current_node->uid == procnode->uid
			&& current_node->gid == procnode->gid)
			break;
		previous_node = current_node;
	}

	if (current_node) {
		/* Found the node */
		if (current_node->process_counter <= g_min_class_process)
			return 0;
	}

	return 1;
}
