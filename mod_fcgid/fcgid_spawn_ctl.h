#ifndef FCGID_SPAWN_CONTROL_H
#define FCGID_SPAWN_CONTROL_H
#include "fcgid_proctbl.h"
#include "fcgid_pm.h"

void spawn_control_init(server_rec * main_server, apr_pool_t * configpool);
void register_termination(server_rec * main_server,
						  fcgid_procnode * procnode);
void register_spawn(server_rec * main_server, fcgid_procnode * procnode);
int is_spawn_allowed(server_rec * main_server, fcgid_command * command);
int is_kill_allowed(fcgid_procnode * procnode);

#endif
