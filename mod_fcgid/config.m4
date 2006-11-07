dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mod_fcgid)

dnl #  list of module object files
fcigd_objs="dnl
fcgid_bridge.lo dnl
fcgid_conf.lo dnl
fcgid_pm_main.lo dnl
fcgid_protocol.lo dnl
fcgid_spawn_ctl.lo dnl
mod_fcgid.lo dnl
fcgid_proctbl_unix.lo dnl
fcgid_pm_unix.lo dnl
fcgid_proc_unix.lo dnl
fcgid_bucket.lo dnl
fcgid_filter.lo dnl
"

APACHE_MODULE(fcgid, [FastCGI support (mod_fcgid)], $fcigd_objs, , no)

APACHE_MODPATH_FINISH
