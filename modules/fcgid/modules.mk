# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# this is used/needed by the APACHE2 build system
#

MOD_FCGID = fcgid_bridge fcgid_conf fcgid_pm_main fcgid_protocol fcgid_spawn_ctl \
	mod_fcgid fcgid_proctbl_unix fcgid_pm_unix fcgid_proc_unix fcgid_bucket fcgid_filter

mod_fcgid.la: ${MOD_FCGID:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_FCGID:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_fcgid.la

