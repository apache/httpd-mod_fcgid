#!/usr/bin/sed -f
#
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
#
# sed script to replace all old directive names with the new ones.
#
# First we fix occurences at the beginning of lines
s/^BusyScanInterval/FcgidBusyScanInterval/g
s/^BusyTimeout/FcgidBusyTimeout/g
s/^DefaultInitEnv/FcgidInitialEnv/g
s/^DefaultMaxClassProcessCount/FcgidMaxProcessesPerClass/g
s/^DefaultMinClassProcessCount/FcgidMinProcessesPerClass/g
s/^ErrorScanInterval/FcgidErrorScanInterval/g
s/^FastCgiAccessChecker/FcgidAccessChecker/g
s/^FastCgiAccessCheckerAuthoritative/FcgidAccessCheckerAuthoritative/g
s/^FastCgiAuthenticator/FcgidAuthenticator/g
s/^FastCgiAuthenticatorAuthoritative/FcgidAuthenticatorAuthoritative/g
s/^FastCgiAuthorizer/FcgidAuthorizer/g
s/^FastCgiAuthorizerAuthoritative/FcgidAuthorizerAuthoritative/g
s/^FCGIWrapper/FcgidWrapper/g
s/^IdleScanInterval/FcgidIdleScanInterval/g
s/^IdleTimeout/FcgidIdleTimeout/g
s/^IPCCommTimeout/FcgidIOTimeout/g
s/^IPCConnectTimeout/FcgidConnectTimeout/g
s/^MaxProcessCount/FcgidMaxProcesses/g
s/^MaxRequestInMem/FcgidMaxRequestInMem/g
s/^MaxRequestLen/FcgidMaxRequestLen/g
s/^MaxRequestsPerProcess/FcgidMaxRequestsPerProcess/g
s/^OutputBufferSize/FcgidOutputBufferSize/g
s/^PassHeader/FcgidPassHeader/g
s/^PHP_Fix_Pathinfo_Enable/FcgidFixPathinfo/g
s/^ProcessLifeTime/FcgidProcessLifeTime/g
s/^SharememPath/FcgidProcessTableFile/g
s/^SocketPath/FcgidIPCDir/g
s/^SpawnScore/FcgidSpawnScore/g
s/^SpawnScoreUpLimit/FcgidSpawnScoreUpLimit/g
s/^TerminationScore/FcgidTerminationScore/g
s/^TimeScore/FcgidTimeScore/g
s/^ZombieScanInterval/FcgidZombieScanInterval/g
# Next we fix all other occurences without matching
# the ones, that are already OK
s/\([^D]\)BusyScanInterval/\1FcgidBusyScanInterval/g
s/\([^D]\)BusyTimeout/\1FcgidBusyTimeout/g
s/\([^D]\)DefaultInitEnv/\1FcgidInitialEnv/g
s/\([^D]\)DefaultMaxClassProcessCount/\1FcgidMaxProcessesPerClass/g
s/\([^D]\)DefaultMinClassProcessCount/\1FcgidMinProcessesPerClass/g
s/\([^D]\)ErrorScanInterval/\1FcgidErrorScanInterval/g
s/\([^D]\)FastCgiAccessChecker/\1FcgidAccessChecker/g
s/\([^D]\)FastCgiAccessCheckerAuthoritative/\1FcgidAccessCheckerAuthoritative/g
s/\([^D]\)FastCgiAuthenticator/\1FcgidAuthenticator/g
s/\([^D]\)FastCgiAuthenticatorAuthoritative/\1FcgidAuthenticatorAuthoritative/g
s/\([^D]\)FastCgiAuthorizer/\1FcgidAuthorizer/g
s/\([^D]\)FastCgiAuthorizerAuthoritative/\1FcgidAuthorizerAuthoritative/g
s/\([^D]\)FCGIWrapper/\1FcgidWrapper/g
s/\([^D]\)IdleScanInterval/\1FcgidIdleScanInterval/g
s/\([^D]\)IdleTimeout/\1FcgidIdleTimeout/g
s/\([^D]\)IPCCommTimeout/\1FcgidIOTimeout/g
s/\([^D]\)IPCConnectTimeout/\1FcgidConnectTimeout/g
s/\([^D]\)MaxProcessCount/\1FcgidMaxProcesses/g
s/\([^D]\)MaxRequestInMem/\1FcgidMaxRequestInMem/g
s/\([^D]\)MaxRequestLen/\1FcgidMaxRequestLen/g
s/\([^D]\)MaxRequestsPerProcess/\1FcgidMaxRequestsPerProcess/g
s/\([^D]\)OutputBufferSize/\1FcgidOutputBufferSize/g
s/\([^D]\)PassHeader/\1FcgidPassHeader/g
s/\([^D]\)PHP_Fix_Pathinfo_Enable/\1FcgidFixPathinfo/g
s/\([^D]\)ProcessLifeTime/\1FcgidProcessLifeTime/g
s/\([^D]\)SharememPath/\1FcgidProcessTableFile/g
s/\([^D]\)SocketPath/\1FcgidIPCDir/g
s/\([^D]\)SpawnScore/\1FcgidSpawnScore/g
s/\([^D]\)SpawnScoreUpLimit/\1FcgidSpawnScoreUpLimit/g
s/\([^D]\)TerminationScore/\1FcgidTerminationScore/g
s/\([^D]\)TimeScore/\1FcgidTimeScore/g
s/\([^D]\)ZombieScanInterval/\1FcgidZombieScanInterval/g
