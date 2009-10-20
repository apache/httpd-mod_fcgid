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
s/\([^d]\)BusyScanInterval/\1FcgidBusyScanInterval/g
s/\([^d]\)BusyTimeout/\1FcgidBusyTimeout/g
s/\([^d]\)DefaultInitEnv/\1FcgidInitialEnv/g
s/\([^d]\)DefaultMaxClassProcessCount/\1FcgidMaxProcessesPerClass/g
s/\([^d]\)DefaultMinClassProcessCount/\1FcgidMinProcessesPerClass/g
s/\([^d]\)ErrorScanInterval/\1FcgidErrorScanInterval/g
s/\([^d]\)FastCgiAccessChecker/\1FcgidAccessChecker/g
s/\([^d]\)FastCgiAccessCheckerAuthoritative/\1FcgidAccessCheckerAuthoritative/g
s/\([^d]\)FastCgiAuthenticator/\1FcgidAuthenticator/g
s/\([^d]\)FastCgiAuthenticatorAuthoritative/\1FcgidAuthenticatorAuthoritative/g
s/\([^d]\)FastCgiAuthorizer/\1FcgidAuthorizer/g
s/\([^d]\)FastCgiAuthorizerAuthoritative/\1FcgidAuthorizerAuthoritative/g
s/\([^d]\)FCGIWrapper/\1FcgidWrapper/g
s/\([^d]\)IdleScanInterval/\1FcgidIdleScanInterval/g
s/\([^d]\)IdleTimeout/\1FcgidIdleTimeout/g
s/\([^d]\)IPCCommTimeout/\1FcgidIOTimeout/g
s/\([^d]\)IPCConnectTimeout/\1FcgidConnectTimeout/g
s/\([^d]\)MaxProcessCount/\1FcgidMaxProcesses/g
s/\([^d]\)MaxRequestInMem/\1FcgidMaxRequestInMem/g
s/\([^d]\)MaxRequestLen/\1FcgidMaxRequestLen/g
s/\([^d]\)MaxRequestsPerProcess/\1FcgidMaxRequestsPerProcess/g
s/\([^d]\)OutputBufferSize/\1FcgidOutputBufferSize/g
s/\([^d]\)PassHeader/\1FcgidPassHeader/g
s/\([^d]\)PHP_Fix_Pathinfo_Enable/\1FcgidFixPathinfo/g
s/\([^d]\)ProcessLifeTime/\1FcgidProcessLifeTime/g
s/\([^d]\)SharememPath/\1FcgidProcessTableFile/g
s/\([^d]\)SocketPath/\1FcgidIPCDir/g
s/\([^d]\)SpawnScore/\1FcgidSpawnScore/g
s/\([^d]\)SpawnScoreUpLimit/\1FcgidSpawnScoreUpLimit/g
s/\([^d]\)TerminationScore/\1FcgidTerminationScore/g
s/\([^d]\)TimeScore/\1FcgidTimeScore/g
s/\([^d]\)ZombieScanInterval/\1FcgidZombieScanInterval/g
