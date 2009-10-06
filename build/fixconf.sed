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
s/^BusyScanInterval/FCGIDBusyScanInterval/g
s/^BusyTimeout/FCGIDBusyTimeout/g
s/^DefaultInitEnv/FCGIDInitialEnv/g
s/^DefaultMaxClassProcessCount/FCGIDMaxProcessesPerClass/g
s/^DefaultMinClassProcessCount/FCGIDMinProcessesPerClass/g
s/^ErrorScanInterval/FCGIDErrorScanInterval/g
s/^FastCgiAccessChecker/FCGIDAccessChecker/g
s/^FastCgiAccessCheckerAuthoritative/FCGIDAccessCheckerAuthoritative/g
s/^FastCgiAuthenticator/FCGIDAuthenticator/g
s/^FastCgiAuthenticatorAuthoritative/FCGIDAuthenticatorAuthoritative/g
s/^FastCgiAuthorizer/FCGIDAuthorizer/g
s/^FastCgiAuthorizerAuthoritative/FCGIDAuthorizerAuthoritative/g
s/^FCGIWrapper/FCGIDWrapper/g
s/^IdleScanInterval/FCGIDIdleScanInterval/g
s/^IdleTimeout/FCGIDIdleTimeout/g
s/^IPCCommTimeout/FCGIDIOTimeout/g
s/^IPCConnectTimeout/FCGIDConnectTimeout/g
s/^MaxProcessCount/FCGIDMaxProcesses/g
s/^MaxRequestInMem/FCGIDMaxRequestInMem/g
s/^MaxRequestLen/FCGIDMaxRequestLen/g
s/^MaxRequestsPerProcess/FCGIDMaxRequestsPerProcess/g
s/^OutputBufferSize/FCGIDOutputBufferSize/g
s/^PassHeader/FCGIDPassHeader/g
s/^PHP_Fix_Pathinfo_Enable/FCGIDFixPathinfo/g
s/^ProcessLifeTime/FCGIDProcessLifeTime/g
s/^SharememPath/FCGIDProcessTableFile/g
s/^SocketPath/FCGIDIPCDir/g
s/^SpawnScore/FCGIDSpawnScore/g
s/^SpawnScoreUpLimit/FCGIDSpawnScoreUpLimit/g
s/^TerminationScore/FCGIDTerminationScore/g
s/^TimeScore/FCGIDTimeScore/g
s/^ZombieScanInterval/FCGIDZombieScanInterval/g
# Next we fix all other occurences without matching
# the ones, that are already OK
s/\([^D]\)BusyScanInterval/\1FCGIDBusyScanInterval/g
s/\([^D]\)BusyTimeout/\1FCGIDBusyTimeout/g
s/\([^D]\)DefaultInitEnv/\1FCGIDInitialEnv/g
s/\([^D]\)DefaultMaxClassProcessCount/\1FCGIDMaxProcessesPerClass/g
s/\([^D]\)DefaultMinClassProcessCount/\1FCGIDMinProcessesPerClass/g
s/\([^D]\)ErrorScanInterval/\1FCGIDErrorScanInterval/g
s/\([^D]\)FastCgiAccessChecker/\1FCGIDAccessChecker/g
s/\([^D]\)FastCgiAccessCheckerAuthoritative/\1FCGIDAccessCheckerAuthoritative/g
s/\([^D]\)FastCgiAuthenticator/\1FCGIDAuthenticator/g
s/\([^D]\)FastCgiAuthenticatorAuthoritative/\1FCGIDAuthenticatorAuthoritative/g
s/\([^D]\)FastCgiAuthorizer/\1FCGIDAuthorizer/g
s/\([^D]\)FastCgiAuthorizerAuthoritative/\1FCGIDAuthorizerAuthoritative/g
s/\([^D]\)FCGIWrapper/\1FCGIDWrapper/g
s/\([^D]\)IdleScanInterval/\1FCGIDIdleScanInterval/g
s/\([^D]\)IdleTimeout/\1FCGIDIdleTimeout/g
s/\([^D]\)IPCCommTimeout/\1FCGIDIOTimeout/g
s/\([^D]\)IPCConnectTimeout/\1FCGIDConnectTimeout/g
s/\([^D]\)MaxProcessCount/\1FCGIDMaxProcesses/g
s/\([^D]\)MaxRequestInMem/\1FCGIDMaxRequestInMem/g
s/\([^D]\)MaxRequestLen/\1FCGIDMaxRequestLen/g
s/\([^D]\)MaxRequestsPerProcess/\1FCGIDMaxRequestsPerProcess/g
s/\([^D]\)OutputBufferSize/\1FCGIDOutputBufferSize/g
s/\([^D]\)PassHeader/\1FCGIDPassHeader/g
s/\([^D]\)PHP_Fix_Pathinfo_Enable/\1FCGIDFixPathinfo/g
s/\([^D]\)ProcessLifeTime/\1FCGIDProcessLifeTime/g
s/\([^D]\)SharememPath/\1FCGIDProcessTableFile/g
s/\([^D]\)SocketPath/\1FCGIDIPCDir/g
s/\([^D]\)SpawnScore/\1FCGIDSpawnScore/g
s/\([^D]\)SpawnScoreUpLimit/\1FCGIDSpawnScoreUpLimit/g
s/\([^D]\)TerminationScore/\1FCGIDTerminationScore/g
s/\([^D]\)TimeScore/\1FCGIDTimeScore/g
s/\([^D]\)ZombieScanInterval/\1FCGIDZombieScanInterval/g
