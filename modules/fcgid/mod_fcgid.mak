# Microsoft Developer Studio Generated NMAKE File, Based on mod_fcgid.dsp
!IF "$(CFG)" == ""
CFG=mod_fcgid - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_fcgid - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_fcgid - Win32 Release" && "$(CFG)" != "mod_fcgid - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_fcgid.mak" CFG="mod_fcgid - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_fcgid - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_fcgid - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_fcgid - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\mod_fcgid.so" "$(DS_POSTBUILD_DEP)"


CLEAN :
	-@erase "$(INTDIR)\fcgid_bridge.obj"
	-@erase "$(INTDIR)\fcgid_bucket.obj"
	-@erase "$(INTDIR)\fcgid_conf.obj"
	-@erase "$(INTDIR)\fcgid_filter.obj"
	-@erase "$(INTDIR)\fcgid_pm_main.obj"
	-@erase "$(INTDIR)\fcgid_pm_win.obj"
	-@erase "$(INTDIR)\fcgid_proc_win.obj"
	-@erase "$(INTDIR)\fcgid_proctbl_win.obj"
	-@erase "$(INTDIR)\fcgid_protocol.obj"
	-@erase "$(INTDIR)\fcgid_spawn_ctl.obj"
	-@erase "$(INTDIR)\mod_fcgid.obj"
	-@erase "$(INTDIR)\mod_fcgid.res"
	-@erase "$(INTDIR)\mod_fcgid_src.idb"
	-@erase "$(INTDIR)\mod_fcgid_src.pdb"
	-@erase "$(OUTDIR)\mod_fcgid.exp"
	-@erase "$(OUTDIR)\mod_fcgid.lib"
	-@erase "$(OUTDIR)\mod_fcgid.pdb"
	-@erase "$(OUTDIR)\mod_fcgid.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "$(APACHE2_HOME)/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_fcgid_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_fcgid.res" /i "../../srclib/apr/include" /i "$(APACHE2_HOME)/include" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_fcgid.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=libhttpd.lib libaprutil-1.lib libapr-1.lib kernel32.lib /nologo /base:"0x46430000" /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_fcgid.pdb" /debug /out:"$(OUTDIR)\mod_fcgid.so" /implib:"$(OUTDIR)\mod_fcgid.lib" /libpath:"..\..\Release" /libpath:"..\..\srclib\apr\Release" /libpath:"..\..\srclib\apr-util\Release" /libpath:"$(APACHE2_HOME)/lib" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\fcgid_bridge.obj" \
	"$(INTDIR)\fcgid_bucket.obj" \
	"$(INTDIR)\fcgid_conf.obj" \
	"$(INTDIR)\fcgid_filter.obj" \
	"$(INTDIR)\fcgid_pm_main.obj" \
	"$(INTDIR)\fcgid_pm_win.obj" \
	"$(INTDIR)\fcgid_proc_win.obj" \
	"$(INTDIR)\fcgid_proctbl_win.obj" \
	"$(INTDIR)\fcgid_protocol.obj" \
	"$(INTDIR)\fcgid_spawn_ctl.obj" \
	"$(INTDIR)\mod_fcgid.obj" \
	"$(INTDIR)\mod_fcgid.res"

"$(OUTDIR)\mod_fcgid.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_fcgid.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_fcgid.so"
   if exist .\Release\mod_fcgid.so.manifest mt.exe -manifest .\Release\mod_fcgid.so.manifest -outputresource:.\Release\mod_fcgid.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_fcgid - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : ".\fcgid_config.h" "$(OUTDIR)\mod_fcgid.so" "$(DS_POSTBUILD_DEP)"


CLEAN :
	-@erase "$(INTDIR)\fcgid_bridge.obj"
	-@erase "$(INTDIR)\fcgid_bucket.obj"
	-@erase "$(INTDIR)\fcgid_conf.obj"
	-@erase "$(INTDIR)\fcgid_filter.obj"
	-@erase "$(INTDIR)\fcgid_pm_main.obj"
	-@erase "$(INTDIR)\fcgid_pm_win.obj"
	-@erase "$(INTDIR)\fcgid_proc_win.obj"
	-@erase "$(INTDIR)\fcgid_proctbl_win.obj"
	-@erase "$(INTDIR)\fcgid_protocol.obj"
	-@erase "$(INTDIR)\fcgid_spawn_ctl.obj"
	-@erase "$(INTDIR)\mod_fcgid.obj"
	-@erase "$(INTDIR)\mod_fcgid.res"
	-@erase "$(INTDIR)\mod_fcgid_src.idb"
	-@erase "$(INTDIR)\mod_fcgid_src.pdb"
	-@erase "$(OUTDIR)\mod_fcgid.exp"
	-@erase "$(OUTDIR)\mod_fcgid.lib"
	-@erase "$(OUTDIR)\mod_fcgid.pdb"
	-@erase "$(OUTDIR)\mod_fcgid.so"
	-@erase ".\fcgid_config.h"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "$(APACHE2_HOME)/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_fcgid_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_fcgid.res" /i "../../srclib/apr/include" /i "$(APACHE2_HOME)/include" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_fcgid.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=libhttpd.lib libaprutil-1.lib libapr-1.lib kernel32.lib /nologo /base:"0x46430000" /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_fcgid.pdb" /debug /out:"$(OUTDIR)\mod_fcgid.so" /implib:"$(OUTDIR)\mod_fcgid.lib" /libpath:"..\..\Debug" /libpath:"..\..\srclib\apr\Debug" /libpath:"..\..\srclib\apr-util\Debug" /libpath:"$(APACHE2_HOME)/lib" 
LINK32_OBJS= \
	"$(INTDIR)\fcgid_bridge.obj" \
	"$(INTDIR)\fcgid_bucket.obj" \
	"$(INTDIR)\fcgid_conf.obj" \
	"$(INTDIR)\fcgid_filter.obj" \
	"$(INTDIR)\fcgid_pm_main.obj" \
	"$(INTDIR)\fcgid_pm_win.obj" \
	"$(INTDIR)\fcgid_proc_win.obj" \
	"$(INTDIR)\fcgid_proctbl_win.obj" \
	"$(INTDIR)\fcgid_protocol.obj" \
	"$(INTDIR)\fcgid_spawn_ctl.obj" \
	"$(INTDIR)\mod_fcgid.obj" \
	"$(INTDIR)\mod_fcgid.res"

"$(OUTDIR)\mod_fcgid.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_fcgid.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_fcgid.so"
   if exist .\Debug\mod_fcgid.so.manifest mt.exe -manifest .\Debug\mod_fcgid.so.manifest -outputresource:.\Debug\mod_fcgid.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_fcgid.dep")
!INCLUDE "mod_fcgid.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_fcgid.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_fcgid - Win32 Release" || "$(CFG)" == "mod_fcgid - Win32 Debug"
SOURCE=.\fcgid_bridge.c

"$(INTDIR)\fcgid_bridge.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_bucket.c

"$(INTDIR)\fcgid_bucket.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_conf.c

"$(INTDIR)\fcgid_conf.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=".\fcgid_config.h.in"

!IF  "$(CFG)" == "mod_fcgid - Win32 Release"

InputPath=".\fcgid_config.h.in"

".\fcgid_config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	echo /* No configuration */ > .\fcgid_config.h
<< 
	

!ELSEIF  "$(CFG)" == "mod_fcgid - Win32 Debug"

InputPath=".\fcgid_config.h.in"

".\fcgid_config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	echo /* No configuration */ > .\fcgid_config.h
<< 
	

!ENDIF 

SOURCE=.\fcgid_filter.c

"$(INTDIR)\fcgid_filter.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_pm_main.c

"$(INTDIR)\fcgid_pm_main.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_pm_win.c

"$(INTDIR)\fcgid_pm_win.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_proc_win.c

"$(INTDIR)\fcgid_proc_win.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_proctbl_win.c

"$(INTDIR)\fcgid_proctbl_win.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_protocol.c

"$(INTDIR)\fcgid_protocol.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\fcgid_spawn_ctl.c

"$(INTDIR)\fcgid_spawn_ctl.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\mod_fcgid.c

"$(INTDIR)\mod_fcgid.obj" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"


SOURCE=.\mod_fcgid.rc

"$(INTDIR)\mod_fcgid.res" : $(SOURCE) "$(INTDIR)" ".\fcgid_config.h"
	$(RSC) $(RSC_PROJ) $(SOURCE)



!ENDIF 

