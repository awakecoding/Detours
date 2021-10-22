##############################################################################
##
##  API Extention to Measure time slept.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) kernel32.lib ws2_32.lib

##############################################################################

all: dirs \
    $(BIND)\mstscex.dll
    \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\mstscex.bsc
!ENDIF

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\mstscex.obj : mstscex.cpp

$(OBJD)\mstscex.res : mstscex.rc

$(BIND)\mstscex.dll $(BIND)\mstscex.lib: \
        $(OBJD)\mstscex.obj $(OBJD)\mstscex.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$(@R).dll /Fd$(@R).pdb \
        $(OBJD)\mstscex.obj $(OBJD)\mstscex.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        $(LIBS)

$(OBJD)\mstscex.bsc : $(OBJD)\mstscex.obj
    bscmake /v /n /o $@ $(OBJD)\mstscex.sbr

##############################################################################

clean:
    -del *~ 2>nul
    -del $(BIND)\mstscex*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\mstscex.dll:
$(OPTD)\mstscex.pdb:

$(BIND)\mstscex.dll : $(OPTD)\mstscex.dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\mstscex.pdb : $(OPTD)\mstscex.pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\mstscex.dll \
    $(BIND)\mstscex.pdb \

!ELSE

option:

!ENDIF

##############################################################################

test: all
    @echo -------- Reseting test binaries to initial state. ---------------------
    $(BIND)\setdll.exe -r mstsc.exe
    @echo.
    @echo -------- Should not load mstscex.dll -----------------------------------
    mstsc.exe
    @echo.
    @echo -------- Adding mstscex.dll to mstsc.exe ------------------------------
    $(BIND)\setdll.exe -d:$(BIND)\mstscex.dll mstsc.exe
    @echo.
    @echo -------- Should load mstscex.dll statically ----------------------------
    mstsc.exe
    @echo.
    @echo -------- Removing mstscex.dll from mstsc.exe --------------------------
    $(BIND)\setdll.exe -r mstsc.exe
    @echo.
    @echo -------- Should not load mstscex.dll -----------------------------------
    mstsc.exe
    @echo.
    @echo -------- Should load mstscex.dll dynamically using withdll.exe----------
    $(BIND)\withdll.exe -d:$(BIND)\mstscex.dll mstsc.exe
    @echo.

debug: all
    windbg -o $(BIND)\withdll.exe -d:$(BIND)\mstscex.dll mstsc.exe


################################################################# End of File.
