@echo off
setlocal enabledelayedexpansion

rem ===========================================================================
rem  build.bat  —  Build the binja-ghidra project (Windows)
rem ===========================================================================
rem  Usage:  build.bat [clean] [install] [bridge] [plugin] [qt]
rem                    [--channel stable^|dev] [--bn-api ^<commit^>]
rem
rem    (no args)  Build both the C++ plugin and the Java bridge JAR (if Java available)
rem    clean      Delete build directories before building
rem    install    Copy the plugin (and JAR if built) into the BN plugins folder
rem    bridge     Build the Java bridge JAR only + package for server deployment
rem    plugin     Build the C++ plugin only (skips Java bridge)
rem    qt         Build Qt 6 via the qt-build submodule (~1-2 hours, first time only)
rem
rem  Binary Ninja API version (pick the one matching your installed BN):
rem    --channel stable   Fetch + build against the latest stable release (default)
rem    --channel dev      Fetch + build against the latest dev (dev branch head)
rem    --bn-api <commit>  Build against an explicit commit (no GitHub lookup)
rem    (--channel and --bn-api are mutually exclusive; stable is the default.
rem     --channel queries the binaryninja-api GitHub, so it needs network access.)
rem
rem  Examples:
rem    build.bat                   — build everything (Java optional — warns if missing)
rem    build.bat clean install     — clean rebuild + install into BN
rem    build.bat plugin            — C++ plugin only, no Java required
rem    build.bat bridge            — build bridge JAR + create server-package\
rem    build.bat qt                — compile Qt (required once on a fresh machine)
rem
rem  Bridge modes (configured in BN Settings -> Ghidra -> Bridge Mode):
rem    local   — bridge JAR runs on this machine alongside BN (default)
rem              Java + Ghidra must be installed locally; JAR installed next to plugin
rem    remote  — bridge runs as a service on the Ghidra server machine
rem              Run build.bat bridge, copy server-package\ to server, run start-bridge.bat
rem ===========================================================================

rem ---------------------------------------------------------------------------
rem  Configuration  — adjust paths here if your environment differs
rem ---------------------------------------------------------------------------
rem  JAVA_HOME is taken from the environment (needed only for the bridge JAR).
rem  Set it to a JDK 17+ install before building the bridge; the check below
rem  reports an actionable error if it is missing or invalid.
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\Tools\VsDevCmd.bat"
set "CMAKE_EXE=C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA_EXE=C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
set "BN_INSTALL=C:\Program Files\Vector35\BinaryNinja"

rem Binary Ninja API commit is resolved from GitHub at build time (see the
rem channel-resolution section below): --channel stable fetches the latest
rem stable release, --channel dev fetches the dev branch head, and
rem --bn-api <sha> pins an explicit commit without contacting GitHub.
set "BN_API_REPO=https://api.github.com/repos/Vector35/binaryninja-api"

rem Qt version must match qt-build\target_qt6_version.py
set "QT_VERSION=6.10.1"
set "QT_COMPILER=msvc2022_64"

rem Qt6_DIR resolution — edit the fallback path if you have Qt installed elsewhere.
rem Priority: 1) locally built qt-build output  2) explicit path below
set "LOCAL_QT=%~dp0qt\%QT_VERSION%\%QT_COMPILER%\lib\cmake\Qt6"
if exist "%LOCAL_QT%\Qt6Config.cmake" (
    set "Qt6_DIR=%LOCAL_QT%"
    set "QMAKE_BIN=%~dp0qt\%QT_VERSION%\%QT_COMPILER%\bin"
) else (
    rem Fallback: set these to your Qt install if you have one outside the repo.
    set "Qt6_DIR=C:\qt\v6.7.2\lib\cmake\Qt6"
    set "QMAKE_BIN=C:\qt\v6.7.2\bin"
)

set "BRIDGE_DIR=%~dp0bridge"
set "PLUGIN_DIR=%~dp0plugin"
set "PLUGIN_BUILD=%PLUGIN_DIR%\build"
set "BRIDGE_JAR=%BRIDGE_DIR%\build\libs\ghidra-bridge-0.1.0.jar"
set "SERVER_PKG=%~dp0server-package"

rem ---------------------------------------------------------------------------
rem  Parse arguments
rem ---------------------------------------------------------------------------
set DO_CLEAN=0
set DO_INSTALL=0
set DO_QT=0
set DO_BRIDGE=1
set DO_PLUGIN=1
set BRIDGE_ONLY=0
set PLUGIN_ONLY=0
set "BN_CHANNEL="
set "BN_API_COMMIT="

rem Use 'shift /1' (not plain 'shift') so %0 — and thus %~dp0 below — is
rem preserved; plain shift renumbers %0 as well and would corrupt the script path.
:argloop
if "%~1"=="" goto argdone
if /I "%~1"=="clean"     ( set DO_CLEAN=1     & shift /1 & goto argloop )
if /I "%~1"=="install"   ( set DO_INSTALL=1   & shift /1 & goto argloop )
if /I "%~1"=="bridge"    ( set BRIDGE_ONLY=1  & shift /1 & goto argloop )
if /I "%~1"=="plugin"    ( set PLUGIN_ONLY=1  & shift /1 & goto argloop )
if /I "%~1"=="qt"        ( set DO_QT=1        & shift /1 & goto argloop )
rem %~2 is captured before the shifts run (the whole line is parsed at once).
if /I "%~1"=="--channel"  ( set "BN_CHANNEL=%~2"    & shift /1 & shift /1 & goto argloop )
if /I "%~1"=="--bn-api"   ( set "BN_API_COMMIT=%~2" & shift /1 & shift /1 & goto argloop )
echo WARNING: ignoring unknown argument '%~1'
shift /1
goto argloop
:argdone

if %BRIDGE_ONLY%==1 if %PLUGIN_ONLY%==0 set DO_PLUGIN=0
if %PLUGIN_ONLY%==1 if %BRIDGE_ONLY%==0 set DO_BRIDGE=0

rem ---------------------------------------------------------------------------
rem  Resolve the Binary Ninja API commit from --channel / --bn-api
rem  (mutually exclusive; defaults to the stable channel).
rem ---------------------------------------------------------------------------
if defined BN_CHANNEL if defined BN_API_COMMIT (
    echo ERROR: pass either --channel or --bn-api, not both.
    exit /b 1
)
rem An explicit --bn-api commit skips the GitHub lookup entirely.
if defined BN_API_COMMIT goto :bn_have_commit

if not defined BN_CHANNEL set "BN_CHANNEL=stable"
set "_CH_OK=0"
if /I "!BN_CHANNEL!"=="stable" set "_CH_OK=1"
if /I "!BN_CHANNEL!"=="dev"    set "_CH_OK=1"
if not "!_CH_OK!"=="1" (
    echo ERROR: --channel must be 'stable' or 'dev' ^(got '!BN_CHANNEL!'^).
    exit /b 1
)

echo Fetching latest '!BN_CHANNEL!' binaryninja-api commit from GitHub...
rem Kept at top level (not inside an if(...) block): the parentheses in the
rem PowerShell command would otherwise unbalance batch's block parsing.
rem PowerShell does the HTTPS request + JSON parse (the curl equivalent on
rem Windows): dev -> dev branch head; stable -> latest stable release's commit.
for /f "usebackq delims=" %%S in (`powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; $b='%BN_API_REPO%'; try { if ('!BN_CHANNEL!' -eq 'dev') { (Invoke-RestMethod ($b+'/commits/dev')).sha } else { $t=(Invoke-RestMethod ($b+'/releases/latest')).tag_name; (Invoke-RestMethod ($b+'/commits/'+$t)).sha } } catch { '' }"`) do set "BN_API_COMMIT=%%S"

if not defined BN_API_COMMIT (
    echo ERROR: could not fetch the latest '!BN_CHANNEL!' binaryninja-api commit from GitHub.
    echo        Check your network connection, or pass --bn-api ^<commit^> explicitly.
    exit /b 1
)

:bn_have_commit
if defined BN_CHANNEL (
    echo Binary Ninja API: channel '!BN_CHANNEL!' -^> commit !BN_API_COMMIT!
) else (
    echo Binary Ninja API: explicit commit !BN_API_COMMIT!
)

rem ---------------------------------------------------------------------------
rem  Set up VS developer environment (required for C++ build; harmless otherwise)
rem ---------------------------------------------------------------------------
call "%VSDEVCMD%" -startdir=none -arch=x64 -host_arch=x64
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to initialise VS developer environment.
    exit /b 1
)

rem Add qmake to PATH so FindBinaryNinjaUI.cmake can locate Qt automatically.
set "PATH=%QMAKE_BIN%;%PATH%"

rem ---------------------------------------------------------------------------
rem  Ensure qt-build submodule is populated (fast — just checks out scripts)
rem ---------------------------------------------------------------------------
if not exist "%~dp0qt-build\build_win64.bat" (
    echo.
    echo Initialising qt-build submodule...
    git -C "%~dp0" submodule update --init qt-build
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Failed to initialise qt-build submodule.
        exit /b %ERRORLEVEL%
    )
)

rem ---------------------------------------------------------------------------
rem  Build Qt (only when explicitly requested with the 'qt' argument)
rem
rem  Guarded with 'goto' rather than a 120-line 'if (...)' block: after VsDevCmd
rem  runs, %PATH% contains parentheses (e.g. "Program Files (x86)"), which cmd
rem  expands at parse time and which break paren-matching across a large block
rem  ("0 was unexpected at this time").  A goto skips the section without parsing
rem  it as one block.
rem ---------------------------------------------------------------------------
if not "%DO_QT%"=="1" goto :skip_qt
    echo.
    echo ====== Building Qt %QT_VERSION% via qt-build submodule ======
    echo This takes 1-2 hours on a fresh machine.
    echo.

    rem ---- Check and install prerequisites ----------------------------------
    set _LLVM_VER=19.1.7
    set "_LIBCLANG_DIR=%USERPROFILE%\libclang\%_LLVM_VER%"
    set _MISSING_DEPS=0

    rem Poetry
    where poetry >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo Installing Poetry...
        where winget >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            winget install --id Python.Poetry --silent --accept-source-agreements --accept-package-agreements
        ) else (
            where pip >nul 2>&1
            if %ERRORLEVEL% EQU 0 (
                pip install --user poetry
            ) else (
                echo ERROR: Cannot install Poetry - winget and pip not found.
                echo        Install Poetry manually: https://python-poetry.org/docs/
                set _MISSING_DEPS=1
            )
        )
        rem Refresh PATH so poetry is available immediately
        set "PATH=%APPDATA%\Python\Scripts;%LOCALAPPDATA%\Programs\Python\Scripts;%PATH%"
    )

    rem libclang — qt6_build.py looks for %USERPROFILE%\libclang\<version>\
    if not exist "%_LIBCLANG_DIR%" (
        mkdir "%USERPROFILE%\libclang" 2>nul
        echo libclang %_LLVM_VER% not found. Installing...

        rem Try winget first (installs to C:\Program Files\LLVM)
        where winget >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            echo Installing LLVM %_LLVM_VER% via winget...
            winget install --id LLVM.LLVM --version %_LLVM_VER% --silent --accept-source-agreements --accept-package-agreements
            if exist "C:\Program Files\LLVM\bin\clang.exe" (
                rem Junction point — no admin required unlike /D symlinks
                mklink /J "%_LIBCLANG_DIR%" "C:\Program Files\LLVM"
                echo Linked C:\Program Files\LLVM to %_LIBCLANG_DIR%
            )
        )

        rem Fallback: download tarball from GitHub (Windows 10 1903+ tar supports .xz)
        if not exist "%_LIBCLANG_DIR%" (
            set "_LLVM_TAR=clang+llvm-%_LLVM_VER%-x86_64-pc-windows-msvc.tar.xz"
            set "_LLVM_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-%_LLVM_VER%/clang%%2Bllvm-%_LLVM_VER%-x86_64-pc-windows-msvc.tar.xz"
            echo Downloading LLVM %_LLVM_VER% from GitHub (~800 MB^)...
            curl -L --progress-bar "%_LLVM_URL%" -o "%TEMP%\%_LLVM_TAR%"
            if %ERRORLEVEL% NEQ 0 (
                echo ERROR: Download failed.
                set _MISSING_DEPS=1
            ) else (
                echo Extracting...
                tar -xf "%TEMP%\%_LLVM_TAR%" -C "%USERPROFILE%\libclang"
                rem GitHub tarball extracts to clang+llvm-<ver>-..., rename to version number
                for /D %%D in ("%USERPROFILE%\libclang\clang+llvm-*") do (
                    rename "%%D" "%_LLVM_VER%"
                )
                del "%TEMP%\%_LLVM_TAR%"
                echo Installed to %_LIBCLANG_DIR%
            )
        )

        if not exist "%_LIBCLANG_DIR%" (
            echo ERROR: Could not install libclang. Install LLVM %_LLVM_VER% manually.
            echo        Place it at %_LIBCLANG_DIR% or set LLVM_INSTALL_DIR in your environment.
            set _MISSING_DEPS=1
        )
    )

    if %_MISSING_DEPS% NEQ 0 (
        echo.
        echo ERROR: Missing prerequisites - fix the errors above and re-run: build.bat qt
        exit /b 1
    )

    rem ---- Run the Qt build -------------------------------------------------
    rem Run from qt-build\ — poetry looks for pyproject.toml in the working directory.
    rem QT_INSTALL_DIR tells qt6_build.py where to copy the finished build.
    set "QT_INSTALL_DIR=%~dp0qt"
    pushd "%~dp0qt-build"
    call build_win64.bat --no-pyside --no-prompt
    set QT_BUILD_ERR=%ERRORLEVEL%
    popd
    if %QT_BUILD_ERR% NEQ 0 (
        echo ERROR: Qt build failed.
        exit /b %QT_BUILD_ERR%
    )

    rem Point Qt6_DIR at the freshly built Qt for the re-configure.
    set "Qt6_DIR=%~dp0qt\%QT_VERSION%\%QT_COMPILER%\lib\cmake\Qt6"
    set "QMAKE_BIN=%~dp0qt\%QT_VERSION%\%QT_COMPILER%\bin"
    set "PATH=%QMAKE_BIN%;%PATH%"

    echo.
    echo Qt build complete. Re-running CMake configure to pick up Qt...
    "%CMAKE_EXE%" ^
        -B "%PLUGIN_BUILD%" ^
        -S "%PLUGIN_DIR%" ^
        -G Ninja ^
        -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" ^
        -DQt6_DIR="%Qt6_DIR%" ^
        -DBN_INSTALL_DIR="%BN_INSTALL%" ^
        -DBN_API_COMMIT_OVERRIDE="%BN_API_COMMIT%" ^
        -DCMAKE_BUILD_TYPE=RelWithDebInfo
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: CMake configure failed.
        exit /b %ERRORLEVEL%
    )
    echo.
    echo Qt is ready. Re-run build.bat to build the plugin.
    exit /b 0
:skip_qt

rem ---------------------------------------------------------------------------
rem  Clean
rem ---------------------------------------------------------------------------
if %DO_CLEAN%==1 (
    echo.
    echo Cleaning build directories...
    if exist "%PLUGIN_BUILD%"     rmdir /s /q "%PLUGIN_BUILD%"
    if exist "%BRIDGE_DIR%\build" rmdir /s /q "%BRIDGE_DIR%\build"
    if exist "%SERVER_PKG%"       rmdir /s /q "%SERVER_PKG%"
    echo Done.
)

rem ---------------------------------------------------------------------------
rem  Build Java bridge
rem ---------------------------------------------------------------------------
if %DO_BRIDGE%==1 (
    rem Bridge build needs a JDK; require JAVA_HOME from the environment.
    rem Use delayed (!JAVA_HOME!) expansion so a path containing parentheses
    rem (e.g. "Program Files (x86)") doesn't break parsing of this block.
    set "_JAVA_OK=1"
    if not defined JAVA_HOME set "_JAVA_OK=0"
    if defined JAVA_HOME if not exist "!JAVA_HOME!\bin\java.exe" set "_JAVA_OK=0"
    if "!_JAVA_OK!"=="0" (
        echo.
        if %BRIDGE_ONLY%==1 (
            echo ERROR: JAVA_HOME is not set ^(or has no bin\java.exe^) - cannot build the bridge JAR.
            echo        Set JAVA_HOME to a JDK 17+ install and re-run, e.g.:
            echo            set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.x-hotspot"
            exit /b 1
        ) else (
            echo NOTE: JAVA_HOME is not set ^(or has no bin\java.exe^) - skipping bridge JAR build.
            echo       Set JAVA_HOME to a JDK 17+ install, then: build.bat bridge
            echo       ^(Java is needed on the build machine to compile the JAR;
            echo        it runs on the Ghidra server in remote mode, or locally in local mode.^)
            set DO_BRIDGE=0
        )
    )
)

if %DO_BRIDGE%==1 (
    echo.
    echo ====== Building Java bridge JAR ======
    pushd "%BRIDGE_DIR%"
    rem Call with an explicit path: VS dev environments often set
    rem NoDefaultCurrentDirectoryInExePath, so a bare 'gradlew.bat' isn't found.
    call "%BRIDGE_DIR%\gradlew.bat" shadowJar
    set BUILD_ERR=!ERRORLEVEL!
    popd
    if !BUILD_ERR! NEQ 0 (
        echo ERROR: Bridge build failed.
        exit /b !BUILD_ERR!
    )
    echo Bridge JAR: %BRIDGE_JAR%

    rem ---- Package for server deployment ------------------------------------
    echo.
    echo ====== Packaging bridge for server deployment ======
    if exist "%SERVER_PKG%" rmdir /s /q "%SERVER_PKG%"
    mkdir "%SERVER_PKG%"
    copy "%BRIDGE_JAR%"                         "%SERVER_PKG%\" >nul
    copy "%~dp0server\start-bridge.sh"          "%SERVER_PKG%\" >nul
    copy "%~dp0server\start-bridge.bat"         "%SERVER_PKG%\" >nul

    rem Write README
    (
        echo Ghidra Bridge -- Server Deployment Package
        echo ==========================================
        echo.
        echo This package runs on the same machine as your Ghidra Server.
        echo Java ^(JDK 17+^) and a Ghidra installation are required on the server.
        echo.
        echo Quick start ^(Linux / macOS^)
        echo ---------------------------
        echo 1. Copy this directory to the Ghidra server machine.
        echo 2. Set GHIDRA_HOME to your Ghidra installation:
        echo      export GHIDRA_HOME=/path/to/ghidra_12.x_PUBLIC
        echo 3. Start the bridge:
        echo      ./start-bridge.sh
        echo    The bridge listens on port 13200 by default.  Use --port N to change it.
        echo.
        echo Quick start ^(Windows^)
        echo ---------------------
        echo 1. Copy this directory to the Ghidra server machine.
        echo 2. Set GHIDRA_HOME in the environment or edit start-bridge.bat.
        echo 3. Run start-bridge.bat.
        echo.
        echo Firewall
        echo --------
        echo Allow TCP port 13200 inbound from your Binary Ninja client machine^(s^).
        echo The bridge has no built-in authentication -- restrict access at the
        echo firewall level to trusted hosts only.
        echo.
        echo Binary Ninja settings
        echo ---------------------
        echo In BN: Settings -^> Ghidra -^> Bridge Mode  -^> set to "remote"
        echo         Settings -^> Ghidra -^> Bridge Port  -^> set to match port above ^(default: 13200^)
        echo The bridge host is always the same as the Ghidra Server host entered
        echo in the Connect dialog -- no separate host configuration needed.
        echo.
        echo Running as a Windows service
        echo ----------------------------
        echo Use NSSM ^(https://nssm.cc^) or Task Scheduler to run start-bridge.bat at startup.
        echo Example with NSSM:
        echo   nssm install GhidraBridge "C:\path\to\server-package\start-bridge.bat"
        echo   nssm set GhidraBridge AppEnvironmentExtra GHIDRA_HOME=C:\path\to\ghidra
        echo   nssm start GhidraBridge
    ) > "%SERVER_PKG%\README.txt"

    echo.
    echo Server package: %SERVER_PKG%\
    echo Copy server-package\ to your Ghidra server machine and run start-bridge.bat
    echo ^(needed only if using remote bridge mode^).
)

rem ---------------------------------------------------------------------------
rem  Build C++ plugin
rem ---------------------------------------------------------------------------
if %DO_PLUGIN%==1 (
    echo.
    echo ====== Configuring C++ plugin ======
    "%CMAKE_EXE%" ^
        -B "%PLUGIN_BUILD%" ^
        -S "%PLUGIN_DIR%" ^
        -G Ninja ^
        -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" ^
        -DQt6_DIR="%Qt6_DIR%" ^
        -DBN_INSTALL_DIR="%BN_INSTALL%" ^
        -DBN_API_COMMIT_OVERRIDE="%BN_API_COMMIT%" ^
        -DCMAKE_BUILD_TYPE=RelWithDebInfo
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: CMake configure failed.
        exit /b %ERRORLEVEL%
    )

    rem Detect if CMake returned early due to missing Qt (plugin target absent).
    "%CMAKE_EXE%" --build "%PLUGIN_BUILD%" --target help 2>&1 | findstr /C:"binja-ghidra" >nul
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo ======================================================
        echo   Qt 6 not found -- plugin cannot be built yet.
        echo.
        echo   Run once to compile Qt ^(~1-2 hours^):
        echo     build.bat qt
        echo.
        echo   Then build normally:
        echo     build.bat
        echo ======================================================
        exit /b 1
    )

    echo.
    echo ====== Building C++ plugin ======
    "%CMAKE_EXE%" --build "%PLUGIN_BUILD%" --config RelWithDebInfo -j 8
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Plugin build failed.
        exit /b %ERRORLEVEL%
    )
    echo Plugin DLL: %PLUGIN_BUILD%\binja-ghidra.dll
)

rem ---------------------------------------------------------------------------
rem  Install into Binary Ninja plugins folder
rem ---------------------------------------------------------------------------
if %DO_INSTALL%==1 (
    echo.
    echo ====== Installing ======

    rem Use delayed (!BN_PLUGINS!) expansion below: %BN_PLUGINS% would expand at
    rem parse time of this if(...) block, before this set runs, i.e. to empty.
    set "BN_PLUGINS=%APPDATA%\Binary Ninja\plugins"
    if not exist "!BN_PLUGINS!" mkdir "!BN_PLUGINS!"

    rem Install the C++ plugin (and JAR via cmake OPTIONAL install rule) whenever
    rem cmake has already been configured for this build directory.
    if exist "%PLUGIN_BUILD%\cmake_install.cmake" (
        "%CMAKE_EXE%" --install "%PLUGIN_BUILD%" --config RelWithDebInfo
        if !ERRORLEVEL! NEQ 0 (
            echo ERROR: Plugin install failed.
            exit /b !ERRORLEVEL!
        )
    ) else (
        if %DO_PLUGIN%==1 (
            echo ERROR: Plugin build directory not found -- run without 'install' first, or
            echo        run 'build.bat' ^(no args^) to build everything before installing.
            exit /b 1
        )
    )

    rem Always explicitly copy the JAR when it was built in this run (belt-and-suspenders:
    rem covers bridge-only mode where cmake may never have been configured, and also makes
    rem it obvious when the JAR is fresh even if cmake's OPTIONAL rule would silently skip it).
    if %DO_BRIDGE%==1 (
        if exist "%BRIDGE_JAR%" (
            copy /Y "%BRIDGE_JAR%" "!BN_PLUGINS!" >nul
            echo Bridge JAR: !BN_PLUGINS!\ghidra-bridge-0.1.0.jar
        )
    )

    echo Installed to: !BN_PLUGINS!\
)

echo.
echo ====== Build complete ======
