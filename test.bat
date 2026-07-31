@echo off
setlocal enabledelayedexpansion

rem ===========================================================================
rem  test.bat  —  Build and run the binja-ghidra test suite (Windows)
rem ===========================================================================
rem  Usage:  test.bat [options]
rem
rem    (no args)   Run the C++ unit tests, the BN-headless/parity tests and
rem                the Java bridge tests (tiers 0-3)
rem    --cpp       C++ tests only (unit + BN-headless)
rem    --java      Java tests only
rem    --parity    Cross-DB parity tier only (C++ BN tests + gradlew parityTest)
rem    --e2e       Live Ghidra-server E2E tier (sets GHIDRA_E2E=1, gradlew e2eTest)
rem    --no-build  Skip the cmake --build step (use existing test binaries)
rem    --verbose   Pass --gtest_print_time=1 to C++ runner; show all Gradle output
rem
rem  Test tiers (see testdata/parity/RULES.md):
rem    0  Pure unit          binja-ghidra-tests + bridge *Test.java     always
rem    1  Ghidra round-trip  bridge *RoundTripTest.java                 needs GHIDRA_HOME
rem    2  BN .bndb tests     binja-ghidra-bn-tests                      SKIPs w/o BN license
rem    3  Cross-DB parity    CanonicalParityTest (C++ + Java)           shared goldens
rem    4  Live-server E2E    LiveServerE2ETest                          only via --e2e
rem
rem  Prerequisites:
rem    C++ tests: CMake build must be configured (cmake -B plugin\build -S plugin)
rem    BN tests:  Binary Ninja install on PATH; headless-capable license
rem               (BN_LICENSE env var is honoured); otherwise tests SKIP
rem    Java tests: JAVA_HOME set to a JDK 17+ install; bridge\gradle.properties
rem               must set ghidraHome
rem    E2E tests: runnable ghidraSvr under ghidraHome (full Ghidra install)
rem
rem  Exit code:
rem    0  All selected suites passed
rem    1  One or more suites failed or could not run
rem ===========================================================================

rem ---------------------------------------------------------------------------
rem  Configuration — mirror build.bat so paths resolve the same way
rem ---------------------------------------------------------------------------
rem Mirror build.bat: VsDevCmd provides the MSVC build environment and the
rem bundled cmake — neither is on PATH by default. Edit these to match your VS
rem install if it differs (same paths as build.bat).
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\Tools\VsDevCmd.bat"
set "CMAKE_EXE=C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
rem If you already have cmake on PATH inside a VS dev prompt: set "CMAKE_EXE=cmake"

rem Binary Ninja install dir — its binaryninjacore.dll must be on PATH so the
rem test executables can load (gtest discovers + runs them). Mirror build.bat.
set "BN_INSTALL=C:\Program Files\Vector35\BinaryNinja"

set "SCRIPT_DIR=%~dp0"
rem Remove trailing backslash
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "PLUGIN_BUILD=%SCRIPT_DIR%\plugin\build"
set "BRIDGE_DIR=%SCRIPT_DIR%\bridge"
set "TEST_EXE=%PLUGIN_BUILD%\binja-ghidra-tests.exe"
set "BN_TEST_EXE=%PLUGIN_BUILD%\binja-ghidra-bn-tests.exe"

rem ---------------------------------------------------------------------------
rem  Parse arguments
rem ---------------------------------------------------------------------------
set RUN_CPP=1
set RUN_BN=1
set RUN_JAVA=1
set RUN_E2E=0
set DO_BUILD=1
set VERBOSE=0
set JAVA_TASK=test

:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="--cpp"      ( set "RUN_JAVA=0" & shift & goto :parse_args )
if /i "%~1"=="--java"     ( set "RUN_CPP=0" & set "RUN_BN=0" & shift & goto :parse_args )
if /i "%~1"=="--parity"   ( set "RUN_CPP=0" & set "JAVA_TASK=parityTest" & shift & goto :parse_args )
if /i "%~1"=="--e2e"      ( set "RUN_CPP=0" & set "RUN_BN=0" & set "RUN_JAVA=0" & set "RUN_E2E=1" & shift & goto :parse_args )
if /i "%~1"=="--no-build" ( set "DO_BUILD=0" & shift & goto :parse_args )
if /i "%~1"=="--verbose"  ( set "VERBOSE=1" & shift & goto :parse_args )
if /i "%~1"=="--help"     ( goto :show_help )
if /i "%~1"=="-h"         ( goto :show_help )
echo WARNING: Unknown option: %~1
shift & goto :parse_args
:done_args

rem ---------------------------------------------------------------------------
rem  Tracking (0=not run, 1=passed, 2=failed, 3=error)
rem ---------------------------------------------------------------------------
set CPP_STATUS=0
set BN_STATUS=0
set JAVA_STATUS=0
set E2E_STATUS=0

rem Load the MSVC build environment so cmake --build -> ninja -> cl.exe works
rem (only needed when we actually build; harmless if cl is already on PATH).
if %DO_BUILD%==1 if not %RUN_CPP%%RUN_BN%==00 call "%VSDEVCMD%" -startdir=none -arch=x64 -host_arch=x64 >nul

rem Put binaryninjacore.dll on PATH so the test exes can load — needed both for
rem gtest's build-time test discovery and for actually running the binaries.
set "PATH=%BN_INSTALL%;%PATH%"

rem ---------------------------------------------------------------------------
rem  C++ unit tests (tier 0)
rem ---------------------------------------------------------------------------
if %RUN_CPP%==0 goto :skip_cpp

echo.
echo ====== C++ unit tests ======

rem Check the build has been configured
if not exist "%PLUGIN_BUILD%\build.ninja" (
if not exist "%PLUGIN_BUILD%\CMakeCache.txt" (
    echo ERROR: plugin\build has not been configured yet.
    echo        Run:  cmake -B plugin\build -S plugin   then try again.
    set CPP_STATUS=3
    goto :skip_cpp
))

rem Build the test binary
if %DO_BUILD%==1 (
    echo Building binja-ghidra-tests...
    "%CMAKE_EXE%" --build "%PLUGIN_BUILD%" --target binja-ghidra-tests
    if errorlevel 1 (
        echo ERROR: C++ test build failed.
        set CPP_STATUS=3
        goto :skip_cpp
    )
)

if not exist "%TEST_EXE%" (
    echo ERROR: Test binary not found at %TEST_EXE%
    echo        Build may have failed — run without --no-build to rebuild.
    set CPP_STATUS=3
    goto :skip_cpp
)

echo Running C++ test binary...
if %VERBOSE%==1 (
    "%TEST_EXE%" --gtest_color=yes --gtest_print_time=1
) else (
    "%TEST_EXE%" --gtest_color=yes
)

if errorlevel 1 (
    set CPP_STATUS=2
) else (
    set CPP_STATUS=1
)

:skip_cpp

rem ---------------------------------------------------------------------------
rem  BN-headless tests (tiers 2 + 3, C++ side) — SKIP cleanly without a license
rem ---------------------------------------------------------------------------
if %RUN_BN%==0 goto :skip_bn

echo.
echo ====== BN-headless / parity tests ======

if not exist "%PLUGIN_BUILD%\build.ninja" (
if not exist "%PLUGIN_BUILD%\CMakeCache.txt" (
    echo ERROR: plugin\build has not been configured yet.
    set BN_STATUS=3
    goto :skip_bn
))

if %DO_BUILD%==1 (
    echo Building binja-ghidra-bn-tests...
    "%CMAKE_EXE%" --build "%PLUGIN_BUILD%" --target binja-ghidra-bn-tests
    if errorlevel 1 (
        echo ERROR: BN test build failed.
        set BN_STATUS=3
        goto :skip_bn
    )
)

if not exist "%BN_TEST_EXE%" (
    echo ERROR: Test binary not found at %BN_TEST_EXE%
    set BN_STATUS=3
    goto :skip_bn
)

echo Running BN-headless test binary...
if %VERBOSE%==1 (
    "%BN_TEST_EXE%" --gtest_color=yes --gtest_print_time=1
) else (
    "%BN_TEST_EXE%" --gtest_color=yes
)

if errorlevel 1 (
    set BN_STATUS=2
) else (
    set BN_STATUS=1
)

:skip_bn

rem ---------------------------------------------------------------------------
rem  Java tests (tiers 0/1/3 via `test`, or parityTest / e2eTest tasks)
rem ---------------------------------------------------------------------------
if %RUN_JAVA%==0 if %RUN_E2E%==0 goto :skip_java

echo.
echo ====== Java bridge tests ======

rem Gradle uses JAVA_HOME; require it (matches build.bat). Delayed !JAVA_HOME!
rem expansion guards against a path with parentheses breaking this block.
set "_JAVA_OK=1"
if not defined JAVA_HOME set "_JAVA_OK=0"
if defined JAVA_HOME if not exist "!JAVA_HOME!\bin\java.exe" set "_JAVA_OK=0"
if "!_JAVA_OK!"=="0" (
    echo ERROR: JAVA_HOME is not set ^(or has no bin\java.exe^) - cannot run the Java tests.
    echo        Set JAVA_HOME to a JDK 17+ install and re-run.
    if %RUN_E2E%==1 ( set E2E_STATUS=3 ) else ( set JAVA_STATUS=3 )
    goto :skip_java
)

if not exist "%BRIDGE_DIR%\gradle.properties" (
    echo ERROR: bridge\gradle.properties not found.
    echo        Create it with:  ghidraHome=C:\path\to\ghidra_12.x_PUBLIC
    if %RUN_E2E%==1 ( set E2E_STATUS=3 ) else ( set JAVA_STATUS=3 )
    goto :skip_java
)

set "_GRADLE_TASK=%JAVA_TASK%"
if %RUN_E2E%==1 (
    set "_GRADLE_TASK=e2eTest"
    set "GHIDRA_E2E=1"
    echo Running live-server E2E tests ^(this starts a local ghidraSvr^)...
) else (
    echo Running Java tests via Gradle ^(!_GRADLE_TASK!^)...
)

pushd "%BRIDGE_DIR%"

rem Call gradlew by full path: VsDevCmd sets NoDefaultCurrentDirectoryInExePath,
rem so a bare 'gradlew.bat' would not be found even after pushd.
if %VERBOSE%==1 (
    call "%BRIDGE_DIR%\gradlew.bat" !_GRADLE_TASK! --rerun
) else (
    call "%BRIDGE_DIR%\gradlew.bat" !_GRADLE_TASK! --rerun --quiet
)
set GRADLE_EXIT=%errorlevel%
popd

if %RUN_E2E%==1 (
    if %GRADLE_EXIT% neq 0 ( set E2E_STATUS=2 ) else ( set E2E_STATUS=1 )
) else (
    if %GRADLE_EXIT% neq 0 ( set JAVA_STATUS=2 ) else ( set JAVA_STATUS=1 )
)

:skip_java

rem ---------------------------------------------------------------------------
rem  Summary
rem ---------------------------------------------------------------------------
echo.
echo ======================================================
echo   Test summary
echo ======================================================

set EXIT_CODE=0

call :print_status "C++ unit tests (GhidraConnectionState / CheckinPreview / Protocol / GhidraJson)" %CPP_STATUS%
call :print_status "BN-headless tests (SyncEngine / CheckinCollect / CanonicalParity)"              %BN_STATUS%
call :print_status "Java tests (RoundTrip / CanonicalParity)"                                       %JAVA_STATUS%
call :print_status "Live-server E2E"                                                                 %E2E_STATUS%

echo.
if %EXIT_CODE%==0 (
    echo All tests passed.
) else (
    echo One or more test suites failed.
)
exit /b %EXIT_CODE%

rem ---------------------------------------------------------------------------
rem  Subroutine: print_status  <label> <status-code>
rem    0 = skipped, 1 = passed, 2 = failed, 3 = error
rem ---------------------------------------------------------------------------
:print_status
set "_label=%~1"
set "_code=%~2"
rem Use delayed (!_label!) expansion: the labels contain parentheses, which would
rem unbalance these if(...) blocks if expanded at parse time with %_label%.
if %_code%==1 ( echo   !_label!: PASSED  & goto :eof )
if %_code%==2 ( echo   !_label!: FAILED  & set EXIT_CODE=1 & goto :eof )
if %_code%==3 ( echo   !_label!: ERROR   & set EXIT_CODE=1 & goto :eof )
echo   !_label!: skipped
goto :eof

rem ---------------------------------------------------------------------------
rem  Help
rem ---------------------------------------------------------------------------
:show_help
echo Usage:  test.bat [--cpp] [--java] [--parity] [--e2e] [--no-build] [--verbose]
echo.
echo   (no args)   Run C++ unit, BN-headless/parity and Java tests (tiers 0-3)
echo   --cpp       C++ tests only (unit + BN-headless)
echo   --java      Java tests only
echo   --parity    Cross-DB parity tier only (C++ BN tests + gradlew parityTest)
echo   --e2e       Live Ghidra-server E2E tier (starts a local ghidraSvr)
echo   --no-build  Skip cmake --build (use existing binaries)
echo   --verbose   More output from all test runners
echo.
exit /b 0
