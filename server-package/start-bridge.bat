@echo off
REM start-bridge.bat — Run the ghidra-bridge service on the Ghidra server machine (Windows).
REM
REM Configuration (edit the variables below or set them in the environment):
REM   GHIDRA_HOME   Path to the Ghidra installation directory (required).
REM   BRIDGE_JAR    Path to ghidra-bridge-0.1.0.jar (default: same dir as script).
REM   BRIDGE_PORT   TCP port to listen on (default: 13200).
REM   JAVA_CMD      Java executable (default: java from PATH).

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM --- Configuration ---
if not defined GHIDRA_HOME (
    echo ERROR: GHIDRA_HOME is not set.
    echo        Set the GHIDRA_HOME environment variable to your Ghidra installation directory.
    pause
    exit /b 1
)
if not defined BRIDGE_JAR  set "BRIDGE_JAR=%SCRIPT_DIR%\ghidra-bridge-0.1.0.jar"
if not defined BRIDGE_PORT set "BRIDGE_PORT=13200"
if not defined JAVA_CMD    set "JAVA_CMD=java"

if not exist "%BRIDGE_JAR%" (
    echo ERROR: Bridge JAR not found: %BRIDGE_JAR%
    echo        Build it with:  build.bat bridge   ^(from the repo root on a build machine^)
    echo        Then copy ghidra-bridge-0.1.0.jar to this directory.
    pause
    exit /b 1
)

REM --- Build classpath ---
set "CP=%BRIDGE_JAR%"
for %%M in (FileSystem DB Generic Utility SoftwareModeling Project) do (
    set "CP=!CP!;%GHIDRA_HOME%\Ghidra\Framework\%%M\lib\*"
)
set "CP=%CP%;%GHIDRA_HOME%\Ghidra\Features\GhidraServer\lib\*"

echo Ghidra Bridge starting...
echo   GHIDRA_HOME : %GHIDRA_HOME%
echo   BRIDGE_JAR  : %BRIDGE_JAR%
echo   Port        : %BRIDGE_PORT%
echo.
echo Binary Ninja should be configured with:
echo   Bridge Port : %BRIDGE_PORT%  ^(Settings -^> Ghidra -^> Bridge Port^)
echo.

"%JAVA_CMD%" ^
    -cp "%CP%" ^
    com.ghidra_svr.bridge.BridgeMain ^
    --port "%BRIDGE_PORT%" ^
    --bind-all ^
    --ghidra-home "%GHIDRA_HOME%" ^
    %*
