@echo off
@rem Standard Gradle wrapper startup script for Windows.

if "%OS%"=="Windows_NT" setlocal

set DIRNAME=%~dp0
if "%DIRNAME%"=="" set DIRNAME=.
set APP_HOME=%DIRNAME%
for %%i in ("%APP_HOME%") do set APP_HOME=%%~fi

if defined JAVA_HOME (
    set JAVA_EXE=%JAVA_HOME:\=/%/bin/java.exe
) else (
    set JAVA_EXE=java.exe
    java -version >NUL 2>&1 || (
        echo ERROR: JAVA_HOME is not set and no 'java' found in PATH. 1>&2
        goto fail
    )
)

if not exist "%JAVA_EXE%" (
    echo ERROR: JAVA_HOME points to an invalid directory: %JAVA_HOME% 1>&2
    goto fail
)

set CLASSPATH=%APP_HOME%gradle\wrapper\gradle-wrapper.jar

"%JAVA_EXE%" -Xmx64m -Xms64m %JAVA_OPTS% %GRADLE_OPTS% ^
    -classpath "%CLASSPATH%" ^
    org.gradle.wrapper.GradleWrapperMain %*

if "%OS%"=="Windows_NT" endlocal
exit /b %ERRORLEVEL%

:fail
if "%OS%"=="Windows_NT" endlocal
exit /b 1
