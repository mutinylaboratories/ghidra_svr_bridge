# FetchQtBuild.cmake
#
# Registers a `build-qt` custom target using the qt-build git submodule
# (vector35/qt-build, checked out at <repo-root>/qt-build/).
#
# The submodule contains platform build scripts that compile Qt 6 with
# Binary Ninja's patches and install it to <repo-root>/qt/.
#
# Qt is built once and cached; subsequent configure runs find it in qt/ in
# under a millisecond and skip everything in this module.
#
# Typical first-time workflow on a machine without Qt:
#
#   git submodule update --init qt-build    # populate the submodule (~seconds)
#   cmake -B plugin/build -S plugin          # configure (registers build-qt)
#   cmake --build plugin/build --target build-qt   # compile Qt (~1-2 hours)
#   cmake -B plugin/build -S plugin          # re-configure to pick up Qt
#   cmake --build plugin/build               # build the plugin
#
# Or use the build scripts which wrap all of this:
#   ./build.sh qt        (macOS / Linux)
#   build.bat qt         (Windows)
#
# Prerequisites for the build-qt target:
#   - Python 3 with Poetry  (pip install poetry  or  pipx install poetry)
#   - A C++ compiler (clang on macOS, gcc/clang on Linux, MSVC 2022 on Windows)
#   - CMake + Ninja
#   - libclang 19 (see qt-build README for download instructions)

# Qt version and per-platform compiler directory — must match target_qt6_version.py
set(_qt_version "6.10.1")
if(WIN32)
    set(_qt_compiler "msvc2022_64")
elseif(APPLE)
    set(_qt_compiler "clang_64")
else()
    set(_qt_compiler "gcc_64")
endif()

set(_qt_install_dir "${CMAKE_SOURCE_DIR}/../qt")
set(_qtbuild_dir    "${CMAKE_SOURCE_DIR}/../qt-build")
set(_qt6cfg_path    "${_qt_install_dir}/${_qt_version}/${_qt_compiler}/lib/cmake/Qt6/Qt6Config.cmake")

# ---------------------------------------------------------------------------
# Fast path — Qt already available (either pre-installed or previously built)
# ---------------------------------------------------------------------------

# Caller-provided Qt6_DIR takes highest precedence.
if(DEFINED Qt6_DIR AND EXISTS "${Qt6_DIR}/Qt6Config.cmake")
    return()
endif()

# Check for a locally built Qt from a previous build-qt run.
if(EXISTS "${_qt6cfg_path}")
    get_filename_component(_qt6dir "${_qt6cfg_path}" DIRECTORY)
    set(Qt6_DIR "${_qt6dir}" CACHE PATH "Qt6 CMake directory" FORCE)
    message(STATUS "Qt6: using local build at ${Qt6_DIR}")
    return()
endif()

# ---------------------------------------------------------------------------
# Qt not found — register the build-qt target
# ---------------------------------------------------------------------------

if(NOT EXISTS "${_qtbuild_dir}/qt6_build.py")
    message(WARNING
        "qt-build submodule is not populated.\n"
        "Run:  git submodule update --init qt-build\n"
        "Then re-run cmake configure.")
    return()
endif()

# Build command: invoke the platform script with flags appropriate for a
# plugin dependency (no PySide, no interactive prompt, install to qt/).
# QT_INSTALL_DIR tells qt6_build.py where to copy the finished build.
if(WIN32)
    set(_build_cmd
        "${CMAKE_COMMAND}" -E env "QT_INSTALL_DIR=${_qt_install_dir}"
        cmd /c "${_qtbuild_dir}/build_win64.bat" --no-pyside --no-prompt)
elseif(APPLE)
    set(_build_cmd
        "${CMAKE_COMMAND}" -E env "QT_INSTALL_DIR=${_qt_install_dir}"
        bash "${_qtbuild_dir}/build_macosx" --no-pyside --no-prompt)
else()
    # Detect arm vs x86 at configure time for the message; the build script
    # itself also detects at runtime but we want the right script name.
    execute_process(COMMAND uname -m
        OUTPUT_VARIABLE _arch OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_arch MATCHES "aarch64|arm")
        set(_platform_script "${_qtbuild_dir}/build_linux-arm")
    else()
        set(_platform_script "${_qtbuild_dir}/build_linux")
    endif()
    set(_build_cmd
        "${CMAKE_COMMAND}" -E env "QT_INSTALL_DIR=${_qt_install_dir}"
        bash "${_platform_script}" --no-pyside --no-prompt)
endif()

add_custom_target(build-qt
    COMMAND ${_build_cmd}
    WORKING_DIRECTORY "${_qtbuild_dir}"
    COMMENT "Building Qt ${_qt_version} with Vector35 patches — this takes 1-2 hours. After it finishes, re-run cmake configure."
    VERBATIM
    USES_TERMINAL
)

message(STATUS "Qt6: not found.")
message(STATUS "Qt6: run  cmake --build plugin/build --target build-qt  then re-run cmake configure.")
message(STATUS "Qt6: will install to ${_qt_install_dir}/${_qt_version}/${_qt_compiler}")
