# FetchGhidra.cmake
#
# Downloads the latest Ghidra release from GitHub at CMake configure time
# and sets GHIDRA_HOME in the cache.
#
# If GHIDRA_HOME is already set (via -DGHIDRA_HOME=... or a prior run) and
# the path exists, this module does nothing.
#
# The zip is extracted to <repo-root>/ghidra/ and deleted afterwards.
# Subsequent configure runs skip the download by checking for the extracted dir.

# ---- Already configured? ---------------------------------------------------

if(DEFINED GHIDRA_HOME AND EXISTS "${GHIDRA_HOME}")
    message(STATUS "Ghidra: ${GHIDRA_HOME}")
    return()
endif()

# ---- Check for a previously extracted installation -------------------------

set(_ghidra_dir "${CMAKE_SOURCE_DIR}/../ghidra")

file(GLOB _existing "${_ghidra_dir}/ghidra_*_PUBLIC")
if(_existing)
    list(GET _existing 0 _home)
    set(GHIDRA_HOME "${_home}" CACHE PATH "Ghidra installation directory" FORCE)
    message(STATUS "Ghidra: ${GHIDRA_HOME}")
    return()
endif()

# ---- Query GitHub releases API ---------------------------------------------

message(STATUS "Ghidra: querying GitHub for latest release...")

set(_api_json "${CMAKE_BINARY_DIR}/ghidra_release.json")
file(DOWNLOAD
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
    "${_api_json}"
    HTTPHEADER "User-Agent: cmake-ghidra-fetch/1.0"
    STATUS _status
    TIMEOUT 30)

list(GET _status 0 _code)
if(NOT _code EQUAL 0)
    list(GET _status 1 _msg)
    message(WARNING "Ghidra: GitHub API query failed (${_msg}) — set -DGHIDRA_HOME=<path>")
    return()
endif()

file(READ "${_api_json}" _json)

# ---- Find the .zip asset ---------------------------------------------------

string(JSON _n_assets ERROR_VARIABLE _err LENGTH "${_json}" "assets")
if(_err OR _n_assets EQUAL 0)
    message(WARNING "Ghidra: no release assets in API response — set -DGHIDRA_HOME=<path>")
    return()
endif()

set(_zip_url  "")
set(_zip_name "")
math(EXPR _last "${_n_assets} - 1")
foreach(_i RANGE 0 ${_last})
    string(JSON _name GET "${_json}" "assets" ${_i} "name")
    # The release zip is the only .zip asset; exclude the .SHA256 sidecar.
    if(_name MATCHES "\\.zip$" AND NOT _name MATCHES "\\.SHA256$")
        string(JSON _zip_url GET "${_json}" "assets" ${_i} "browser_download_url")
        set(_zip_name "${_name}")
        break()
    endif()
endforeach()

if(NOT _zip_url)
    message(WARNING "Ghidra: could not find zip asset — set -DGHIDRA_HOME=<path>")
    return()
endif()

# ---- Download --------------------------------------------------------------

file(MAKE_DIRECTORY "${_ghidra_dir}")
set(_zip_path "${_ghidra_dir}/${_zip_name}")

message(STATUS "Ghidra: downloading ${_zip_name} (this may take a few minutes)...")
file(DOWNLOAD "${_zip_url}" "${_zip_path}"
    SHOW_PROGRESS
    STATUS _status
    TIMEOUT 600)

list(GET _status 0 _code)
if(NOT _code EQUAL 0)
    list(GET _status 1 _msg)
    file(REMOVE "${_zip_path}")
    message(WARNING "Ghidra: download failed (${_msg}) — set -DGHIDRA_HOME=<path>")
    return()
endif()

# ---- Extract ---------------------------------------------------------------

message(STATUS "Ghidra: extracting ${_zip_name}...")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar xf "${_zip_path}"
    WORKING_DIRECTORY "${_ghidra_dir}"
    RESULT_VARIABLE _result)

file(REMOVE "${_zip_path}")

if(NOT _result EQUAL 0)
    message(WARNING "Ghidra: extraction failed — set -DGHIDRA_HOME=<path>")
    return()
endif()

# ---- Locate extracted directory and cache ----------------------------------

file(GLOB _found "${_ghidra_dir}/ghidra_*_PUBLIC")
if(NOT _found)
    message(WARNING "Ghidra: expected ghidra_*_PUBLIC directory after extraction — set -DGHIDRA_HOME=<path>")
    return()
endif()

list(GET _found 0 _home)
set(GHIDRA_HOME "${_home}" CACHE PATH "Ghidra installation directory" FORCE)
message(STATUS "Ghidra: installed to ${GHIDRA_HOME}")
