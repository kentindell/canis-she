# This software is licensed according to the APACHE LICENSE 2.0:
#
# https://www.apache.org/licenses/LICENSE-2.0.txt

cmake_minimum_required(VERSION 2.8)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(swshe)

option(SM_KEY_EXPANSION_CACHED "Use RAM to store cached key expansion to speed up AES" ON) 
option(SM_RAM_TABLES "Put AES tables in RAM to eliminate flash memory cache effects" ON)
option(SM_CPU_LITTLE_ENDIAN "Build for a little endian CPU" ON)
option(SM_CODE_IN_RAM "Code in RAM for slow XIP devices" OFF)

if(SM_KEY_EXPANSION_CACHED)
    message(STATUS "SM_KEY_EXPANSION_CACHED is ON")
    add_definitions(-DSM_KEY_EXPANSION_CACHED)
else()
    message(STATUS "SM_KEY_EXPANSION_CACHED is OFF")
    add_definitions(-DSM_NO_KEY_EXPANSION_CACHE)
endif(SM_KEY_EXPANSION_CACHED)
unset(SM_KEY_EXPANSION_CACHED CACHE)

if(SM_RAM_TABLES)
    message(STATUS "SM_RAM_TABLES is ON")
    add_definitions(-DSM_RAM_TABLES)
else()
    message(STATUS "SM_RAM_TABLES is OFF")
    add_definitions(-DSM_ROM_TABLES)
endif(SM_RAM_TABLES)
unset(SM_RAM_TABLES CACHE)

if(SM_CPU_LITTLE_ENDIAN)
    message(STATUS "SM_CPU_LITTLE_ENDIAN is ON")
    add_definitions(-DSM_CPU_LITTLE_ENDIAN)
else()
    message(STATUS "SM_CPU_LITTLE_ENDIAN is OFF")
    add_definitions(-DSM_CPU_BIG_ENDIAN)
endif(SM_CPU_LITTLE_ENDIAN)
unset(SM_CPU_LITTLE_ENDIAN CACHE)

if(SM_CODE_IN_RAM)
    message(STATUS "SM_CODE_IN_RAM is ON")
    add_definitions(-DSM_CODE_IN_RAM)
else()
    message(STATUS "SM_CODE_IN_RAM is OFF")
endif(SM_CODE_IN_RAM)
unset(SM_CODE_IN_RAM CACHE)

add_library(swshe cmac.c cmacdyn.c dececb.c encecb.c exportramkey.c extseed.c getid.c init.c kdf.c loadkey.c platform.c reset.c rng.c)

include_directories(..)
set(CMAKE_CXX_STANDARD 99)
set (CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS}")
set(SOURCE_FILES
        cmac.c
        cmacdyn.c
        dececb.c
        encecb.c
        exportramkey.c
        extseed.c
        getid.c
        init.c
        kdf.c
        loadkey.c
        platform.c
        reset.c
        rng.c
        nvram.h
        swshe.h)

target_compile_options(swshe PRIVATE -Wall -Wextra -Wpedantic -Werror)

install(TARGETS swshe DESTINATION ${CMAKE_BINARY_DIR}/../../../lib/)

set(CMAKE_C_COMPILER gcc)
