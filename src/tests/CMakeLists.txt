# Secure Hardware Extensions (SHE) Hardware Security Module (HSM) API
#
# Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
#
# This software is licensed according to the APACHE LICENSE 2.0:
#
# https://www.apache.org/licenses/LICENSE-2.0.txt

project(tests)

add_executable(vectors vectors.c nvram.c)
add_executable(vectors2 vectors2.c nvram.c)

target_link_libraries(vectors ${CMAKE_BINARY_DIR}/../swshe/libswshe.a)
target_link_libraries(vectors2 ${CMAKE_BINARY_DIR}/../swshe/libswshe.a)

include_directories(..)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES
        vectors.c
        vectors2.c
        test.h
        nvram.c
)

set(CMAKE_C_COMPILER clang)
