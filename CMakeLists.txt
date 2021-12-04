cmake_minimum_required(VERSION 3.18)
project(pslib)

set(HEADERS
    ps.h
    ps_image.h
    ps_inject.h
    ps_target.h
)

set(SOURCES
    ps.cpp
    ps_image.cpp
    ps_inject.cpp
)

add_library(pslib STATIC ${SOURCSE} ${HEADERS})
set_target_properties(pslib PROPERTIES LINKER_LANGUAGE CXX)