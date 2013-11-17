cmake_minimum_required(VERSION 2.6)
project( secop )

include( FindPkgConfig )

pkg_check_modules ( LIBCRYPTO++ libcrypto++>=5.6.1 )
pkg_check_modules ( LIBUTILS libutils>=1.0 )

set (SECOP_VERSION_MAJOR 1)
set (SECOP_VERSION_MINOR 0)
set (SECOP_APP_NAME "secop")

configure_file (
	"${PROJECT_SOURCE_DIR}/Config.h.in"
	"${PROJECT_BINARY_DIR}/Config.h"
)
include_directories("${PROJECT_BINARY_DIR}")

add_subdirectory( jsoncpp )
add_subdirectory( src )
add_subdirectory( test )

set( secop_src
	secop.cpp
	)

include_directories (
	"${PROJECT_SOURCE_DIR}/src"
	"${PROJECT_SOURCE_DIR}/jsoncpp"
	)

add_definitions( -std=c++11 )

add_executable( secop ${secop_src} )

target_link_libraries( secop applib ${LIBUTILS_LDFLAGS})

enable_testing()
add_test( NAME TestSecop COMMAND testsecop )


