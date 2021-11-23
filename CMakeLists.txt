cmake_minimum_required(VERSION 2.6)
project( secop )

include( FindPkgConfig )

pkg_check_modules ( LIBCRYPTO++ REQUIRED libcrypto++>=5.6.1 )
pkg_check_modules ( LIBUTILS REQUIRED libutils>=1.5.18)

find_package(nlohmann_json 3.2.0 REQUIRED)

set (SECOP_VERSION_MAJOR 1)
set (SECOP_VERSION_MINOR 0)
set (SECOP_APP_NAME "secop")

configure_file (
	"${PROJECT_SOURCE_DIR}/Config.h.in"
	"${PROJECT_BINARY_DIR}/Config.h"
)
include_directories("${PROJECT_BINARY_DIR}")

add_subdirectory( src )
add_subdirectory( test )

set( secop_src
	secop.cpp
	)

include_directories (
	"${PROJECT_SOURCE_DIR}/src"
	)

add_definitions( -Wall -Werror )

add_executable( secop ${secop_src} )

target_link_libraries( secop applib ${LIBUTILS_LDFLAGS})

enable_testing()
add_test( NAME TestSecop COMMAND testsecop )

install( DIRECTORY
			DESTINATION /var/opi/secop
			DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
	)
install( TARGETS secop DESTINATION sbin )
