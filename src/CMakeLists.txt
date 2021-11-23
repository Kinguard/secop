set( applib_src
	Crypto.cpp
	CryptoStorage.cpp
	SecopServer.cpp
	)


include_directories ( "${PROJECT_SOURCE_DIR}/jsoncpp" )
add_definitions( -std=c++11 -Wall )
add_library(applib ${applib_src})

target_link_libraries( applib ${LIBCRYPTO++_LDFLAGS})
