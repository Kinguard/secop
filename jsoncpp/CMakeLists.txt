set( jsoncpp_src
	jsoncpp.cpp
	)

#include_directories ( "${LIBJSONCPP_INCLUDE_DIRS}" )
add_definitions( -std=c++11 -Wall )
add_library(jsoncpplib ${jsoncpp_src})

#target_link_libraries( applib jsoncpp ${LIBCRYPTO++_LDFLAGS})
