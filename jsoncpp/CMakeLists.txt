set( jsoncpp_src
	jsoncpp.cpp
	)

add_definitions( -std=c++11 -Wall )
add_library(jsoncpplib ${jsoncpp_src})
