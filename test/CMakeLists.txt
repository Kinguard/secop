pkg_check_modules( CPPUNIT cppunit>=1.12.1 )

set( testsecop_src
	test.cpp
	TestCrypto.cpp
        TestCryptoStorage.cpp
	)

include_directories(
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/jsoncpp"
)

add_definitions( -std=c++11 -Wall )
add_executable( testsecop ${testsecop_src} )

target_link_libraries( testsecop applib ${CPPUNIT_LDFLAGS} ${LIBCRYPTO++_LDFLAGS} ${LIBUTILS_LDFLAGS})

