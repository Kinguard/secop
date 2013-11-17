#ifndef TESTCRYPTOSTORAGE_H_
#define TESTCRYPTOSTORAGE_H_

#include <cppunit/extensions/HelperMacros.h>

class TestCryptoStorage: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestCryptoStorage ); 
	CPPUNIT_TEST( TestBasic );
	CPPUNIT_TEST( TestUser );
	CPPUNIT_TEST( TestService );
	CPPUNIT_TEST( TestACL );
	CPPUNIT_TEST( TestIdentifiers );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();
	 
	void TestBasic();
	void TestUser();
	void TestService();
	void TestACL();
	void TestIdentifiers();
};

#endif /* TESTCRYPTOSTORAGE_H_ */
