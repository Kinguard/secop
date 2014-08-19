#ifndef TESTCRYPTOSTORAGE_H_
#define TESTCRYPTOSTORAGE_H_

#include <cppunit/extensions/HelperMacros.h>

class TestCryptoStorage: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestCryptoStorage ); 
	CPPUNIT_TEST( TestBasic );
	CPPUNIT_TEST( TestUser );
	CPPUNIT_TEST( TestGroup );
	CPPUNIT_TEST( TestService );
	CPPUNIT_TEST( TestACL );
	CPPUNIT_TEST( TestIdentifiers );
	CPPUNIT_TEST( TestAttributes );
	CPPUNIT_TEST( TestAppid );
	CPPUNIT_TEST( TestAppACL );
	CPPUNIT_TEST(TestI18N);
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();
	 
	void TestBasic();
	void TestUser();
	void TestGroup();
	void TestService();
	void TestACL();
	void TestIdentifiers();
	void TestAttributes();
	void TestAppid();
	void TestAppACL();
	void TestI18N();
};

#endif /* TESTCRYPTOSTORAGE_H_ */
