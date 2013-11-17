#ifndef TESTCRYPTO_H_
#define TESTCRYPTO_H_

#include "Crypto.h"

#include <cppunit/extensions/HelperMacros.h>

class TestCrypto: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestCrypto );
	CPPUNIT_TEST( TestCrypt );
	CPPUNIT_TEST( TestCrypt2 );
	CPPUNIT_TEST( TestCrypt3 );
	CPPUNIT_TEST( TestMisc );
	CPPUNIT_TEST( TestBase64 );
	CPPUNIT_TEST( TestMaxKey );
	CPPUNIT_TEST( TestMinKey );
	CPPUNIT_TEST_SUITE_END();
public:
	TestCrypto(): TestFixture(), key(AES::DEFAULT_KEYLENGTH), iv(AES::BLOCKSIZE)
	{
	}
	void setUp();
	void tearDown();

	void TestCrypt();
	void TestCrypt2();
	void TestCrypt3();
	void TestMisc();
	void TestBase64();
	void TestMaxKey();
	void TestMinKey();
private:
	AutoSeededRandomPool rnd;
	SecVector<byte> key;
	vector<byte> iv;
};

#endif /* TESTCRYPTO_H_ */
