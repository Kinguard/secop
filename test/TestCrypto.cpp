#include "TestCrypto.h"

CPPUNIT_TEST_SUITE_REGISTRATION ( TestCrypto );

#include <crypto++/config.h>
#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>

using namespace CryptoPP;

void TestCrypto::setUp()
{
	rnd.GenerateBlock( &key[0], key.size() );
	rnd.GenerateBlock( &iv[0], iv.size() );
}

void TestCrypto::tearDown()
{
}

void TestCrypto::TestCrypt()
{
	Crypto c(key, iv);
	string plaintext = "The quick brown fox jumps over the lazy dog"
			"The quick brown fox jumps over the lazy dog"
			"The quick brown fox jumps over the lazy dog"
			"The quick brown fox jumps over the lazy dog"
			"The quick brown fox jumps over the lazy dog";

	string enced = c.Encrypt(plaintext);
	string decoded = c.Decrypt(enced);
	CPPUNIT_ASSERT_EQUAL(plaintext, decoded);

	string p2 = "Gud hjälpe Zorns mö qvickt få byxa.";
	enced = c.Encrypt(p2);
	decoded = c.Decrypt(enced);
	CPPUNIT_ASSERT_EQUAL(p2, decoded);
}

void TestCrypto::TestCrypt2()
{
	Crypto c(key, iv);
	vector<byte> v1 = {
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6
	};
	vector<byte> v2;

	c.Encrypt(v1,v2);
	vector<byte> v3;

	c.Decrypt(v2, v3);
	CPPUNIT_ASSERT( v1 == v3);
	CPPUNIT_ASSERT( std::equal(v1.begin(), v1.end(), v3.begin() ) );

	string vs = c.Decrypt(v2);
	CPPUNIT_ASSERT( v1.size() == vs.size());
	CPPUNIT_ASSERT( std::equal( v1.begin(), v1.end(), vs.begin() ) );
}

void TestCrypto::TestCrypt3()
{
	Crypto c(key, iv);
	vector<byte> v1 = {
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,
			1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6
	};
	vector<byte> v2;

	c.Encrypt(v1,v2);

	string vs = c.Decrypt(v2);
	CPPUNIT_ASSERT( v1.size() == vs.size());
	CPPUNIT_ASSERT( std::equal( v1.begin(), v1.end(), vs.begin() ) );
}


void
TestCrypto::TestBase64 ()
{
	string plain = "Hello World";
	string enc = "SGVsbG8gV29ybGQ=";

	CPPUNIT_ASSERT_EQUAL(plain, Crypto::Base64Decode(enc) );
	CPPUNIT_ASSERT_EQUAL(enc, Crypto::Base64Encode(plain) );
}

void
TestCrypto::TestMaxKey ()
{
	SecVector<byte> lkey(AES::MAX_KEYLENGTH);

	rnd.GenerateBlock( &lkey[0], lkey.size() );

	Crypto c(lkey,  iv);

	string plaintext = "The quick brown fox jumps over the lazy dog";

	string enced = c.Encrypt(plaintext);
	string decoded = c.Decrypt(enced);
	CPPUNIT_ASSERT_EQUAL(plaintext, decoded);
}

void
TestCrypto::TestMisc ()
{
	SecVector<byte> key;
	vector<byte> iv;
	CPPUNIT_ASSERT_NO_THROW( Crypto d(key, iv) );

	Crypto d2(key, iv);
	CPPUNIT_ASSERT_THROW(d2.Encrypt("Hello World!"), CryptoPP::Exception);
}

void
TestCrypto::TestMinKey ()
{
	SecByteBlock lkey(AES::MIN_KEYLENGTH);
	byte liv[ AES::BLOCKSIZE ];

	rnd.GenerateBlock( lkey, lkey.size() );
	rnd.GenerateBlock( liv, sizeof(liv) );

	Crypto c(key, iv);

	string plaintext = "The quick brown fox jumps over the lazy dog";

	string enced = c.Encrypt(plaintext);
	string decoded = c.Decrypt(enced);
	CPPUNIT_ASSERT_EQUAL(plaintext, decoded);
}
