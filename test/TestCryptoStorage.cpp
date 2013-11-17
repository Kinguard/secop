#include "TestCryptoStorage.h"

#include "CryptoStorage.h"
#include <unistd.h>

#include <stdexcept>
#include <algorithm>

CPPUNIT_TEST_SUITE_REGISTRATION ( TestCryptoStorage );

void TestCryptoStorage::setUp()
{
	// Make sure we have an empty db
	unlink("/tmp/cstest.db");
	{
		CryptoStoragePtr c( new CryptoStorage("/tmp/cstest.db","My Password") );
		c->CreateUser("tmp");
	}

}

void TestCryptoStorage::tearDown()
{
	unlink("/tmp/cstest.db");
}
 
void TestCryptoStorage::TestBasic()
{
	// Wrong password, should fail
	CPPUNIT_ASSERT_THROW( CryptoStorage("/tmp/cstest.db", "my bad password"), CryptoPP::InvalidCiphertext );
}

void TestCryptoStorage::TestUser()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT( ! c.HasUser("test") );
	CPPUNIT_ASSERT_NO_THROW( c.CreateUser("test") );
	CPPUNIT_ASSERT( c.HasUser("test") );
	CPPUNIT_ASSERT_THROW( c.CreateUser("test"), std::runtime_error );

	vector<string> u=c.GetUsers();
	CPPUNIT_ASSERT( u.size() == 2 );
	CPPUNIT_ASSERT( find(u.begin(), u.end(),"tmp") != u.end() );
	CPPUNIT_ASSERT( find(u.begin(), u.end(),"test") != u.end() );

	CPPUNIT_ASSERT_NO_THROW( c.DeleteUser("test") );
	CPPUNIT_ASSERT_THROW( c.DeleteUser("test"), std::runtime_error );
	CPPUNIT_ASSERT( ! c.HasUser("test") );
}

void TestCryptoStorage::TestService()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT( ! c.HasService("tmp", "test") );
	CPPUNIT_ASSERT_NO_THROW( c.AddService("tmp", "test") );
	CPPUNIT_ASSERT(  c.HasService("tmp", "test") );
	CPPUNIT_ASSERT_THROW( c.AddService("tmp", "test"), std::runtime_error);

	c.AddService("tmp", "test2");
	CPPUNIT_ASSERT_THROW( c.GetServices("no user"), std::runtime_error );
	vector<string> s = c.GetServices("tmp");
	CPPUNIT_ASSERT( s.size() == 2 );
	CPPUNIT_ASSERT( find(s.begin(), s.end(),"test") != s.end() );
	CPPUNIT_ASSERT( find(s.begin(), s.end(),"test2") != s.end() );

	// Test adding a service to a none user
	CPPUNIT_ASSERT_THROW( c.AddService("no user", "test"), std::runtime_error);

	// Remove service
	CPPUNIT_ASSERT_THROW( c.RemoveService("no user", "test"), std::runtime_error);
	CPPUNIT_ASSERT_THROW( c.RemoveService("tmp", "no service"), std::runtime_error);
	CPPUNIT_ASSERT_NO_THROW( c.RemoveService("tmp", "test") );
	CPPUNIT_ASSERT( ! c.HasService("tmp", "test") );

}

void TestCryptoStorage::TestACL()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT_THROW( c.HasACL("no user", "",""), std::runtime_error );
	CPPUNIT_ASSERT_THROW( c.HasACL("tmp", "no service",""), std::runtime_error );
	c.AddService("tmp", "test");
	CPPUNIT_ASSERT( ! c.HasACL("tmp", "test", "no entity"));

	CPPUNIT_ASSERT_THROW( c.AddAcl( "tmp", "no service",""), std::runtime_error );
	CPPUNIT_ASSERT_NO_THROW( c.AddAcl( "tmp", "test", "www-data") );
	CPPUNIT_ASSERT( c.HasACL("tmp", "test", "www-data") );

	CPPUNIT_ASSERT_NO_THROW( c.AddAcl( "tmp", "test", "www2") );
	CPPUNIT_ASSERT( c.HasACL("tmp", "test", "www2") );

	vector<string> acls = c.GetACL("tmp", "test");
	CPPUNIT_ASSERT( acls.size() == 2);
	CPPUNIT_ASSERT( find(acls.begin(), acls.end(),"www-data") != acls.end() );
	CPPUNIT_ASSERT( find(acls.begin(), acls.end(),"www2") != acls.end() );

	CPPUNIT_ASSERT_THROW( c.RemoveAcl("no user", "",""), std::runtime_error);
	CPPUNIT_ASSERT_THROW( c.RemoveAcl("tmp", "no service",""), std::runtime_error);

	CPPUNIT_ASSERT_NO_THROW( c.RemoveAcl( "tmp", "test", "www-data") );
	CPPUNIT_ASSERT( !c.HasACL("tmp", "test", "www-data") );
	CPPUNIT_ASSERT( c.HasACL("tmp", "test", "www2") );

	CPPUNIT_ASSERT_NO_THROW( c.RemoveAcl( "tmp", "test", "www2") );
	CPPUNIT_ASSERT( !c.HasACL("tmp", "test", "www-data") );
	CPPUNIT_ASSERT( !c.HasACL("tmp", "test", "www2") );
}

void TestCryptoStorage::TestIdentifiers()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT_THROW( c.GetIdentifiers("no user", ""), std::runtime_error );
	CPPUNIT_ASSERT_THROW( c.GetIdentifiers("tmp", "no service"), std::runtime_error );

	c.AddService("tmp", "test");

	CPPUNIT_ASSERT_NO_THROW( c.GetIdentifiers("tmp","test"));

	Json::Value id(Json::objectValue);
	id["user"]="user";
	id["password"]="password";
	id["service"]="service";
	id["comment"]="comment";

	CPPUNIT_ASSERT_NO_THROW( c.AddIdentifier("tmp","test",id));

	Json::Value ret = c.GetIdentifiers("tmp","test");

	CPPUNIT_ASSERT( ret.size() == 1 );
	Json::Value idr = ret[0u];
	CPPUNIT_ASSERT( idr["user"].asString() == "user" );
	CPPUNIT_ASSERT( idr["password"].asString() == "password" );
	CPPUNIT_ASSERT( idr["service"].asString() == "service" );
	CPPUNIT_ASSERT( idr["comment"].asString() == "comment" );
	idr["user"]="new user";
	CPPUNIT_ASSERT_NO_THROW( c.AddIdentifier("tmp","test",idr));

	Json::Value ret2 = c.GetIdentifiers("tmp","test");
	CPPUNIT_ASSERT_EQUAL( (int)ret2.size(), 2 );
	CPPUNIT_ASSERT( ret2[1]["user"].asString() == "new user");
	CPPUNIT_ASSERT( ret2[0u]["user"].asString() == "user");
}
