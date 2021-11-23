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
	CPPUNIT_ASSERT_NO_THROW( CryptoStorage("/tmp/cstest.db", "My Password", true) );

	CryptoStorage c("/tmp/cstest.db","My Password");
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

void TestCryptoStorage::TestGroup()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT_EQUAL( (size_t) 0 + 1, c.GroupsGet().size() );

	CPPUNIT_ASSERT( ! c.HasGroup("test") );
	CPPUNIT_ASSERT_NO_THROW( c.GroupAdd("test") );
	CPPUNIT_ASSERT( c.HasGroup("test") );

	CPPUNIT_ASSERT_EQUAL( (size_t) 1 + 1, c.GroupsGet().size() );
	CPPUNIT_ASSERT_NO_THROW( c.GroupAdd("test2") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 2 + 1, c.GroupsGet().size() );
	CPPUNIT_ASSERT_NO_THROW( c.GroupRemove("test2") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 1 + 1, c.GroupsGet().size() );

	CPPUNIT_ASSERT_THROW( c.GroupAddMember("Nogroup","mem1"), std::runtime_error );
	CPPUNIT_ASSERT_NO_THROW( c.GroupAddMember("test", "mem1") );
	CPPUNIT_ASSERT_NO_THROW( c.GroupAddMember("test", "mem1") );

	CPPUNIT_ASSERT_EQUAL( (size_t) 1, c.GroupGetMembers("test").size() );
	CPPUNIT_ASSERT_NO_THROW( c.GroupAddMember("test", "mem2") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 2, c.GroupGetMembers("test").size() );

	CPPUNIT_ASSERT_THROW( c.GroupRemoveMember("Nogroup","mem1"), std::runtime_error );
	CPPUNIT_ASSERT_NO_THROW( c.GroupRemoveMember("test", "mem1") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 1, c.GroupGetMembers("test").size() );
	CPPUNIT_ASSERT_NO_THROW( c.GroupRemoveMember("test", "mem1") );

	CPPUNIT_ASSERT_THROW( c.GroupRemove("Nogroup"), std::runtime_error );
	CPPUNIT_ASSERT_NO_THROW( c.GroupRemove("test") );
	CPPUNIT_ASSERT_THROW( c.GroupRemove("test"), std::runtime_error );

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

	json id;
	id["user"]="user";
	id["password"]="password";
	id["service"]="service";
	id["comment"]="comment";

	CPPUNIT_ASSERT_NO_THROW( c.AddIdentifier("tmp","test",id));

	json ret = c.GetIdentifiers("tmp","test");

	CPPUNIT_ASSERT( ret.size() == 1 );
	json idr = ret[0u];
	CPPUNIT_ASSERT( idr["user"].get<string>() == "user" );
	CPPUNIT_ASSERT( idr["password"].get<string>() == "password" );
	CPPUNIT_ASSERT( idr["service"].get<string>() == "service" );
	CPPUNIT_ASSERT( idr["comment"].get<string>() == "comment" );
	idr["user"]="new user";
	CPPUNIT_ASSERT_NO_THROW( c.AddIdentifier("tmp","test",idr));

	json ret2 = c.GetIdentifiers("tmp","test");
	CPPUNIT_ASSERT_EQUAL( (int)ret2.size(), 2 );
	CPPUNIT_ASSERT( ret2[1]["user"].get<string>() == "new user");
	CPPUNIT_ASSERT( ret2[0u]["user"].get<string>() == "user");
}

void TestCryptoStorage::TestAttributes()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT_NO_THROW( c.CreateUser("test","Tester Testsson") );
	string display = c.GetAttribute("test","displayname");
	CPPUNIT_ASSERT_EQUAL( display, string("Tester Testsson"));

	CPPUNIT_ASSERT_THROW( c.GetAttribute("wronguser","noattr"), std::runtime_error);
	CPPUNIT_ASSERT_THROW( c.GetAttribute("wronguser",""), std::runtime_error);

	CPPUNIT_ASSERT_NO_THROW( c.AddAttribute("test", "displayname", "No Nam") );
	string aval = "green";
	CPPUNIT_ASSERT_NO_THROW( c.AddAttribute("test", "eyecolor", aval) );
	CPPUNIT_ASSERT( c.HasAttribute("test","eyecolor") );
	CPPUNIT_ASSERT_EQUAL( c.GetAttribute("test","eyecolor"), aval);

	CPPUNIT_ASSERT( ! c.HasAttribute("test","noattr") );
	CPPUNIT_ASSERT_THROW( c.GetAttribute("test","noattr"), std::runtime_error);

	vector<string> attrs = c.GetAttributes("test");
	CPPUNIT_ASSERT_EQUAL( (int)attrs.size(), 2);

	CPPUNIT_ASSERT_THROW( c.RemoveAttribute("nouser","noattr"), std::runtime_error);
	CPPUNIT_ASSERT_THROW( c.RemoveAttribute("test","noattr"), std::runtime_error);
	CPPUNIT_ASSERT_NO_THROW( c.RemoveAttribute("test","eyecolor") );

	CPPUNIT_ASSERT( ! c.HasAttribute("test","eyecolor") );
	CPPUNIT_ASSERT_THROW( c.GetAttribute("test","eyecolor"), std::runtime_error);

	attrs = c.GetAttributes("test");
	CPPUNIT_ASSERT_EQUAL( (int)attrs.size(), 1);

}

void TestCryptoStorage::TestAppid()
{
	CryptoStorage c("/tmp/cstest.db","My Password");
	CPPUNIT_ASSERT_NO_THROW( c.CreateAppID("myappid") );

	vector<string> appids = c.GetAppIDs();
	CPPUNIT_ASSERT_EQUAL( appids.size(), (size_t) 1);
	CPPUNIT_ASSERT_EQUAL( appids[0], string("myappid") );

	CPPUNIT_ASSERT_NO_THROW( c.CreateAppID("id2") );
	CPPUNIT_ASSERT_EQUAL( c.GetAppIDs().size(), (size_t) 2);

	CPPUNIT_ASSERT_THROW( c.CreateAppID("id2"), std::runtime_error );

	CPPUNIT_ASSERT_NO_THROW( c.DeleteAppID("id2") );
	CPPUNIT_ASSERT_EQUAL( c.GetAppIDs().size(), (size_t) 1);
	CPPUNIT_ASSERT_THROW( c.DeleteAppID("id2"), std::runtime_error );

	json id;
	id["user"]="user";
	id["password"]="password";
	id["service"]="service";
	id["comment"]="comment";

	CPPUNIT_ASSERT_NO_THROW( c.AppAddIdentifier( "myappid", id) );

	json ret = c.AppGetIdentifiers("myappid");

	CPPUNIT_ASSERT_EQUAL( ret.size(), (size_t) 1 );
	json idr = ret[0u];
	CPPUNIT_ASSERT( idr["user"].get<string>() == "user" );
	CPPUNIT_ASSERT( idr["password"].get<string>() == "password" );
	CPPUNIT_ASSERT( idr["service"].get<string>() == "service" );
	CPPUNIT_ASSERT( idr["comment"].get<string>() == "comment" );

	id["user"]="another user";
	CPPUNIT_ASSERT_NO_THROW( c.AppAddIdentifier( "myappid", id) );
	CPPUNIT_ASSERT_EQUAL( c.AppGetIdentifiers("myappid").size(), (size_t) 2 );

}

void TestCryptoStorage::TestAppACL()
{
	CryptoStorage c("/tmp/cstest.db","My Password");
	CPPUNIT_ASSERT_NO_THROW( c.CreateAppID("myappid") );

	CPPUNIT_ASSERT_EQUAL((size_t)0, c.AppGetACL("myappid").size());

	CPPUNIT_ASSERT( c.AppACLEmpty("myappid"));
	CPPUNIT_ASSERT( ! c.AppHasACL("myappid","lll"));

	CPPUNIT_ASSERT_NO_THROW( c.AppAddAcl("myappid","www-data") );
	CPPUNIT_ASSERT( c.AppHasACL("myappid","www-data"));

	CPPUNIT_ASSERT_EQUAL((size_t)1, c.AppGetACL("myappid").size());
	CPPUNIT_ASSERT_NO_THROW( c.AppAddAcl("myappid","e2") );
	CPPUNIT_ASSERT_EQUAL((size_t)2, c.AppGetACL("myappid").size());

	CPPUNIT_ASSERT_NO_THROW( c.AppRemoveAcl("myappid","e2") );
	CPPUNIT_ASSERT_EQUAL((size_t)1, c.AppGetACL("myappid").size());

	CPPUNIT_ASSERT_NO_THROW( c.AppRemoveAcl("myappid","noe") );
	CPPUNIT_ASSERT_EQUAL((size_t)1, c.AppGetACL("myappid").size());

	CPPUNIT_ASSERT_THROW( c.AppRemoveAcl("lalala","noe"), std::runtime_error );


}

void TestCryptoStorage::TestI18N()
{
	CryptoStorage c("/tmp/cstest.db","My Password");

	CPPUNIT_ASSERT_EQUAL( (size_t)1, c.GroupsGet().size() );

	CPPUNIT_ASSERT_NO_THROW( c.GroupAdd("gröpp") );
	vector<string> groups = c.GroupsGet();

	bool found = false;
	for( const string& group:groups)
	{
		if( group == "gröpp" )
		{
			found = true;
		}
	}
	CPPUNIT_ASSERT( found );
}
