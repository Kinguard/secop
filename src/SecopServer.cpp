/*
 * SecopServer.cpp
 *
 *  Created on: Oct 22, 2013
 *      Author: tor
 */

#include "SecopServer.h"

#include <libutils/UserGroups.h>
#include <libutils/Socket.h>
#include <libutils/Logger.h>

using namespace std;
using namespace Utils;
using namespace Utils::Net;

#define OPIUSER "opiuser"

// Convenience class for debug/trace
class ScopedLog: public NoCopy
{
private:
	string name;
public:
	ScopedLog(const string& name): name(name)
	{
		logg << Logger::Debug << name << " start"<<lend;
	}

	virtual ~ScopedLog()
	{
		logg << Logger::Debug << name << " stop"<<lend;
	}

};

SecopServer::SecopServer (const string& socketpath, const string& dbpath):
		state(UNINITIALIZED),
		Utils::Net::NetServer(UnixStreamServerSocketPtr( new UnixStreamServerSocket(socketpath)), 0),
		dbpath(dbpath)
{
	logg << Logger::Debug << "Secop server starting"<<lend;

	// Setup commands possible
	this->actions["init"]=make_pair(UNINITIALIZED, &SecopServer::DoInitialize);
	this->actions["status"]=make_pair(UNINITIALIZED|INITIALIZED, &SecopServer::DoStatus);
	this->actions["auth"]=make_pair(INITIALIZED, &SecopServer::DoAuthenticate );

	this->actions["createuser"]=make_pair(INITIALIZED, &SecopServer::DoCreateUser );
	this->actions["removeuser"]=make_pair(INITIALIZED, &SecopServer::DoRemoveUser );
	this->actions["getusers"]=make_pair(INITIALIZED, &SecopServer::DoGetUsers );

	this->actions["getservices"]=make_pair(INITIALIZED, &SecopServer::DoGetServices );
	this->actions["addservice"]=make_pair(INITIALIZED, &SecopServer::DoAddService );
	this->actions["removeservice"]=make_pair(INITIALIZED, &SecopServer::DoRemoveService );

	this->actions["getacl"]=make_pair(INITIALIZED, &SecopServer::DoGetACL );
	this->actions["addacl"]=make_pair(INITIALIZED, &SecopServer::DoAddACL );
	this->actions["removeacl"]=make_pair(INITIALIZED, &SecopServer::DoRemoveACL );
	this->actions["hasacl"]=make_pair(INITIALIZED, &SecopServer::DoHasACL );


	this->actions["getidentifiers"]=make_pair(INITIALIZED, &SecopServer::DoGetIdentifiers );
}

void
SecopServer::Dispatch ( SocketPtr con )
{
	ScopedLog l("Dispatch");

	// Convert into unixsocket
	UnixStreamClientSocketPtr sock = static_pointer_cast<UnixStreamClientSocket>(con);

	char buf[64*1024];
	size_t rd;
	Json::Value session;
	session["user"]["authenticated"]=false;
	try
	{
		while( (rd = sock->Read(buf, sizeof(buf))) > 0 )
		{
			logg << "Read request of socket"<<lend;
			Json::Value req;
			if( reader.parse(buf, req) )
			{
				if( req.isMember("cmd") && req["cmd"].isString() )
				{
					this->ProcessOneCommand(sock, req, session);
				}
				else
				{
					this->SendErrorMessage(sock, Json::Value::null, 4, "Missing command in request");
					break;
				}
			}
			else
			{
				this->SendErrorMessage(sock, Json::Value::null, 4, "Unable to parse request");
				break;
			}
		}
	}
	catch(Utils::ErrnoException& e)
	{
		logg << Logger::Debug << "Caught exception on socket read ("<<e.what()<<")"<<lend;
	}

	this->decreq();
}

void
SecopServer::ProcessOneCommand ( UnixStreamClientSocketPtr& client,
		Json::Value& cmd, Json::Value& session )
{
	string action = cmd["cmd"].asString();
	if( this->actions.find(action) != this->actions.end() )
	{
		if( this->state & this->actions[action].first )
		{
			((*this).*actions[action].second)(client,cmd, session);
		}
		else
		{
			this->SendErrorMessage(client, cmd, 4, "Illegal state for request");
			return;
		}
	}
	else
	{
		this->SendErrorMessage(client, cmd, 4, "Unknown action");
		return;
	}
}

void
SecopServer::SendReply ( UnixStreamClientSocketPtr& client, Json::Value& val )
{
	string r = writer.write(val);
	client->Write(r.c_str(), r.length());
}

inline bool
SecopServer::CheckAPIVersion ( const Json::Value& cmd )
{
	return !cmd.isNull() && cmd.isMember("version") && cmd["version"].isNumeric() && (cmd["version"].asDouble() == API_VERSION);
}

inline bool
SecopServer::CheckTID ( const Json::Value& cmd )
{
	return !cmd.isNull() && cmd.isMember("tid") && cmd["tid"].isIntegral();
}

inline bool
SecopServer::CheckUsername(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("username") && cmd["username"].isString();

}

inline bool
SecopServer::CheckService(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("servicename") && cmd["servicename"].isString();
}

bool
SecopServer::CheckArguments(UnixStreamClientSocketPtr &client, int what, const Json::Value& cmd)
{

	if( ( what & CHK_API) && !SecopServer::CheckAPIVersion(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Unknown protocol version");
		return false;
	}

	if( (what & CHK_TID) && !SecopServer::CheckTID(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing transaction id");
		return false;
	}

	if( (what & CHK_USR) && !SecopServer::CheckUsername(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return false;
	}

	if( (what & CHK_SRV) && !SecopServer::CheckService(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return false;
	}

	return true;
}


inline void
SecopServer::SendErrorMessage ( UnixStreamClientSocketPtr& client, const Json::Value& cmd, int errcode, const string& msg )
{
	Json::Value ret(Json::objectValue);
	ret["status"]["value"]=errcode;
	ret["status"]["desc"]=msg;

	if( SecopServer::CheckTID(cmd) )
	{
		ret["tid"]=cmd["tid"];
	}

	this->SendReply(client, ret);
}

inline void
SecopServer::SendOK (UnixStreamClientSocketPtr& client, const Json::Value& cmd, const Json::Value &val)
{
	Json::Value ret(Json::objectValue);
	ret["status"]["value"]=0;
	ret["status"]["desc"]="OK";

	if( SecopServer::CheckTID(cmd) )
	{
		ret["tid"]=cmd["tid"];
	}

	// Append any possible extra values to answer
	if( ! val.isNull() )
	{
		for( auto x: val.getMemberNames() )
		{
			ret[x]=val[x];
		}
	}

	this->SendReply(client, ret);
}


void
SecopServer::DoInitialize ( UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session )
{
	//Todo: Only let root call this?
	ScopedLog l("Initialize");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	if( cmd.isMember("key") && cmd["key"].isString() )
	{
		SecVector<byte> sv;
		Crypto::Base64Decode(cmd["key"].asString(), sv);
		try{
			this->store = CryptoStoragePtr(
						new CryptoStorage(this->dbpath, sv)
					);
		}catch(CryptoPP::Exception& e)
		{
			this->SendErrorMessage(client, cmd, 1, e.what() );
			return;
		}
	}
	else if( cmd.isMember("pwd") && cmd["pwd"].isString() )
	{
		try{
			this->store = CryptoStoragePtr(
						new CryptoStorage(this->dbpath, SecString(cmd["pwd"].asCString() ) )
					);
		}catch(CryptoPP::Exception& e)
		{
			this->SendErrorMessage(client, cmd, 1, e.what() );
			return;
		}
	}
	else
	{
		this->SendErrorMessage(client, cmd, 1, "Key or password not provided" );
		return;
	}

	this->state = INITIALIZED;
	this->SendOK(client, cmd);
}


SecopServer::~SecopServer ()
{
	logg << Logger::Debug << "Secop server terminating"<<lend;
}

void
SecopServer::DoStatus ( UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session )
{
	ScopedLog l("Status");

	if( ! this->CheckArguments( client, CHK_TID, cmd) )
	{
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["server"]["state"]=(int)this->state;
	ret["server"]["api"]=API_VERSION;

	if(session["user"]["authenticated"].asBool() )
	{
		ret["server"]["user"]=session["user"]["username"];
	}

	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAuthenticate ( UnixStreamClientSocketPtr& client,
		Json::Value& cmd, Json::Value& session )
{
	ScopedLog l("Authenticate");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	if( !cmd.isMember("type") || !cmd["type"].isString() )
	{
		this->SendErrorMessage(client, cmd, 4, "Missing argument");
		return;
	}
	string type = cmd["type"].asString();
	if( type == "socket")
	{
		struct ucred uc = client->GetCredentials();
		session["user"]["username"]=User::UIDToUser( uc.uid );
		session["user"]["group"]=Group::GIDToGroup(uc.gid);
		session["user"]["uid"]=uc.uid;
		session["user"]["gid"]=uc.gid;
		session["user"]["pid"]=uc.pid;
	}
	else if( type == "plain")
	{
		if( !cmd.isMember("username") || !cmd["username"].isString() )
		{
			this->SendErrorMessage(client, cmd, 2, "Missing argument");
			return;
		}
		if( !cmd.isMember("password") || !cmd["password"].isString() )
		{
			this->SendErrorMessage(client, cmd, 2, "Missing argument");
			return;
		}

		string user = cmd["username"].asString();
		SecString pwd = cmd["password"].asCString();

		if( !this->store->HasUser( user ) )
		{
			this->SendErrorMessage(client, cmd, 2, "Authentication error");
			return;
		}

		if( !this->store->HasService(user, OPIUSER) )
		{
			this->SendErrorMessage(client, cmd, 2, "Service unknown");
			return;
		}

		Json::Value ids = this->store->GetIdentifiers(user ,OPIUSER);

		if( ids.size()== 0 || !ids.isArray() )
		{
			this->SendErrorMessage(client, cmd, 2, "Database error");
			return;
		}

		Json::Value id = ids[(Json::Value::UInt)0];

		if( !id.isMember("password"))
		{
			this->SendErrorMessage(client, cmd, 2, "Database error");
			return;
		}

		if( id["password"].asCString() != pwd)
		{
			this->SendErrorMessage(client, cmd, 2, "Authentication error");
			return;
		}

		session["user"]["username"]=user;
	}
	else
	{
		this->SendErrorMessage(client, cmd, 4, "Unknown authentication type");
		return;
	}
	session["user"]["authenticated"]=true;
	this->SendOK(client, cmd);
}

void
SecopServer::DoCreateUser ( UnixStreamClientSocketPtr& client, Json::Value& cmd,
		Json::Value& session )
{
	ScopedLog l("Create user");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	if( !cmd.isMember("password") || !cmd["password"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string user = cmd["username"].asString();
	SecString pwd = cmd["password"].asCString();

	if( this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 2, "User already exists");
		return;
	}

	this->store->CreateUser(user);
	this->store->AddService(user, OPIUSER);

	Json::Value id(Json::objectValue);
	id["password"]=pwd.c_str();
	this->store->AddIdentifier(user, OPIUSER, id);

	this->SendOK(client, cmd);
}

void
SecopServer::DoRemoveUser ( UnixStreamClientSocketPtr& client, Json::Value& cmd,
		Json::Value& session )
{
	ScopedLog l("Remove user");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Unknown user");
		return;
	}

	this->store->DeleteUser(user);

	this->SendOK(client, cmd);

}

void
SecopServer::DoGetUsers(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Who is allowed to do this?
	ScopedLog l("Get users");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	vector<string> users = this->store->GetUsers();

	Json::Value ret(Json::objectValue);

	for( auto user: users )
	{
		ret["users"].append(user);
	}
	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoGetServices(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	//TODO: Howto handle opiuser service?

	ScopedLog l("Get services");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	vector<string> services = this->store->GetServices(cmd["username"].asString());

	Json::Value ret(Json::objectValue);

	for( auto service: services )
	{
		ret["services"].append(service);
	}

	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAddService(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	//TODO: Howto handle opiuser service?

	ScopedLog l("Add service");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( this->store->HasService(user,service) )
	{
		this->SendErrorMessage(client, cmd, 3, "Service exists");
		return;
	}

	this->store->AddService( user, service );

	this->SendOK(client, cmd);
}

void
SecopServer::DoRemoveService(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	//TODO: Howto handle opiuser service?

	ScopedLog l("Remove service");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !this->store->HasService(user,service) )
	{
		this->SendErrorMessage(client, cmd, 3, "Service unknown");
		return;
	}

	this->store->RemoveService(user, service);

	this->SendOK(client, cmd);
}


void
SecopServer::DoGetACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session)
{
	ScopedLog l("Get ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();

	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "User unknown");
		return;
	}

	if( !this->store->HasService(user, service) )
	{
		this->SendErrorMessage(client, cmd, 2, "Service unknown");
		return;
	}

	vector<string> acls = this->store->GetACL(user, service );

	Json::Value ret(Json::objectValue);

	for( auto acl: acls )
	{
		ret["acl"].append(acl);
	}
	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAddACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session)
{
	//TODO: Access control!
	ScopedLog l("Add ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	if( !cmd.isMember("acl") || !cmd["acl"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();
	string acl = cmd["acl"].asString();

	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "User unknown");
		return;
	}

	if( !this->store->HasService(user, service) )
	{
		this->SendErrorMessage(client, cmd, 2, "Service unknown");
		return;
	}

	if( this->store->HasACL(user, service, acl) )
	{
		this->SendErrorMessage(client, cmd, 2, "ACL already present");
		return;
	}

	this->store->AddAcl(user, service, acl);

	this->SendOK(client, cmd);
}

void
SecopServer::DoRemoveACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session)
{
	//TODO: Access control!
	ScopedLog l("Remove ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	if( !cmd.isMember("acl") || !cmd["acl"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();
	string acl = cmd["acl"].asString();

	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "User unknown");
		return;
	}

	if( !this->store->HasService(user, service) )
	{
		this->SendErrorMessage(client, cmd, 2, "Service unknown");
		return;
	}

	if( !this->store->HasACL(user, service, acl) )
	{
		this->SendErrorMessage(client, cmd, 2, "ACL not present");
		return;
	}

	this->store->RemoveAcl(user, service, acl);

	this->SendOK(client, cmd);
}

void
SecopServer::DoHasACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session)
{
	ScopedLog l("Has ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	if( !cmd.isMember("acl") || !cmd["acl"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();
	string acl = cmd["acl"].asString();

	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "User unknown");
		return;
	}

	if( !this->store->HasService(user, service) )
	{
		this->SendErrorMessage(client, cmd, 2, "Service unknown");
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["hasacl"] = this->store->HasACL(user, service, acl);

	this->SendOK(client, cmd, ret);
}



void
SecopServer::DoGetIdentifiers(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!

	ScopedLog l("Get identifiers");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();
	string service = cmd["servicename"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !this->store->HasService(user,service) )
	{
		this->SendErrorMessage(client, cmd, 3, "Service unknown");
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["identifiers"] = this->store->GetIdentifiers( user, service );

	this->SendOK(client, cmd, ret);
}

