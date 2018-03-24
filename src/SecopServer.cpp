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

#include <pthread.h>

#include <map>

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

class PolicyController
{
	/* Key - Policy value - default reply if user not mentioned */
	map<string, bool> dfl;

	/* key - policy value map key - user value - policyvalue */
	map<string, map<string, bool> > pol;
public:
	PolicyController()
	{
		pol["createuser"]			= {};
		pol["removeuser"]			= {};
		pol["removeservice"]		= {};
		pol["addacl"]				= {};
		pol["removeacl"]			= {};
		pol["addidentifier"]		= {};
		pol["removeidentifier"]		= {};
		pol["getidentifiers"]		= {};
		pol["createappid"]			= {};
		pol["removeappid"]			= {};
		pol["appaddacl"]			= {};
		pol["removeappacl"]			= {};
		pol["getappidentifiers"]	= {};
		pol["addappidentifier"]		= {};
		pol["removeappidentifier"]	= {};
		pol["addgroup"]				= {};
		pol["addgroupmember"]		= {};
		pol["removegroupmember"]	= {};
		pol["removegroup"]			= {};
		pol["updatepassword"]		= {};
		pol["isadmin"]				= {
			{ "root", true },
		};


	}

	bool Check(const string& actor, const string& policy )
	{
		if( this->pol.find(policy) == this->pol.end() )
		{
			throw std::runtime_error("Unknown policy");
		}

		/*
		 * Setup default return value
		 * Default is deny if not defined
		 */
		bool ret = false;
		if( this->dfl.find(policy) != this->dfl.end() )
		{
			ret = this->dfl[policy];
		}

		/* Check if user is mentioned */
		if( this->pol[policy].find(actor) != this->pol[policy].end() )
		{
			ret = this->pol[policy][actor];
		}

		return ret;
	}

	virtual ~PolicyController()
	{

	}
};

static PolicyController pc;


struct threadinfo
{
	SecopServer* server;
	SocketPtr client;
};

SecopServer::SecopServer (const string& socketpath, const string& dbpath):
		state(UNINITIALIZED),
		Utils::Net::NetServer(UnixStreamServerSocketPtr( new UnixStreamServerSocket(socketpath)), 0),
		dbpath(dbpath)
{
	logg << Logger::Debug << "Secop server starting"<<lend;

	// Setup commands possible
	this->actions["init"]=make_pair(UNINITIALIZED, &SecopServer::DoInitialize);
	this->actions["status"]=make_pair(UNINITIALIZED|INITIALIZED|AUTHENTICATED, &SecopServer::DoStatus);
	this->actions["auth"]=make_pair(INITIALIZED|AUTHENTICATED, &SecopServer::DoAuthenticate );

	this->actions["createuser"]=make_pair(AUTHENTICATED, &SecopServer::DoCreateUser );
	this->actions["removeuser"]=make_pair(AUTHENTICATED, &SecopServer::DoRemoveUser );
	this->actions["getusers"]=make_pair(AUTHENTICATED, &SecopServer::DoGetUsers );
	this->actions["updateuserpassword"]=make_pair(AUTHENTICATED, &SecopServer::DoUpdatePassword );
	this->actions["getusergroups"]=make_pair(AUTHENTICATED, &SecopServer::DoGetUserGroups );

	this->actions["getattributes"] = make_pair(AUTHENTICATED, &SecopServer::DoGetAttributes );
	this->actions["getattribute"] = make_pair(AUTHENTICATED, &SecopServer::DoGetAttribute );
	this->actions["addattribute"] = make_pair(AUTHENTICATED, &SecopServer::DoAddAttribute );
	this->actions["removeattribute"] = make_pair(AUTHENTICATED, &SecopServer::DoRemoveAttribute );

	this->actions["getservices"]=make_pair(AUTHENTICATED, &SecopServer::DoGetServices );
	this->actions["addservice"]=make_pair(AUTHENTICATED, &SecopServer::DoAddService );
	this->actions["removeservice"]=make_pair(AUTHENTICATED, &SecopServer::DoRemoveService );

	this->actions["getacl"]=make_pair(AUTHENTICATED, &SecopServer::DoGetACL );
	this->actions["addacl"]=make_pair(AUTHENTICATED, &SecopServer::DoAddACL );
	this->actions["removeacl"]=make_pair(AUTHENTICATED, &SecopServer::DoRemoveACL );
	this->actions["hasacl"]=make_pair(AUTHENTICATED, &SecopServer::DoHasACL );

	this->actions["groupadd"]=make_pair(AUTHENTICATED, &SecopServer::DoGroupAdd );
	this->actions["groupsget"]=make_pair(AUTHENTICATED, &SecopServer::DoGroupsGet );
	this->actions["groupaddmember"]=make_pair(AUTHENTICATED, &SecopServer::DoGroupAddMember );
	this->actions["groupremovemember"]=make_pair(AUTHENTICATED, &SecopServer::DoGroupRemoveMember );
	this->actions["groupgetmembers"]=make_pair(AUTHENTICATED, &SecopServer::DoGroupGetMembers );
	this->actions["groupremove"]=make_pair(AUTHENTICATED, &SecopServer::DoGroupRemove );

	this->actions["addidentifier"]=make_pair(AUTHENTICATED, &SecopServer::DoAddIdentifier );
	this->actions["removeidentifier"]=make_pair(AUTHENTICATED, &SecopServer::DoRemoveIdentifier );
	this->actions["getidentifiers"]=make_pair(AUTHENTICATED, &SecopServer::DoGetIdentifiers );

	this->actions["createappid"]=make_pair(AUTHENTICATED, &SecopServer::DoCreateAppID );
	this->actions["getappids"]=make_pair(AUTHENTICATED, &SecopServer::DoGetAppIDs );
	this->actions["removeappid"]=make_pair(AUTHENTICATED, &SecopServer::DoRemoveAppID );


	this->actions["addappidentifier"]=make_pair(AUTHENTICATED, &SecopServer::DoAppAddIdentifier );
	this->actions["getappidentifiers"]=make_pair(AUTHENTICATED, &SecopServer::DoAppGetIdentifiers );
	this->actions["removeappidentifier"]=make_pair(AUTHENTICATED, &SecopServer::DoAppRemoveIdentifier );

	this->actions["addappacl"]=make_pair(AUTHENTICATED, &SecopServer::DoAppAddACL );
	this->actions["getappacl"]=make_pair(AUTHENTICATED, &SecopServer::DoAppGetACL );
	this->actions["removeappacl"]=make_pair(AUTHENTICATED, &SecopServer::DoAppRemoveACL );
	this->actions["hasappacl"]=make_pair(AUTHENTICATED, &SecopServer::DoAppHasACL );
}

void
SecopServer::Dispatch ( SocketPtr con )
{
	ScopedLog l("Dispatch");

	struct threadinfo* tin = new threadinfo( {this, con });
	pthread_t thread;

	pthread_create( &thread, nullptr, SecopServer::ClientThread, tin);

	pthread_detach( thread );
}

void
SecopServer::ProcessOneCommand ( UnixStreamClientSocketPtr& client,
		Json::Value& cmd, Json::Value& session )
{
	ScopedLock l(this->biglock);

	string action = cmd["cmd"].asString();

	logg << Logger::Debug << "Process request of "<< action << lend;
	if( this->actions.find(action) != this->actions.end() )
	{
		unsigned char valid_states = this->actions[action].first;

		if( this->state & valid_states ||
				( ( valid_states & AUTHENTICATED) && session["user"]["authenticated"].asBool() ))
		{
			try
			{
				((*this).*actions[action].second)(client,cmd, session);
			}
			catch( std::runtime_error& err)
			{
				logg << Logger::Error << "Failed to execute command "<< action << ": "<<err.what()<<lend;
				this->SendErrorMessage(client, cmd, 4, "Internal error");
			}
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

inline bool
SecopServer::CheckAppID(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("appid") && cmd["appid"].isString();
}

bool SecopServer::CheckGroup(const Json::Value &cmd)
{
	return !cmd.isNull() &&	cmd.isMember("group") && cmd["group"].isString();
}

bool SecopServer::CheckMember(const Json::Value &cmd)
{
	return !cmd.isNull() &&	cmd.isMember("member") && cmd["member"].isString();
}

bool SecopServer::CheckPassword(const Json::Value &cmd)
{
	return !cmd.isNull() &&	cmd.isMember("password") && cmd["password"].isString();
}


bool SecopServer::IsAdmin(const string &user)
{
	// Policy trumps membership
	if( pc.Check(user, "isadmin") )
	{
		return true;
	}
	return this->store->GroupHasMember("admin", user);
}

bool SecopServer::AdminOrAllowed(const string &user, const string &policy)
{
	return this->IsAdmin(user) || pc.Check(user,policy);
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

	if( (what & CHK_PWD) && !SecopServer::CheckPassword(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return false;
	}

	if( (what & CHK_SRV) && !SecopServer::CheckService(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return false;
	}

	if( (what & CHK_APPID) && !SecopServer::CheckAppID(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return false;
	}

	if( (what & CHK_GRP) && !SecopServer::CheckGroup(cmd) )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return false;
	}

	if( (what & CHK_MEM) && !SecopServer::CheckMember(cmd) )
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

vector<string> SecopServer::GetUserGroups(const string &user)
{
	vector<string> ret;

	vector<string> groups = this->store->GroupsGet();

	for(const string& group: groups)
	{
		vector<string> users = this->store->GroupGetMembers(group);

		if( find( users.begin(), users.end(), user) != users.end() )
		{
			ret.push_back( group );
		}

	}
	return ret;
}

void SecopServer::HandleClient(UnixStreamClientSocketPtr client)
{
	char buf[64*1024];
	size_t rd;

	Json::Value session;
	session["user"]["authenticated"]=false;

	try
	{
		while( (rd = client->Read(buf, sizeof(buf))) > 0 )
		{
			logg << "Read request of socket"<<lend;
			Json::Value req;
			if( this->reader.parse(buf, buf+rd, req) )
			{
				if( req.isMember("cmd") && req["cmd"].isString() )
				{
					this->ProcessOneCommand(client, req, session);
				}
				else
				{
					this->SendErrorMessage(client, Json::Value::null, 4, "Missing command in request");
					break;
				}
			}
			else
			{
				this->SendErrorMessage(client, Json::Value::null, 4, "Unable to parse request");
				break;
			}
		}
	}
	catch(Utils::ErrnoException& e)
	{
		logg << Logger::Debug << "Caught exception on socket read ("<<e.what()<<")"<<lend;
	}

	// Make sure user is "logged out"
	this->decreq();
}

void *SecopServer::ClientThread(void *obj)
{
	struct threadinfo* tinfo =  static_cast< struct threadinfo* >(obj);

	// Convert into unixsocket
	UnixStreamClientSocketPtr sock = static_pointer_cast<UnixStreamClientSocket>(tinfo->client);

	tinfo->server->HandleClient( sock );

	tinfo->client.reset();

	delete tinfo;

	return NULL;
}


void
SecopServer::DoInitialize ( UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session )
{
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

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "createuser") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	if( !cmd.isMember("password") || !cmd["password"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string user = cmd["username"].asString();
	SecString pwd = cmd["password"].asCString();
	string displayname;

	if( cmd.isMember("displayname") || cmd["displayname"].isString() )
	{
		displayname = cmd["displayname"].asString();
	}

	if( this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 2, "User already exists");
		return;
	}

	this->store->CreateUser(user, displayname);
	this->store->AddService(user, OPIUSER);
	this->store->AddAcl(user, OPIUSER, "root");
	this->store->AddAcl(user, OPIUSER, user);

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

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "removeuser") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string user = cmd["username"].asString();

	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Unknown user");
		return;
	}

	// Remove from groups
	vector<string> groups = this->GetUserGroups( user );
	for(const string& group: groups)
	{
		this->store->GroupRemoveMember( group, user);
	}

	// Remove user from database
	this->store->DeleteUser(user);

	this->SendOK(client, cmd);

}

void SecopServer::DoUpdatePassword(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Update password");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_PWD, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();
	string pwd  = cmd["password"].asString();
	string actor = session["user"]["username"].asString();

	// Self or admin
	if( ( actor != user) && ! this->IsAdmin(actor) )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	// Check database
	if( !this->store->HasUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 2, "User unknown");
		return;
	}

	if( !this->store->HasService(user, OPIUSER) )
	{
		this->SendErrorMessage(client, cmd, 2, "Database error");
		return;
	}

	Json::Value newids(Json::arrayValue);

	Json::Value newpd;
	newpd["password"] = pwd;

	newids.append(newpd);

	this->store->UpdateIdentifiers(user, OPIUSER, newids);

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
	ret["users"]=Json::arrayValue;

	for( auto user: users )
	{
		ret["users"].append(user);
	}
	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGetUserGroups(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Get user groups");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	Json::Value ret(Json::objectValue);
	ret["groups"]=Json::arrayValue;

	vector<string> groups = this->GetUserGroups(user);
	for(const string& group: groups)
	{
			ret["groups"].append( group );
	}

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoAddAttribute(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	ScopedLog l("Add Attribute");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !cmd.isMember("attribute") || !cmd["attribute"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	if( !cmd.isMember("value") || !cmd["value"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string attribute = cmd["attribute"].asString();
	string value = cmd["value"].asString();

	this->store->AddAttribute(user, attribute, value );

	this->SendOK(client, cmd);
}

void SecopServer::DoRemoveAttribute(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	ScopedLog l("Remove Attribute");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !cmd.isMember("attribute") || !cmd["attribute"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string attribute = cmd["attribute"].asString();

	if( !this->store->HasAttribute(user, attribute ) )
	{
		this->SendErrorMessage(client, cmd, 2, "No such attribute");
		return;
	}

	this->store->RemoveAttribute(user,attribute);

	this->SendOK(client, cmd);
}

void SecopServer::DoGetAttributes(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	ScopedLog l("get Attributes");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	vector<string> attrs = this->store->GetAttributes(user);

	Json::Value ret(Json::objectValue);

	for( auto attr: attrs )
	{
		ret["attributes"].append(attr);
	}
	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGetAttribute(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	ScopedLog l("Get Attribute");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !cmd.isMember("attribute") || !cmd["attribute"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string attribute = cmd["attribute"].asString();

	if( ! this->store->HasAttribute(user, attribute ) )
	{
		this->SendErrorMessage(client, cmd, 3, "Attribute unknown");
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["attribute"] = this->store->GetAttribute(user,attribute);

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

	/* Check if user is allowed to bypass acl-check */
	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "removeservice" ) )
	{
		/* Only allowed to remove if no ACL or mentioned in ACL */
		if ( ! this->store->ACLEmpty(user, service) && ! this->store->HasACL(user, service, session["user"]["username"].asString() ) )
		{
			this->SendErrorMessage(client, cmd, 4, "Not allowed");
			return;
		}
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

	ret["acl"] = Json::Value(Json::arrayValue);

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

	/* A user can add an ACL if none of the following are true -
	 *   There are ACLs present
	 *   User is not already in ACL
	 *   Policy disallows user to always add ACLs
	 */

	if( ! this->store->ACLEmpty(user, service) )
	{
		if ( ! this->store->HasACL(user, service, session["user"]["username"].asString() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "addacl") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
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

	/* A user can remove a ACL if none of the following are true -
	 *   User is not already in ACL
	 *   Policy disallows user to always remove ACLs
	 */

	if ( ! this->store->HasACL(user, service, session["user"]["username"].asString() )  )
	{
		if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "removeacl") )
		{
			this->SendErrorMessage(client, cmd, 4, "Not allowed");
			return;
		}
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
SecopServer::DoAddIdentifier(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session)
{
	//TODO: Access control!

	ScopedLog l("Add identifier");

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

	if( !cmd.isMember("identifier") || !cmd["identifier"].isObject() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing or malformed argument");
		return;
	}

	/* A user is allowed to add an identifier if -
	 * Policy gives global add capabilities
	 * User is in ACL
	 */

	if( ! this->store->ACLEmpty(user, service) )
	{
		if ( ! this->store->HasACL(user, service, session["user"]["username"].asString() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "addidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	this->store->AddIdentifier(user, service, cmd["identifier"]);

	this->SendOK(client, cmd);
}

void
SecopServer::DoRemoveIdentifier(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session)
{

	ScopedLog l("Remove identifier");

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

	if( !cmd.isMember("identifier") || !cmd["identifier"].isObject() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing or malformed argument");
		return;
	}

	/* A user is allowed to remove an identifier if -
	 * Policy gives global remove capabilities
	 * User is in ACL
	 */

	if( ! this->store->ACLEmpty(user, service) )
	{
		if ( ! this->store->HasACL(user, service, session["user"]["username"].asString() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "removeidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	bool id_hasname = false, id_hasservice = false;
	string id_name, id_service;

	if( cmd["identifier"].isMember("user") && cmd["identifier"]["user"].isString() )
	{
		id_hasname = true;
		id_name = cmd["identifier"]["user"].asString();
	}

	if( cmd["identifier"].isMember("service") && cmd["identifier"]["service"].isString() )
	{
		id_hasservice = true;
		id_service = cmd["identifier"]["service"].asString();
	}

	if( !id_hasname && !id_hasservice )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing or malformed argument");
		return;
	}

	Json::Value ids = this->store->GetIdentifiers(user, service);
	Json::Value new_ids(Json::arrayValue);
	for( auto id: ids)
	{
		bool match_user = false, match_service=false;

		if( id.isMember("user") && id["user"].isString() && id_hasname )
		{
			match_user = ( id["user"].asString() == id_name );
		}

		if( id.isMember("service") && id["service"].isString() && id_hasservice )
		{
			match_service = ( id["service"].asString() == id_service );
		}

		// Todo: there has to be a more clever way
		if( id_hasname && id_hasservice && match_user && match_service )
		{
			continue;
		}
		else if( id_hasname && !id_hasservice && match_user)
		{
			continue;
		}
		else if( ! id_hasname && id_hasservice && match_service )
		{
			continue;
		}
		else
		{
			// Not found, append to new list
			new_ids.append( id );
		}
	}

	this->store->UpdateIdentifiers(user, service, new_ids);

	this->SendOK(client, cmd);
}

void SecopServer::DoGroupAdd(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Add group");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "addgroup") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].asString();
	this->store->GroupAdd(group);

	this->SendOK(client, cmd);
}

void SecopServer::DoGroupsGet(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Get groups");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	//Todo: Should we have any policy on this?


	vector<string> groups = this->store->GroupsGet();

	Json::Value ret(Json::objectValue);
	ret["groups"]=Json::arrayValue;
	for(auto group: groups)
	{
		ret["groups"].append(group);
	}

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGroupAddMember(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Add group member");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP | CHK_MEM, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "addgroupmember") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].asString();
	string member = cmd["member"].asString();

	this->store->GroupAddMember(group, member);

	this->SendOK(client, cmd);
}

void SecopServer::DoGroupRemoveMember(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Remove group member");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP | CHK_MEM, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "removegroupmember") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].asString();
	string member = cmd["member"].asString();

	this->store->GroupRemoveMember(group, member);

	this->SendOK(client, cmd);

}

void SecopServer::DoGroupGetMembers(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Get group members");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP, cmd) )
	{
		return;
	}

	//Todo: Should we have any policy on this?

	string group = cmd["group"].asString();

	vector<string> members = this->store->GroupGetMembers(group);

	Json::Value ret(Json::objectValue);
	ret["members"]=Json::arrayValue;
	for(auto member: members)
	{
		ret["members"].append(member);
	}

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGroupRemove(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Remove group");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "removegroup") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].asString();

	// Sanity check, we don't allow users to remove admin group
	if( group == "admin" )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	this->store->GroupRemove(group);

	this->SendOK(client, cmd);
}

void SecopServer::DoCreateAppID(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Create appid");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "createappid") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string appid = cmd["appid"].asString();

	if( this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid already exists");
		return;
	}

	this->store->CreateAppID(appid);

	this->SendOK(client, cmd);

}

void SecopServer::DoGetAppIDs(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Get appids");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	vector<string> appids = this->store->GetAppIDs();

	Json::Value ret(Json::objectValue);

	for( auto appid: appids )
	{
		ret["appids"].append(appid);
	}
	this->SendOK(client, cmd, ret);

}

void SecopServer::DoRemoveAppID(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Remove appid");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].asString(), "removeappid") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string appid = cmd["appid"].asString();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Unknown appid");
		return;
	}

	this->store->DeleteAppID( appid );

	this->SendOK(client, cmd);
}

void SecopServer::DoAppGetIdentifiers(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!

	ScopedLog l("Get app identifiers");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID,  cmd) )
	{
		return;
	}

	string appid = cmd["appid"].asString();

	if( ! this->store->HasAppID(appid) )
	{
		this->SendErrorMessage(client, cmd, 3, "Appid unknown");
		return;
	}

	/* Todo, add policy check */
	// Not empty and user not in ACL
	if( ! this->store->AppACLEmpty(appid) &&
			! this->store->AppHasACL( appid, session["user"]["username"].asString() ) &&
			! this->AdminOrAllowed(session["user"]["username"].asString(), "getappidentifiers") )
	{
		this->SendErrorMessage(client, cmd, 4, "Access not allowed");
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["identifiers"] = this->store->AppGetIdentifiers( appid );

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoAppAddIdentifier(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Add app identifier");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	string appid = cmd["appid"].asString();

	if( ! this->store->HasAppID( appid) )
	{
		this->SendErrorMessage(client, cmd, 3, "Appid unknown");
		return;
	}


	if( !cmd.isMember("identifier") || !cmd["identifier"].isObject() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing or malformed argument");
		return;
	}

	/* A user is allowed to add an identifier if -
	 * Policy gives global add capabilities
	 * User is in ACL
	 */

	if( ! this->store->AppACLEmpty(appid) )
	{
		if ( ! this->store->AppHasACL(appid, session["user"]["username"].asString() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "addappidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	this->store->AppAddIdentifier( appid, cmd["identifier"]);

	this->SendOK(client, cmd);

}

void SecopServer::DoAppRemoveIdentifier(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Remove identifier");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	string appid = cmd["appid"].asString();

	if( ! this->store->HasAppID( appid) )
	{
		this->SendErrorMessage(client, cmd, 3, "Appid unknown");
		return;
	}

	if( !cmd.isMember("identifier") || !cmd["identifier"].isObject() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing or malformed argument");
		return;
	}

	/* A user is allowed to remove an identifier if -
	 * Policy gives global remove capabilities
	 * User is in ACL
	 */

	if( ! this->store->AppACLEmpty( appid ) )
	{
		if ( ! this->store->AppHasACL(appid, session["user"]["username"].asString() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "removeappidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	Json::Value needle = cmd["identifier"];
	Json::Value ids = this->store->AppGetIdentifiers( appid );
	Json::Value new_ids(Json::arrayValue);

	bool id_removed = false;
	// For each identifier for appid
	for( auto id: ids)
	{
		bool found = false;

		//For each key/value in search arg

		Json::Value::Members ms = needle.getMemberNames();

		for( auto m: ms)
		{
			// Member exists in current identifier?
			if( id.isMember( m ) )
			{
				if( id[m].asString() == needle[m].asString() )
				{
					// Found match!
					found = true;
					id_removed = true;
				}
			}
		}

		if( ! found )
		{
			// Not found, append to new list
			new_ids.append( id );
		}
	}

	this->store->AppUpdateIdentifiers(appid, new_ids);

	if( id_removed )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		this->SendErrorMessage(client, cmd,3, "Identifier not found");
	}
}

void SecopServer::DoAppAddACL(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{

	ScopedLog l("Add app ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( !cmd.isMember("acl") || !cmd["acl"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string appid = cmd["appid"].asString();
	string acl = cmd["acl"].asString();

	if( acl == "" )
	{
		this->SendErrorMessage(client, cmd, 2, "Invalid argument");
		return;
	}

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid unknown");
		return;
	}

	if( this->store->AppHasACL(appid, acl) )
	{
		this->SendErrorMessage(client, cmd, 2, "ACL already present");
		return;
	}

	/* A user can add an ACL if none of the following are true -
	 *   There are ACLs present
	 *   User is not already in ACL
	 *   Policy disallows user to always add ACLs
	 */

	if( ! this->store->AppACLEmpty( appid ) )
	{
		if ( ! this->store->AppHasACL(appid, session["user"]["username"].asString() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "appaddacl") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	this->store->AppAddAcl(appid, acl);

	this->SendOK(client, cmd);

}

void SecopServer::DoAppGetACL(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Get app ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	string appid = cmd["appid"].asString();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid unknown");
		return;
	}


	vector<string> acls = this->store->AppGetACL( appid );

	Json::Value ret(Json::objectValue);

	ret["acl"] = Json::Value(Json::arrayValue);

	for( auto acl: acls )
	{
		ret["acl"].append(acl);
	}
	this->SendOK(client, cmd, ret);
}

void SecopServer::DoAppRemoveACL(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	//TODO: Access control!
	ScopedLog l("Remove app ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( !cmd.isMember("acl") || !cmd["acl"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string appid = cmd["appid"].asString();
	string acl = cmd["acl"].asString();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "appid unknown");
		return;
	}

	if( !this->store->AppHasACL(appid, acl) )
	{
		this->SendErrorMessage(client, cmd, 2, "ACL not present");
		return;
	}

	/* A user can remove a ACL if none of the following are true -
	 *   User is not already in ACL
	 *   Policy disallows user to always remove ACLs
	 */

	if ( ! this->store->AppHasACL(appid, session["user"]["username"].asString() )  )
	{
		if ( ! this->AdminOrAllowed(session["user"]["username"].asString() , "removeappacl") )
		{
			this->SendErrorMessage(client, cmd, 4, "Not allowed");
			return;
		}
	}

	this->store->AppRemoveAcl(appid, acl);

	this->SendOK(client, cmd);

}

void SecopServer::DoAppHasACL(UnixStreamClientSocketPtr &client, Json::Value &cmd, Json::Value &session)
{
	ScopedLog l("Has app ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( !cmd.isMember("acl") || !cmd["acl"].isString() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string appid = cmd["appid"].asString();
	string acl = cmd["acl"].asString();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid unknown");
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["hasacl"] = this->store->AppHasACL(appid, acl);

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

	/* Todo, add policy check */
	// Not empty and user not in ACL
	if( ! this->store->ACLEmpty(user, service) &&
			! this->store->HasACL(user, service, session["user"]["username"].asString() ) &&
			! this->AdminOrAllowed(session["user"]["username"].asString(), "getidentifiers") )
	{
		this->SendErrorMessage(client, cmd, 4, "Access not allowed");
		return;
	}

	Json::Value ret(Json::objectValue);
	ret["identifiers"] = this->store->GetIdentifiers( user, service );

	this->SendOK(client, cmd, ret);
}

