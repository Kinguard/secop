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
#include <memory>
#include <utility>

using namespace std;
using namespace Utils;
using namespace Utils::Net;

constexpr const char* OPIUSER="opiuser";

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

	bool Check(const string& actor, const string& policy ) const
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
			ret = this->dfl.at(policy);
		}

		/* Check if user is mentioned */
		if( this->pol.at(policy).find(actor) != this->pol.at(policy).end() )
		{
			ret = this->pol.at(policy).at(actor);
		}

		return ret;
	}
};

static const PolicyController pc;


struct threadinfo
{
	SecopServer* server;
	SocketPtr client;
};

SecopServer::SecopServer (const string& socketpath, string dbpath):
		Utils::Net::NetServer(std::make_shared<UnixStreamServerSocket>( socketpath), 0),
        state(UNINITIALIZED),
		dbpath(std::move(dbpath))
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
		json& cmd, json& session )
{
	ScopedLock l(this->biglock);

	string action = cmd["cmd"].get<string>();

	logg << Logger::Debug << "Process request of "<< action << lend;
	if( this->actions.find(action) != this->actions.end() )
	{
		unsigned char valid_states = this->actions[action].first;

		if( this->state & valid_states ||
				( ( valid_states & AUTHENTICATED) && session["user"]["authenticated"].get<bool>() ))
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
SecopServer::SendReply ( UnixStreamClientSocketPtr& client, json& val )
{
	stringstream r(val.dump());

    client->Write(r.str().c_str(), r.str().length());
}

inline bool
SecopServer::CheckAPIVersion ( const json& cmd )
{
	return !cmd.is_null() && cmd.contains("version") && cmd["version"].is_number() && (cmd["version"].get<double>() == API_VERSION);
}

inline bool
SecopServer::CheckTID ( const json& cmd )
{
	return !cmd.is_null() && cmd.contains("tid") && cmd["tid"].is_number_integer();
}

inline bool
SecopServer::CheckUsername(const json& cmd)
{
	return !cmd.is_null() &&	cmd.contains("username") && cmd["username"].is_string();

}

inline bool
SecopServer::CheckService(const json& cmd)
{
	return !cmd.is_null() &&	cmd.contains("servicename") && cmd["servicename"].is_string();
}

inline bool
SecopServer::CheckAppID(const json& cmd)
{
	return !cmd.is_null() &&	cmd.contains("appid") && cmd["appid"].is_string();
}

bool SecopServer::CheckGroup(const json &cmd)
{
	return !cmd.is_null() &&	cmd.contains("group") && cmd["group"].is_string();
}

bool SecopServer::CheckMember(const json &cmd)
{
	return !cmd.is_null() &&	cmd.contains("member") && cmd["member"].is_string();
}

bool SecopServer::CheckPassword(const json &cmd)
{
	return !cmd.is_null() &&	cmd.contains("password") && cmd["password"].is_string();
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
SecopServer::CheckArguments(UnixStreamClientSocketPtr &client, int what, const json& cmd)
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
SecopServer::SendErrorMessage ( UnixStreamClientSocketPtr& client, const json& cmd, int errcode, const string& msg )
{
	json ret;
	ret["status"]["value"]=errcode;
	ret["status"]["desc"]=msg;

	if( SecopServer::CheckTID(cmd) )
	{
		ret["tid"]=cmd["tid"];
	}

	this->SendReply(client, ret);
}

inline void
SecopServer::SendOK (UnixStreamClientSocketPtr& client, const json& cmd, const json &val)
{
	json ret;
	ret["status"]["value"]=0;
	ret["status"]["desc"]="OK";

	if( SecopServer::CheckTID(cmd) )
	{
		ret["tid"]=cmd["tid"];
	}

	// Append any possible extra values to answer
	if( ! val.is_null() )
	{
		ret.insert(val.begin(), val.end());
/*
		for( auto x: val.getMemberNames() )
		{
			ret[x]=val[x];
		}
*/
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
	int errcount = 0;

	json session;
	session["user"]["authenticated"]=false;

	logg << Logger::Debug << "Handle new client connection" << lend;

	try
	{

		while( (rd = client->Read(buf, sizeof(buf))) > 0 && errcount < 5 )
		{
			logg << "Read request of socket "<< static_cast<int>(rd) << " bytes." << lend;
			json req;
			try
			{
				req = json::parse(buf,buf+rd);

				if( req.contains("cmd") && req["cmd"].is_string() )
				{
					this->ProcessOneCommand(client, req, session);
					// CMD "sucessful", reset counter
					errcount = 0;
				}
				else
				{
					logg << Logger::Debug << "Missing command in request: ["<< req.dump(4)<<"]"<<lend;
					this->SendErrorMessage(client, json(), 4, "Missing command in request");
					errcount++;
				}
			}
			catch(json::parse_error& err)
			{
				logg << Logger::Notice << "Unable to parse request from client" << lend;
				this->SendErrorMessage(client, json(), 4, "Unable to parse request");
				errcount++;

			}
		}
	}
	catch(Utils::ErrnoException& e)
	{
		logg << Logger::Debug << "Caught exception on socket read ("<<e.what()<<")"<<lend;
	}

	if( errcount >= 5 )
	{
		logg << Logger::Debug << "Terminating connection due to to many errors" << lend;
	}

	logg << Logger::Debug << "Close client connection" << lend;

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

	return nullptr;
}


void
SecopServer::DoInitialize ( UnixStreamClientSocketPtr& client, json& cmd, json& session )
{
	ScopedLog l("Initialize");
    (void) session;
	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	if( cmd.contains("key") && cmd["key"].is_string() )
	{
		SecVector<byte> sv;
		Crypto::Base64Decode(cmd["key"].get<string>(), sv);
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
	else if( cmd.contains("pwd") && cmd["pwd"].is_string() )
	{
		try{
			this->store = CryptoStoragePtr(
						new CryptoStorage(this->dbpath, SecString(cmd["pwd"].get<string>().c_str()) )
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
SecopServer::DoStatus ( UnixStreamClientSocketPtr& client, json& cmd, json& session )
{
	ScopedLog l("Status");

	if( ! this->CheckArguments( client, CHK_TID, cmd) )
	{
		return;
	}

	json ret;
    ret["server"]["state"]=static_cast<int>(this->state);
	ret["server"]["api"]=API_VERSION;

	if(session["user"]["authenticated"].get<bool>() )
	{
		ret["server"]["user"]=session["user"]["username"];
	}

	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAuthenticate ( UnixStreamClientSocketPtr& client,
		json& cmd, json& session )
{
	ScopedLog l("Authenticate");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	if( !cmd.contains("type") || !cmd["type"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 4, "Missing argument");
		return;
	}
	string type = cmd["type"].get<string>();
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
		if( !cmd.contains("username") || !cmd["username"].is_string() )
		{
			this->SendErrorMessage(client, cmd, 2, "Missing argument");
			return;
		}
		if( !cmd.contains("password") || !cmd["password"].is_string() )
		{
			this->SendErrorMessage(client, cmd, 2, "Missing argument");
			return;
		}

		string user = cmd["username"].get<string>();
		SecString pwd = cmd["password"].get<string>().c_str();

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

		json ids = this->store->GetIdentifiers(user ,OPIUSER);

		if( ids.size()== 0 || !ids.is_array() )
		{
			this->SendErrorMessage(client, cmd, 2, "Database error");
			return;
		}

		//json id = ids[static_cast<json::UInt>(0)];
		json id = ids[0];

		if( !id.contains("password"))
		{
			this->SendErrorMessage(client, cmd, 2, "Database error");
			return;
		}

		if( id["password"].get<string>().c_str() != pwd)
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
SecopServer::DoCreateUser ( UnixStreamClientSocketPtr& client, json& cmd,
		json& session )
{
	ScopedLog l("Create user");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "createuser") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	if( !cmd.contains("password") || !cmd["password"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string user = cmd["username"].get<string>();
	SecString pwd = cmd["password"].get<string>().c_str();
	string displayname;

	if( cmd.contains("displayname") || cmd["displayname"].is_string() )
	{
		displayname = cmd["displayname"].get<string>();
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

	json id;
	id["password"]=pwd.c_str();
	this->store->AddIdentifier(user, OPIUSER, id);

	this->SendOK(client, cmd);
}

void
SecopServer::DoRemoveUser ( UnixStreamClientSocketPtr& client, json& cmd,
		json& session )
{
	ScopedLog l("Remove user");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "removeuser") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string user = cmd["username"].get<string>();

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

void SecopServer::DoUpdatePassword(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Update password");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_PWD, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string pwd  = cmd["password"].get<string>();
	string actor = session["user"]["username"].get<string>();

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

	json newids;

	json newpd;
	newpd["password"] = pwd;

	newids.push_back(newpd);

	this->store->UpdateIdentifiers(user, OPIUSER, newids);

	this->SendOK(client, cmd);
}

void
SecopServer::DoGetUsers(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Who is allowed to do this?
	ScopedLog l("Get users");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	vector<string> users = this->store->GetUsers();

	json ret;
	ret["users"]=json::array();

	for( const auto& user: users )
	{
		ret["users"].push_back(user);
	}
	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGetUserGroups(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Get user groups");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();

	json ret;
	ret["groups"]=json::array();

	vector<string> groups = this->GetUserGroups(user);
	for(const string& group: groups)
	{
			ret["groups"].push_back( group );
	}

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoAddAttribute(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	ScopedLog l("Add Attribute");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !cmd.contains("attribute") || !cmd["attribute"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	if( !cmd.contains("value") || !cmd["value"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string attribute = cmd["attribute"].get<string>();
	string value = cmd["value"].get<string>();

	this->store->AddAttribute(user, attribute, value );

	this->SendOK(client, cmd);
}

void SecopServer::DoRemoveAttribute(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	ScopedLog l("Remove Attribute");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !cmd.contains("attribute") || !cmd["attribute"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string attribute = cmd["attribute"].get<string>();

	if( !this->store->HasAttribute(user, attribute ) )
	{
		this->SendErrorMessage(client, cmd, 2, "No such attribute");
		return;
	}

	this->store->RemoveAttribute(user,attribute);

	this->SendOK(client, cmd);
}

void SecopServer::DoGetAttributes(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	ScopedLog l("get Attributes");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	vector<string> attrs = this->store->GetAttributes(user);

	json ret;

	for( const auto& attr: attrs )
	{
		ret["attributes"].push_back(attr);
	}
	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGetAttribute(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	ScopedLog l("Get Attribute");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();

	if( ! this->store->HasUser(user) )
	{
		this->SendErrorMessage(client, cmd, 3, "User unknown");
		return;
	}

	if( !cmd.contains("attribute") || !cmd["attribute"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string attribute = cmd["attribute"].get<string>();

	if( ! this->store->HasAttribute(user, attribute ) )
	{
		this->SendErrorMessage(client, cmd, 3, "Attribute unknown");
		return;
	}

	json ret;
	ret["attribute"] = this->store->GetAttribute(user,attribute);

	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoGetServices(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	//TODO: Howto handle opiuser service?

	ScopedLog l("Get services");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR, cmd) )
	{
		return;
	}

	vector<string> services = this->store->GetServices(cmd["username"].get<string>());

	json ret;

	for( const auto& service: services )
	{
		ret["services"].push_back(service);
	}

	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAddService(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	//TODO: Howto handle opiuser service?

	ScopedLog l("Add service");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();

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
SecopServer::DoRemoveService(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{

	ScopedLog l("Remove service");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();

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
	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "removeservice" ) )
	{
		/* Only allowed to remove if no ACL or mentioned in ACL */
		if ( ! this->store->ACLEmpty(user, service) && ! this->store->HasACL(user, service, session["user"]["username"].get<string>() ) )
		{
			this->SendErrorMessage(client, cmd, 4, "Not allowed");
			return;
		}
	}

	this->store->RemoveService(user, service);

	this->SendOK(client, cmd);
}


void
SecopServer::DoGetACL(UnixStreamClientSocketPtr& client, json& cmd, json& session)
{
	ScopedLog l("Get ACL");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();

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

	json ret;

	ret["acl"] = json::array();

	for( const auto& acl: acls )
	{
		ret["acl"].push_back(acl);
	}
	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAddACL(UnixStreamClientSocketPtr& client, json& cmd, json& session)
{
	//TODO: Access control!
	ScopedLog l("Add ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	if( !cmd.contains("acl") || !cmd["acl"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();
	string acl = cmd["acl"].get<string>();

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
		if ( ! this->store->HasACL(user, service, session["user"]["username"].get<string>() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "addacl") )
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
SecopServer::DoRemoveACL(UnixStreamClientSocketPtr& client, json& cmd, json& session)
{
	//TODO: Access control!
	ScopedLog l("Remove ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	if( !cmd.contains("acl") || !cmd["acl"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();
	string acl = cmd["acl"].get<string>();

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

	if ( ! this->store->HasACL(user, service, session["user"]["username"].get<string>() )  )
	{
		if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "removeacl") )
		{
			this->SendErrorMessage(client, cmd, 4, "Not allowed");
			return;
		}
	}

	this->store->RemoveAcl(user, service, acl);

	this->SendOK(client, cmd);
}

void
SecopServer::DoHasACL(UnixStreamClientSocketPtr& client, json& cmd, json& session)
{
	ScopedLog l("Has ACL");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	if( !cmd.contains("acl") || !cmd["acl"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();
	string acl = cmd["acl"].get<string>();

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

	json ret;
	ret["hasacl"] = this->store->HasACL(user, service, acl);

	this->SendOK(client, cmd, ret);
}

void
SecopServer::DoAddIdentifier(UnixStreamClientSocketPtr& client, json& cmd, json& session)
{
	//TODO: Access control!

	ScopedLog l("Add identifier");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();

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

	if( !cmd.contains("identifier") || !cmd["identifier"].is_object() )
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
		if ( ! this->store->HasACL(user, service, session["user"]["username"].get<string>() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "addidentifier") )
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
SecopServer::DoRemoveIdentifier(UnixStreamClientSocketPtr& client, json& cmd, json& session)
{

	ScopedLog l("Remove identifier");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();

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

	if( !cmd.contains("identifier") || !cmd["identifier"].is_object() )
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
		if ( ! this->store->HasACL(user, service, session["user"]["username"].get<string>() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "removeidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	bool id_hasname = false, id_hasservice = false;
	string id_name, id_service;

	if( cmd["identifier"].contains("user") && cmd["identifier"]["user"].is_string() )
	{
		id_hasname = true;
		id_name = cmd["identifier"]["user"].get<string>();
	}

	if( cmd["identifier"].contains("service") && cmd["identifier"]["service"].is_string() )
	{
		id_hasservice = true;
		id_service = cmd["identifier"]["service"].get<string>();
	}

	if( !id_hasname && !id_hasservice )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing or malformed argument");
		return;
	}

	json ids = this->store->GetIdentifiers(user, service);
	json new_ids = json::array();
	for( auto id: ids)
	{
		bool match_user = false, match_service=false;

		if( id.contains("user") && id["user"].is_string() && id_hasname )
		{
			match_user = ( id["user"].get<string>() == id_name );
		}

		if( id.contains("service") && id["service"].is_string() && id_hasservice )
		{
			match_service = ( id["service"].get<string>() == id_service );
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
			new_ids.push_back( id );
		}
	}

	this->store->UpdateIdentifiers(user, service, new_ids);

	this->SendOK(client, cmd);
}

void SecopServer::DoGroupAdd(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Add group");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "addgroup") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].get<string>();
	this->store->GroupAdd(group);

	this->SendOK(client, cmd);
}

void SecopServer::DoGroupsGet(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Get groups");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	//Todo: Should we have any policy on this?


	vector<string> groups = this->store->GroupsGet();

	json ret;
	ret["groups"];
	for(const auto& group: groups)
	{
		ret["groups"].push_back(group);
	}

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGroupAddMember(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Add group member");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP | CHK_MEM, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "addgroupmember") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].get<string>();
	string member = cmd["member"].get<string>();

	this->store->GroupAddMember(group, member);

	this->SendOK(client, cmd);
}

void SecopServer::DoGroupRemoveMember(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Remove group member");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP | CHK_MEM, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "removegroupmember") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].get<string>();
	string member = cmd["member"].get<string>();

	this->store->GroupRemoveMember(group, member);

	this->SendOK(client, cmd);

}

void SecopServer::DoGroupGetMembers(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Get group members");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP, cmd) )
	{
		return;
	}

	//Todo: Should we have any policy on this?

	string group = cmd["group"].get<string>();

	vector<string> members = this->store->GroupGetMembers(group);

	json ret;
	ret["members"];
	for( const auto& member: members)
	{
		ret["members"].push_back(member);
	}

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoGroupRemove(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Remove group");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_GRP, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "removegroup") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string group = cmd["group"].get<string>();

	// Sanity check, we don't allow users to remove admin group
	if( group == "admin" )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	this->store->GroupRemove(group);

	this->SendOK(client, cmd);
}

void SecopServer::DoCreateAppID(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Create appid");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "createappid") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string appid = cmd["appid"].get<string>();

	if( this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid already exists");
		return;
	}

	this->store->CreateAppID(appid);

	this->SendOK(client, cmd);

}

void SecopServer::DoGetAppIDs(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Get appids");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID, cmd) )
	{
		return;
	}

	vector<string> appids = this->store->GetAppIDs();

	json ret;

	for( const auto& appid: appids )
	{
		ret["appids"].push_back(appid);
	}
	this->SendOK(client, cmd, ret);

}

void SecopServer::DoRemoveAppID(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Remove appid");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( ! this->AdminOrAllowed(session["user"]["username"].get<string>(), "removeappid") )
	{
		this->SendErrorMessage(client, cmd, 2, "Not allowed");
		return;
	}

	string appid = cmd["appid"].get<string>();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Unknown appid");
		return;
	}

	this->store->DeleteAppID( appid );

	this->SendOK(client, cmd);
}

void SecopServer::DoAppGetIdentifiers(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!

	ScopedLog l("Get app identifiers");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID,  cmd) )
	{
		return;
	}

	string appid = cmd["appid"].get<string>();

	if( ! this->store->HasAppID(appid) )
	{
		this->SendErrorMessage(client, cmd, 3, "Appid unknown");
		return;
	}

	/* Todo, add policy check */
	// Not empty and user not in ACL
	if( ! this->store->AppACLEmpty(appid) &&
			! this->store->AppHasACL( appid, session["user"]["username"].get<string>() ) &&
			! this->AdminOrAllowed(session["user"]["username"].get<string>(), "getappidentifiers") )
	{
		this->SendErrorMessage(client, cmd, 4, "Access not allowed");
		return;
	}

	json ret;
	ret["identifiers"] = this->store->AppGetIdentifiers( appid );

	this->SendOK(client, cmd, ret);
}

void SecopServer::DoAppAddIdentifier(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Add app identifier");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	string appid = cmd["appid"].get<string>();

	if( ! this->store->HasAppID( appid) )
	{
		this->SendErrorMessage(client, cmd, 3, "Appid unknown");
		return;
	}


	if( !cmd.contains("identifier") || !cmd["identifier"].is_object() )
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
		if ( ! this->store->AppHasACL(appid, session["user"]["username"].get<string>() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "addappidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	this->store->AppAddIdentifier( appid, cmd["identifier"]);

	this->SendOK(client, cmd);

}

void SecopServer::DoAppRemoveIdentifier(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Remove identifier");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	string appid = cmd["appid"].get<string>();

	if( ! this->store->HasAppID( appid) )
	{
		this->SendErrorMessage(client, cmd, 3, "Appid unknown");
		return;
	}

	if( !cmd.contains("identifier") || !cmd["identifier"].is_object() )
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
		if ( ! this->store->AppHasACL(appid, session["user"]["username"].get<string>() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "removeappidentifier") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	json needle = cmd["identifier"];
	json ids = this->store->AppGetIdentifiers( appid );
	json new_ids= json::array();

	bool id_removed = false;
	// For each identifier for appid
	for( auto id: ids)
	{
		bool found = false;

		//For each key/value in search arg


		for( const auto& m: needle.items())
		{
			// Member exists in current identifier?
			if( id.contains( m.key() ) )
			{
				if( id[m.key() ].get<string>() == m.value().get<string>() )
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
			new_ids.push_back( id );
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

void SecopServer::DoAppAddACL(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{

	ScopedLog l("Add app ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( !cmd.contains("acl") || !cmd["acl"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string appid = cmd["appid"].get<string>();
	string acl = cmd["acl"].get<string>();

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
		if ( ! this->store->AppHasACL(appid, session["user"]["username"].get<string>() )  )
		{
			if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "appaddacl") )
			{
				this->SendErrorMessage(client, cmd, 4, "Not allowed");
				return;
			}
		}
	}

	this->store->AppAddAcl(appid, acl);

	this->SendOK(client, cmd);

}

void SecopServer::DoAppGetACL(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Get app ACL");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	string appid = cmd["appid"].get<string>();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid unknown");
		return;
	}


	vector<string> acls = this->store->AppGetACL( appid );

	json ret;

	ret["acl"] = json::array();

	for( const auto& acl: acls )
	{
		ret["acl"].push_back(acl);
	}
	this->SendOK(client, cmd, ret);
}

void SecopServer::DoAppRemoveACL(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!
	ScopedLog l("Remove app ACL");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( !cmd.contains("acl") || !cmd["acl"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}

	string appid = cmd["appid"].get<string>();
	string acl = cmd["acl"].get<string>();

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

	if ( ! this->store->AppHasACL(appid, session["user"]["username"].get<string>() )  )
	{
		if ( ! this->AdminOrAllowed(session["user"]["username"].get<string>() , "removeappacl") )
		{
			this->SendErrorMessage(client, cmd, 4, "Not allowed");
			return;
		}
	}

	this->store->AppRemoveAcl(appid, acl);

	this->SendOK(client, cmd);

}

void SecopServer::DoAppHasACL(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	ScopedLog l("Has app ACL");
    (void) session;

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_APPID, cmd) )
	{
		return;
	}

	if( !cmd.contains("acl") || !cmd["acl"].is_string() )
	{
		this->SendErrorMessage(client, cmd, 2, "Missing argument");
		return;
	}
	string appid = cmd["appid"].get<string>();
	string acl = cmd["acl"].get<string>();

	if( !this->store->HasAppID( appid ) )
	{
		this->SendErrorMessage(client, cmd, 2, "Appid unknown");
		return;
	}

	json ret;
	ret["hasacl"] = this->store->AppHasACL(appid, acl);

	this->SendOK(client, cmd, ret);

}

void
SecopServer::DoGetIdentifiers(UnixStreamClientSocketPtr &client, json &cmd, json &session)
{
	//TODO: Access control!

	ScopedLog l("Get identifiers");

	if( ! this->CheckArguments( client, CHK_API | CHK_TID | CHK_USR | CHK_SRV, cmd) )
	{
		return;
	}

	string user = cmd["username"].get<string>();
	string service = cmd["servicename"].get<string>();

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
			! this->store->HasACL(user, service, session["user"]["username"].get<string>() ) &&
			! this->AdminOrAllowed(session["user"]["username"].get<string>(), "getidentifiers") )
	{
		this->SendErrorMessage(client, cmd, 4, "Access not allowed");
		return;
	}

	json ret;
	ret["identifiers"] = this->store->GetIdentifiers( user, service );

	this->SendOK(client, cmd, ret);
}

