/*
 * CryptoStorage.cpp
 *
 *  Created on: Oct 22, 2013
 *      Author: tor
 */

#include <libutils/FileUtils.h>
#include <libutils/Logger.h>

#include <utility>
#include <vector>

#include "CryptoStorage.h"

using namespace Utils;

//TODO: Change to something a bit more random?
const vector<byte> CryptoStorage::iv=
		{
				1,2,3,4,
				5,6,7,8,
				9,10,11,12,
				13,14,15,16
		};

void CryptoStorage::New()
{
	this->data.clear();

	this->data["user"]=json();

	this->data["group"]=json();
	this->data["group"]["admin"]=json::array();

	this->data["system"]=json();
	this->data["config"]["version"]=this->version;

	this->Write();
}

void
CryptoStorage::Initialize ()
{
	if( ! File::FileExists( path ) )
	{
		logg << Logger::Debug << "Creating new storage at "<<this->path<<lend;
		this->New();
	}
	else
	{
		logg << Logger::Debug << "Reading storage at "<< this->path<<lend;
		this->Read();
	}
}



CryptoStorage::CryptoStorage (string  path, const SecString& pwd , bool undertest)
	:version(1.0), readversion(0), path(std::move(path)), undertest(undertest)
{
	SecVector<byte> key = Crypto::PBKDF2(pwd,32);
	this->key = key;
	this->filecrypto.Initialize(key, iv);
	this->Initialize();
}


CryptoStorage::CryptoStorage (string  path, const SecVector<byte>& key, bool undertest)
	:version(1.0),readversion(0), path(std::move(path)), undertest(undertest), key(key), filecrypto(key, iv)
{
	this->Initialize();
}

bool CryptoStorage::HasAppID(const string &appid)
{
	return this->data["system"].contains(appid);
}

void CryptoStorage::CreateAppID(const string &appid)
{
	if( this->HasAppID(appid) )
	{
		throw std::runtime_error("Appid already exists");
	}
	this->data["system"][appid]["attributes"]=json();

	this->Write();

}

void CryptoStorage::DeleteAppID(const string &appid)
{
	if( this->HasAppID( appid ) )
	{
		this->data["system"].erase(appid);
	}
	else
	{
		throw std::runtime_error("Appid not found");
	}
	this->Write();
}

vector<string> CryptoStorage::GetAppIDs()
{
	vector<string> ret;
	for(const auto& system: this->data["system"].items() )
	{
		ret.push_back(system.key());
	}
	return ret;
}

bool CryptoStorage::HasGroup(const string &group)
{
	return this->data["group"].contains(group);
}

void CryptoStorage::GroupAdd(const string &group)
{
	if( this->HasGroup( group ) )
	{
		throw std::runtime_error("Group exists");
	}
	this->data["group"][group]=json::array();
	this->Write();
}

vector<string> CryptoStorage::GroupsGet()
{
	vector<string> ret;
	for(const auto& group: this->data["group"].items() )
	{
		ret.push_back(group.key());
	}
	return ret;
}

void CryptoStorage::GroupAddMember(const string &group, const string &member)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	json members = this->data["group"][group];

	bool found = false;
	for_each(members.begin(), members.end(),
			 [&found, member](const json& v){ if(v.get<string>() == member ){ found=true;}}
	);

	if( ! found )
	{
		members.push_back(member);
		this->data["group"][group] = members;
		this->Write();
	}
}

void CryptoStorage::GroupRemoveMember(const string &group, const string &member)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	json members = this->data["group"][group];
	json replace = json::array();

	bool removed = false;
	for(const auto& mem: members)
	{
		if( mem.get<string>() != member )
		{
			replace.push_back(mem);
		}
		else
		{
			removed = true;
		}
	}

	if( removed )
	{
		this->data["group"][group] = replace;
		this->Write();
	}
}

vector<string> CryptoStorage::GroupGetMembers(const string &group)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	vector<string> ret;

	json members = this->data["group"][group];
	for(const auto& member: members)
	{
		ret.push_back( member.get<string>() );
	}
	return ret;
}

void CryptoStorage::GroupRemove(const string &group)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	this->data["group"].erase(group);
	this->Write();
}

bool CryptoStorage::GroupHasMember(const string &group, const string &member)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	bool found = false;
	json members = this->data["group"][group];
	for(const auto& mem: members)
	{
		if( mem.get<string>() == member )
		{
			found = true;
		}
	}

	return found;
}

void CryptoStorage::AppAddIdentifier(const string &appid, const json &val)
{
	json ids = this->AppGetIdentifiers( appid );

	ids.push_back(val);

	this->AppUpdateIdentifiers( appid, ids );
}

json CryptoStorage::AppGetIdentifiers(const string &appid)
{

	if( this->data["system"][appid].contains("identifiers") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["identifiers"].is_string() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->AppUpdateIdentifiers(appid, json::array() );
	}
	return this->AppDecryptIdentifiers( appid );
}

void CryptoStorage::AppUpdateIdentifiers(const string &appid, const json &val)
{

	if( ! val.is_array() )
	{
		throw std::runtime_error("Identifiers not array");
	}
	this->AppEncryptIdentifiers(appid, val);

	this->Write();

}

void CryptoStorage::AppAddAcl(const string &appid, const string &entity)
{
	if( !this->HasAppID( appid ) )
	{
		throw std::runtime_error("Appid unknown");
	}

	if( this->data["system"][appid].contains("acl") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["acl"].is_array() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["system"][appid]["acl"]=json::array();
	}

	bool found = false;

	for(const auto& v : this->data["system"][appid]["acl"] )
	{
		if( v.is_string() && v.get<string>() == entity )
		{
			found = true;
		}
	}

	if( ! found )
	{
		this->data["system"][appid]["acl"].push_back( json( entity ) );

		this->Write();
	}

}

bool CryptoStorage::AppHasACL(const string &appid, const string &entity)
{
	if( ! this->HasAppID( appid)  )
	{
		throw std::runtime_error("User unknown");
	}

	if( ! this->data["system"][appid].contains("acl") )
	{
		return false;
	}

	if( ! this->data["system"][appid]["acl"].is_array() )
	{
		throw std::runtime_error("Malformed syntax in storage");
	}

	bool found = false;
	for( const auto& x: this->data["system"][appid]["acl"] )
	{
		if( x.is_string() && x.get<string>() == entity )
		{
			found = true;
			break;
		}
	}
	return found;
}

bool CryptoStorage::AppACLEmpty(const string &appid)
{
	if( ! this->HasAppID(appid)  )
	{
		throw std::runtime_error("User unknown");
	}

	if( ! this->data["system"][appid].contains("acl") )
	{
		return true;
	}

	if( ! this->data["system"][appid]["acl"].is_array() )
	{
		throw std::runtime_error("Malformed syntax in storage");
	}

	return this->data["system"][appid]["acl"].size() == 0;

}

vector<string> CryptoStorage::AppGetACL(const string &appid)
{
	if( !this->HasAppID( appid ) )
	{
		throw std::runtime_error("Appid unknown");
	}

	if( this->data["system"][appid].contains("acl") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["acl"].is_array() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["system"][appid]["acl"]=json::array();
	}

	vector<string> ret;
	json acl = this->data["system"][appid]["acl"];
	for( const auto& ent: acl)
	{
		if( ent.is_string() )
		{
			ret.push_back(ent.get<string>());
		}
	}
	return ret;

}

void CryptoStorage::AppRemoveAcl(const string &appid, const string &entity)
{
	if ( !this->HasAppID(appid) ) {
		throw std::runtime_error("Appid unknown");
	}

	if( this->data["system"][appid].contains("acl") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["acl"].is_array() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}

	json newArray = json::array();
	bool removed = false;
	for( const auto& x: this->data["system"][appid]["acl"] )
	{
		if( x.is_string() && x.get<string>() != entity )
		{
			newArray.push_back(x.get<string>() );
		}
		else
		{
			removed = true;
		}
	}

	if( removed )
	{
		this->data["system"][appid]["acl"] = newArray;
		this->Write();
	}
}

CryptoStorage::~CryptoStorage () = default;

void
CryptoStorage::Read ()
{
	vector<byte> in;
	File::ReadVector<vector<byte>>(this->path, in);

    stringstream cnt(this->filecrypto.Decrypt(in));
    logg << Logger::Debug << "Decrypted db, size "<< static_cast<int>(cnt.str().size()) <<lend;
	if( this->undertest )
	{
		logg << Logger::Debug << "Content ["<<cnt.str() <<"]"<<lend;
	}

	json ret = json::array();
    string errs;
	try
	{
		cnt >> this->data;
	}
	catch (json::parse_error& err)
	{
		logg << Logger::Error << "Failed to parse storage at "<<this->path << " ( " << err.what() << ")" <<lend;
		throw;
	}

    logg << Logger::Debug << "Read storage at"<< this->path <<lend;
	if( data["config"].contains("version") && data["config"]["version"].is_number_float() )
    {
		this->readversion = this->data["config"]["version"].get<double>();
        logg << Logger::Debug << "Storage file has version "<< static_cast<int>(this->readversion) << lend;
    }
    else
    {
        logg << Logger::Debug << "No version information found on storage"<<lend;
    }

}

void
CryptoStorage::AddService ( const string& username, const string& servicename )
{
	if( ! this->HasUser(username)  )
	{
		throw std::runtime_error("User unknown in add service");
	}

	if( this->HasService( username, servicename ) )
	{
		throw std::runtime_error("Service already added");
	}

	this->data["user"][username]["services"][servicename]["acl"] = json::array();

	this->Write();
}

void
CryptoStorage::RemoveService( const string& username, const string& servicename )
{
	if( ! this->HasUser(username)  )
	{
		throw std::runtime_error("User unknown in remove service");
	}

	if( ! this->HasService( username, servicename ) )
	{
		throw std::runtime_error("Service not found for user");
	}

	this->data["user"][username]["services"].erase(servicename);

	this->Write();
}

vector<string>
CryptoStorage::GetServices(const string &username)
{
	if( ! this->HasUser(username)  )
	{
		throw std::runtime_error("User unknown in get services");
	}

	vector<string> ret;
	for(const auto& service: this->data["user"][username]["services"].items() )
	{
		ret.push_back(service.key());
	}
	return ret;
}

vector<string>
CryptoStorage::GetACL(const string& username, const string& service)
{
	if( !this->HasService( username, service ) )
	{
		throw std::runtime_error("Service unknown");
	}

	if( this->data["user"][username]["services"][service].contains("acl") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["acl"].is_array() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["user"][username]["services"][service]["acl"]=json::array();
	}

	vector<string> ret;
	json acl = this->data["user"][username]["services"][service]["acl"];
	for( const auto& ent: acl)
	{
		if( ent.is_string() )
		{
			ret.push_back(ent.get<string>());
		}
	}
	return ret;
}

void
CryptoStorage::AddAcl ( const string& username, const string& service,
		const string& entity )
{
	if( !this->HasService( username, service ) )
	{
		throw std::runtime_error("Service unknown");
	}

	if( this->data["user"][username]["services"][service].contains("acl") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["acl"].is_array() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["user"][username]["services"][service]["acl"]=json::array();
	}

	bool found = false;

	for(const auto& v : this->data["user"][username]["services"][service]["acl"] )
	{
		if( v.is_string() && v.get<string>() == entity )
		{
			found = true;
		}
	}

	if( ! found )
	{
		this->data["user"][username]["services"][service]["acl"].push_back( json( entity ) );

		this->Write();
	}
}

void
CryptoStorage::RemoveAcl(const string &username, const string &service, const string &entity)
{
	if ( !this->HasService(username, service) ) {
		throw std::runtime_error("Service unknown");
	}

	if( this->data["user"][username]["services"][service].contains("acl") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["acl"].is_array() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}

	json newArray = json::array();
	bool removed = false;
	for( const auto& x: this->data["user"][username]["services"][service]["acl"] )
	{
		if( x.is_string() && x.get<string>() != entity )
		{
			newArray.push_back(x.get<string>() );
		}
		else
		{
			removed = true;
		}
	}

	if( removed )
	{
		this->data["user"][username]["services"][service]["acl"] = newArray;
		this->Write();
	}
}

bool
CryptoStorage::ACLEmpty(const string &username, const string &service)
{
	if( ! this->HasUser(username)  )
	{
		throw std::runtime_error("User unknown");
	}

	if( ! this->HasService( username, service ) )
	{
		throw std::runtime_error("Service not found for user");
	}

	if( ! this->data["user"][username]["services"][service].contains("acl") )
	{
		return true;
	}

	if( ! this->data["user"][username]["services"][service]["acl"].is_array() )
	{
		throw std::runtime_error("Malformed syntax in storage");
	}

	return this->data["user"][username]["services"][service]["acl"].size() == 0;
}

bool
CryptoStorage::HasACL(const string &username, const string &service, const string &entity)
{

	if( ! this->HasUser(username)  )
	{
		throw std::runtime_error("User unknown");
	}

	if( ! this->HasService( username, service ) )
	{
		throw std::runtime_error("Service not found for user");
	}

	if( ! this->data["user"][username]["services"][service].contains("acl") )
	{
		return false;
	}

	if( ! this->data["user"][username]["services"][service]["acl"].is_array() )
	{
		throw std::runtime_error("Malformed syntax in storage");
	}

	bool found = false;
	for( const auto& x: this->data["user"][username]["services"][service]["acl"] )
	{
		if( x.is_string() && x.get<string>() == entity )
		{
			found = true;
			break;
		}
	}
	return found;
}

void
CryptoStorage::AddIdentifier ( const string& username, const string& service,
		const json& val )
{
	json ids = this->GetIdentifiers(username, service );

	ids.push_back(val);

	this->UpdateIdentifiers(username, service, ids);
}

json
CryptoStorage::GetIdentifiers ( const string& username, const string& service )
{
	if( ! this->HasService(username, service) )
	{
		throw std::runtime_error("No such service");
	}

	if( this->data["user"][username]["services"][service].contains("identifiers") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["identifiers"].is_string() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->UpdateIdentifiers(username, service, json::array() );
	}
	return this->DecryptIdentifiers(username,service);
}

void
CryptoStorage::UpdateIdentifiers ( const string& username,
		const string& service, const json& val )
{
	if( ! this->HasService(username, service) )
	{
		throw std::runtime_error("No such service");
	}

	if( ! val.is_array() )
	{
		throw std::runtime_error("Identifiers not array");
	}
	this->EncryptIdentifiers(username, service, val);

	this->Write();
}


void
CryptoStorage::Write ()
{
	// Make a local backup if db exists.
	if( File::FileExists(this->path) )
	{
		File::Copy(this->path, this->path+".bak");
	}

	stringstream output;
	output << this->data;

	string enc = this->filecrypto.Encrypt(output.str());

	vector<byte> vout(enc.begin(), enc.end());

	File::SafeWrite(this->path, &vout[0], vout.size(), 0600);
}

void
CryptoStorage::CreateUser (const string& username , const string &displayname)
{
	if( this->HasUser(username) )
	{
		throw std::runtime_error("User already exists");
	}
	this->data["user"][username]["services"]=json();

	if( displayname != "" )
	{
		this->data["user"][username]["attributes"]["displayname"]=displayname;
	}
	else
	{
		this->data["user"][username]["attributes"]=json();
	}
	this->Write();
}

void
CryptoStorage::CreateApplication ( const string& appname )
{
	if( this->hasApplication(appname) )
	{
		throw std::runtime_error("User already exists");
	}
	this->data["system"][appname]=json();

	this->Write();
}

bool
CryptoStorage::HasUser (const string& user)
{
	return this->data["user"].contains(user);
}

vector<string>
CryptoStorage::GetUsers()
{
	vector<string> ret;
	for(const auto& user: this->data["user"].items() )
	{
		ret.push_back(user.key());
	}
	return ret;
}

bool CryptoStorage::HasAttribute(const string &username, const string &attributename)
{
	if( ! this->HasUser(username) )
	{
		return false;
	}
	return this->data["user"][username]["attributes"].contains(attributename);

}

vector<string> CryptoStorage::GetAttributes(const string &username)
{
	if( ! this->HasUser(username) )
	{
		throw std::runtime_error("User not found");
	}
	return vector<string>(this->data["user"][username]["attributes"].begin(),this->data["user"][username]["attributes"].end());
}

string CryptoStorage::GetAttribute(const string &username, const string &attributename)
{
	if( ! this->HasAttribute(username, attributename) )
	{
		throw std::runtime_error("User or attribute not found");
	}

	return this->data["user"][username]["attributes"][attributename].get<string>();
}

void CryptoStorage::AddAttribute(const string &username, const string &attributename, const string& attributevalue)
{
	if( ! this->HasUser(username) )
	{
		throw std::runtime_error("User not found");
	}

	this->data["user"][username]["attributes"][attributename]=attributevalue;

	this->Write();
}

void CryptoStorage::RemoveAttribute(const string &username, const string &attributename)
{
	if( ! this->HasUser(username) )
	{
		throw std::runtime_error("User not found");
	}

	if( !this->HasAttribute(username, attributename) )
	{
		throw std::runtime_error("Attribute not found");
	}

	this->data["user"][username]["attributes"].erase(attributename);

	this->Write();
}

bool
CryptoStorage::HasService ( const string& user, const string& service )
{
	return this->data["user"][user]["services"].contains(service);
}

bool
CryptoStorage::hasApplication (const string& app)
{
	return this->data["system"].contains(app);
}

json
CryptoStorage::DecryptIdentifiers(const string& username, const string& service)
{
	vector<byte> iv;

	Crypto::Base64Decode(this->data["user"][username]["services"][service]["iv"].get<string>(), iv);

	vector<byte> val;
	Crypto::Base64Decode(this->data["user"][username]["services"][service]["identifiers"].get<string>(), val);

	this->idcrypto.Initialize(this->key, iv);
    stringstream ids( this->idcrypto.Decrypt(val) );

	json ret;
	ids >> ret;

	return ret;
}

void
CryptoStorage::EncryptIdentifiers(const string& username, const string& service, const json& val)
{
	// Generate and save new IV
	vector<byte> iv(AES::BLOCKSIZE);
	this->rnd.GenerateBlock(&iv[0], iv.size() );

	string b64iv = Crypto::Base64Encode( iv );
	this->data["user"][username]["services"][service]["iv"]=b64iv;

	this->idcrypto.Initialize(this->key, iv);
	stringstream output;
	output << val;

	string b64val = Crypto::Base64Encode(
            this->idcrypto.Encrypt( output.str() )
			);

	this->data["user"][username]["services"][service]["identifiers"] = b64val;
}

json CryptoStorage::AppDecryptIdentifiers(const string &appid)
{
	vector<byte> iv;

	Crypto::Base64Decode(this->data["system"][appid]["iv"].get<string>(), iv);

	vector<byte> val;
	Crypto::Base64Decode(this->data["system"][appid]["identifiers"].get<string>(), val);

	this->idcrypto.Initialize(this->key, iv);

	return json::parse(this->idcrypto.Decrypt(val));
}

void CryptoStorage::AppEncryptIdentifiers(const string &appid, const json &val)
{
	// Generate and save new IV
	vector<byte> iv(AES::BLOCKSIZE);
	this->rnd.GenerateBlock(&iv[0], iv.size() );

	string b64iv = Crypto::Base64Encode( iv );
	this->data["system"][appid]["iv"]=b64iv;

	this->idcrypto.Initialize(this->key, iv);

    stringstream output;
	output << val;

	string b64val = Crypto::Base64Encode(
            this->idcrypto.Encrypt( output.str() )
			);

	this->data["system"][appid]["identifiers"] = b64val;
}


void
CryptoStorage::DeleteUser ( const string& username )
{
	if( this->HasUser( username ) )
	{
		this->data["user"].erase(username);
	}
	else
	{
		throw std::runtime_error("User not found");
	}
	this->Write();
}
