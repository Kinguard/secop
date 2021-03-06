/*
 * CryptoStorage.cpp
 *
 *  Created on: Oct 22, 2013
 *      Author: tor
 */

#include <libutils/FileUtils.h>
#include <libutils/Logger.h>

#include <vector>

#include "CryptoStorage.h"

using namespace Utils;

//TODO: Change to something a bit more random?
static vector<byte> iv=
		{
				1,2,3,4,
				5,6,7,8,
				9,10,11,12,
				13,14,15,16
		};

void CryptoStorage::New()
{
	this->data.clear();

	this->data["user"]=Json::nullValue;

	this->data["group"]=Json::nullValue;
	this->data["group"]["admin"]=Json::arrayValue;

	this->data["system"]=Json::nullValue;
	this->data["config"]["version"]=this->version;

	this->Write();
}

void
CryptoStorage::Initialize ()
{
    // Initialize StreamWriter

    Json::StreamWriterBuilder builder;

    this->writer = unique_ptr<Json::StreamWriter>(builder.newStreamWriter());

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



CryptoStorage::CryptoStorage (const string& path, const SecString& pwd , bool undertest)
	:version(1.0), readversion(0), path(path), undertest(undertest)
{
	SecVector<byte> key = Crypto::PBKDF2(pwd,32);
	this->key = key;
	this->filecrypto.Initialize(key, iv);
	this->Initialize();
}


CryptoStorage::CryptoStorage (const string& path, const SecVector<byte>& key, bool undertest)
	:version(1.0),readversion(0), path(path), undertest(undertest), key(key), filecrypto(key, iv)
{
	this->Initialize();
}

bool CryptoStorage::HasAppID(const string &appid)
{
	return this->data["system"].isMember(appid);
}

void CryptoStorage::CreateAppID(const string &appid)
{
	if( this->HasAppID(appid) )
	{
		throw std::runtime_error("Appid already exists");
	}
	this->data["system"][appid]["attributes"]=Json::nullValue;

	this->Write();

}

void CryptoStorage::DeleteAppID(const string &appid)
{
	if( this->HasAppID( appid ) )
	{
		this->data["system"].removeMember(appid);
	}
	else
	{
		throw std::runtime_error("Appid not found");
	}
	this->Write();
}

vector<string> CryptoStorage::GetAppIDs()
{
	return this->data["system"].getMemberNames();
}

bool CryptoStorage::HasGroup(const string &group)
{
	return this->data["group"].isMember(group);
}

void CryptoStorage::GroupAdd(const string &group)
{
	if( this->HasGroup( group ) )
	{
		throw std::runtime_error("Group exists");
	}
	this->data["group"][group]=Json::arrayValue;
	this->Write();
}

vector<string> CryptoStorage::GroupsGet()
{
	return this->data["group"].getMemberNames();
}

void CryptoStorage::GroupAddMember(const string &group, const string &member)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	Json::Value members = this->data["group"][group];

	bool found = false;
	for_each(members.begin(), members.end(),
			 [&found, member](Json::Value v){ if(v.asString() == member ){ found=true;}}
	);

	if( ! found )
	{
		members.append(member);
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

	Json::Value members = this->data["group"][group];
	Json::Value replace(Json::arrayValue);

	bool removed = false;
	for(auto mem: members)
	{
		if( mem.asString() != member )
		{
			replace.append(mem);
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

	Json::Value members = this->data["group"][group];
	for(auto member: members)
	{
		ret.push_back( member.asString() );
	}
	return ret;
}

void CryptoStorage::GroupRemove(const string &group)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	this->data["group"].removeMember(group);
	this->Write();
}

bool CryptoStorage::GroupHasMember(const string &group, const string &member)
{
	if( ! this->HasGroup( group ) )
	{
		throw std::runtime_error("Group doesn't' exists");
	}

	bool found = false;
	Json::Value members = this->data["group"][group];
	for(auto mem: members)
	{
		if( mem.asString() == member )
		{
			found = true;
		}
	}

	return found;
}

void CryptoStorage::AppAddIdentifier(const string &appid, const Json::Value &val)
{
	Json::Value ids = this->AppGetIdentifiers( appid );

	ids.append(val);

	this->AppUpdateIdentifiers( appid, ids );
}

Json::Value CryptoStorage::AppGetIdentifiers(const string &appid)
{

	if( this->data["system"][appid].isMember("identifiers") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["identifiers"].isString() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->AppUpdateIdentifiers(appid, Json::Value(Json::arrayValue) );
	}
	return this->AppDecryptIdentifiers( appid );
}

void CryptoStorage::AppUpdateIdentifiers(const string &appid, const Json::Value &val)
{

	if( ! val.isArray() )
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

	if( this->data["system"][appid].isMember("acl") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["acl"].isArray() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["system"][appid]["acl"]=Json::Value(Json::arrayValue);
	}

	bool found = false;

	for(auto v : this->data["system"][appid]["acl"] )
	{
		if( v.isString() && v.asString() == entity )
		{
			found = true;
		}
	}

	if( ! found )
	{
		this->data["system"][appid]["acl"].append( Json::Value( entity ) );

		this->Write();
	}

}

bool CryptoStorage::AppHasACL(const string &appid, const string &entity)
{
	if( ! this->HasAppID( appid)  )
	{
		throw std::runtime_error("User unknown");
	}

	if( ! this->data["system"][appid].isMember("acl") )
	{
		return false;
	}

	if( ! this->data["system"][appid]["acl"].isArray() )
	{
		throw std::runtime_error("Malformed syntax in storage");
	}

	bool found = false;
	for( auto x: this->data["system"][appid]["acl"] )
	{
		if( x.isString() && x.asString() == entity )
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

	if( ! this->data["system"][appid].isMember("acl") )
	{
		return true;
	}

	if( ! this->data["system"][appid]["acl"].isArray() )
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

	if( this->data["system"][appid].isMember("acl") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["acl"].isArray() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["system"][appid]["acl"]=Json::Value(Json::arrayValue);
	}

	vector<string> ret;
	Json::Value acl = this->data["system"][appid]["acl"];
	for( auto ent: acl)
	{
		if( ent.isString() )
		{
			ret.push_back(ent.asString());
		}
	}
	return ret;

}

void CryptoStorage::AppRemoveAcl(const string &appid, const string &entity)
{
	if ( !this->HasAppID(appid) ) {
		throw std::runtime_error("Appid unknown");
	}

	if( this->data["system"][appid].isMember("acl") )
	{
		// Element is present, verify
		if( ! this->data["system"][appid]["acl"].isArray() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}

	Json::Value newArray(Json::arrayValue);
	bool removed = false;
	for( auto x: this->data["system"][appid]["acl"] )
	{
		if( x.isString() && x.asString() != entity )
		{
			newArray.append(x.asString() );
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

CryptoStorage::~CryptoStorage ()
{
}

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

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value ret(Json::arrayValue);
    string errs;
    if( ! Json::parseFromStream(builder, cnt, &this->data, &errs) )
    {
        logg << Logger::Error << "Failed to parse storage at "<<this->path << " Errors " << errs <<lend;
        throw std::runtime_error(errs);
    }

    logg << Logger::Debug << "Read storage at"<< this->path <<lend;
    if( data["config"].isMember("version") && data["config"]["version"].isDouble() )
    {
        this->readversion = this->data["config"]["version"].asDouble();
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

	this->data["user"][username]["services"][servicename]["acl"] = Json::Value(Json::arrayValue);

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

	this->data["user"][username]["services"].removeMember(servicename);

	this->Write();
}

vector<string>
CryptoStorage::GetServices(const string &username)
{
	if( ! this->HasUser(username)  )
	{
		throw std::runtime_error("User unknown in get services");
	}
	return this->data["user"][username]["services"].getMemberNames();
}

vector<string>
CryptoStorage::GetACL(const string& username, const string& service)
{
	if( !this->HasService( username, service ) )
	{
		throw std::runtime_error("Service unknown");
	}

	if( this->data["user"][username]["services"][service].isMember("acl") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["acl"].isArray() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["user"][username]["services"][service]["acl"]=Json::Value(Json::arrayValue);
	}

	vector<string> ret;
	Json::Value acl = this->data["user"][username]["services"][service]["acl"];
	for( auto ent: acl)
	{
		if( ent.isString() )
		{
			ret.push_back(ent.asString());
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

	if( this->data["user"][username]["services"][service].isMember("acl") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["acl"].isArray() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->data["user"][username]["services"][service]["acl"]=Json::Value(Json::arrayValue);
	}

	bool found = false;

	for(auto v : this->data["user"][username]["services"][service]["acl"] )
	{
        if( v.isString() && v.asString() == entity )
		{
			found = true;
		}
	}

	if( ! found )
	{
		this->data["user"][username]["services"][service]["acl"].append( Json::Value( entity ) );

		this->Write();
	}
}

void
CryptoStorage::RemoveAcl(const string &username, const string &service, const string &entity)
{
	if ( !this->HasService(username, service) ) {
		throw std::runtime_error("Service unknown");
	}

	if( this->data["user"][username]["services"][service].isMember("acl") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["acl"].isArray() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}

	Json::Value newArray(Json::arrayValue);
	bool removed = false;
	for( auto x: this->data["user"][username]["services"][service]["acl"] )
	{
		if( x.isString() && x.asString() != entity )
		{
			newArray.append(x.asString() );
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

	if( ! this->data["user"][username]["services"][service].isMember("acl") )
	{
		return true;
	}

	if( ! this->data["user"][username]["services"][service]["acl"].isArray() )
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

	if( ! this->data["user"][username]["services"][service].isMember("acl") )
	{
		return false;
	}

	if( ! this->data["user"][username]["services"][service]["acl"].isArray() )
	{
		throw std::runtime_error("Malformed syntax in storage");
	}

	bool found = false;
	for( auto x: this->data["user"][username]["services"][service]["acl"] )
	{
		if( x.isString() && x.asString() == entity )
		{
			found = true;
			break;
		}
	}
	return found;
}

void
CryptoStorage::AddIdentifier ( const string& username, const string& service,
		const Json::Value& val )
{
	Json::Value ids = this->GetIdentifiers(username, service );

	ids.append(val);

	this->UpdateIdentifiers(username, service, ids);
}

Json::Value
CryptoStorage::GetIdentifiers ( const string& username, const string& service )
{
	if( ! this->HasService(username, service) )
	{
		throw std::runtime_error("No such service");
	}

	if( this->data["user"][username]["services"][service].isMember("identifiers") )
	{
		// Element is present, verify
		if( ! this->data["user"][username]["services"][service]["identifiers"].isString() )
		{
			throw std::runtime_error("Malformed syntax in storage");
		}
	}
	else
	{
		// Not present, create
		this->UpdateIdentifiers(username, service, Json::Value(Json::arrayValue) );
	}
	return this->DecryptIdentifiers(username,service);
}

void
CryptoStorage::UpdateIdentifiers ( const string& username,
		const string& service, const Json::Value& val )
{
	if( ! this->HasService(username, service) )
	{
		throw std::runtime_error("No such service");
	}

	if( ! val.isArray() )
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
	this->writer->write(this->data, &output);
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
	this->data["user"][username]["services"]=Json::nullValue;

	if( displayname != "" )
	{
		this->data["user"][username]["attributes"]["displayname"]=displayname;
	}
	else
	{
		this->data["user"][username]["attributes"]=Json::nullValue;
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
	this->data["system"][appname]=Json::nullValue;

	this->Write();
}

bool
CryptoStorage::HasUser (const string& user)
{
	return this->data["user"].isMember(user);
}

vector<string>
CryptoStorage::GetUsers()
{
	return this->data["user"].getMemberNames();
}

bool CryptoStorage::HasAttribute(const string &username, const string &attributename)
{
	if( ! this->HasUser(username) )
	{
		return false;
	}
	return this->data["user"][username]["attributes"].isMember(attributename);

}

vector<string> CryptoStorage::GetAttributes(const string &username)
{
	if( ! this->HasUser(username) )
	{
		throw std::runtime_error("User not found");
	}

	return this->data["user"][username]["attributes"].getMemberNames();
}

string CryptoStorage::GetAttribute(const string &username, const string &attributename)
{
	if( ! this->HasAttribute(username, attributename) )
	{
		throw std::runtime_error("User or attribute not found");
	}

	return this->data["user"][username]["attributes"][attributename].asString();
}

void CryptoStorage::AddAttribute(const string &username, const string &attributename, const string attributevalue)
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

	this->data["user"][username]["attributes"].removeMember(attributename);

	this->Write();
}

bool
CryptoStorage::HasService ( const string& user, const string& service )
{
	return this->data["user"][user]["services"].isMember(service);
}

bool
CryptoStorage::hasApplication (const string& app)
{
	return this->data["system"].isMember(app);
}

Json::Value
CryptoStorage::DecryptIdentifiers(const string& username, const string& service)
{
	vector<byte> iv;

	Crypto::Base64Decode(this->data["user"][username]["services"][service]["iv"].asString(), iv);

	vector<byte> val;
	Crypto::Base64Decode(this->data["user"][username]["services"][service]["identifiers"].asString(), val);

	this->idcrypto.Initialize(this->key, iv);
    stringstream ids( this->idcrypto.Decrypt(val) );

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value ret(Json::arrayValue);
    string errs;
    if( ! Json::parseFromStream(builder, ids, &ret, &errs) )
    {
        throw std::runtime_error(errs);
    }

	return ret;
}

void
CryptoStorage::EncryptIdentifiers(const string& username, const string& service, const Json::Value& val)
{
	// Generate and save new IV
	vector<byte> iv(AES::BLOCKSIZE);
	this->rnd.GenerateBlock(&iv[0], iv.size() );

	string b64iv = Crypto::Base64Encode( iv );
	this->data["user"][username]["services"][service]["iv"]=b64iv;

	this->idcrypto.Initialize(this->key, iv);
    stringstream output;
    this->writer->write(val, &output);
	string b64val = Crypto::Base64Encode(
            this->idcrypto.Encrypt( output.str() )
			);

	this->data["user"][username]["services"][service]["identifiers"] = b64val;
}

Json::Value CryptoStorage::AppDecryptIdentifiers(const string &appid)
{
	vector<byte> iv;

	Crypto::Base64Decode(this->data["system"][appid]["iv"].asString(), iv);

	vector<byte> val;
	Crypto::Base64Decode(this->data["system"][appid]["identifiers"].asString(), val);

	this->idcrypto.Initialize(this->key, iv);
    stringstream ids(this->idcrypto.Decrypt(val));

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value ret(Json::arrayValue);
    string errs;
    if( ! Json::parseFromStream(builder, ids, &ret, &errs) )
    {
        throw std::runtime_error(errs);
    }

	return ret;
}

void CryptoStorage::AppEncryptIdentifiers(const string &appid, const Json::Value &val)
{
	// Generate and save new IV
	vector<byte> iv(AES::BLOCKSIZE);
	this->rnd.GenerateBlock(&iv[0], iv.size() );

	string b64iv = Crypto::Base64Encode( iv );
	this->data["system"][appid]["iv"]=b64iv;

	this->idcrypto.Initialize(this->key, iv);

    stringstream output;
    this->writer->write( val, & output);
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
		this->data["user"].removeMember(username);
	}
	else
	{
		throw std::runtime_error("User not found");
	}
	this->Write();
}
