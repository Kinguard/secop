/*
 * CryptoStorage.h
 *
 *  Created on: Oct 22, 2013
 *      Author: tor
 */

#ifndef CRYPTOSTORAGE_H_
#define CRYPTOSTORAGE_H_

#include <string>
#include <vector>
#include <memory>

#include <nlohmann/json.hpp>

#include "Crypto.h"

using namespace std;
using json = nlohmann::json;

class CryptoStorage
{
public:
	CryptoStorage (string  path, const SecString& pwd, bool undertest=false);
	CryptoStorage (string  path, const SecVector<byte>& key, bool undertest=false);

	bool HasAppID(const string& appid);
	void CreateAppID(const string& appid);
	void DeleteAppID(const string& appid);
	vector<string> GetAppIDs(void);

	bool HasGroup(const string& group);
	void GroupAdd(const string& group);
	vector<string> GroupsGet( );
	void GroupAddMember( const string& group, const string& member);
	void GroupRemoveMember( const string& group, const string& member);
	vector<string> GroupGetMembers( const string& group);
	void GroupRemove( const string& group);
	bool GroupHasMember( const string& group, const string& member);

	void AppAddIdentifier(const string& appid, const json& val);
	json AppGetIdentifiers(const string& appid);
	void AppUpdateIdentifiers(const string& appid, const json& val);

	void AppAddAcl(const string& appid, const string& entity);
	bool AppHasACL(const string& appid, const string& entity);
	bool AppACLEmpty(const string& appid);
	vector<string> AppGetACL(const string& appid);
	void AppRemoveAcl(const string& appid, const string& entity);

	bool HasUser(const string& user);
	void CreateUser(const string& username, const string& displayname="");
	void DeleteUser(const string& username);
	vector<string> GetUsers(void);

	bool HasAttribute( const string& username, const string& attributename);
	vector<string> GetAttributes(const string& username);
	string GetAttribute( const string& username, const string& attributename);
	void AddAttribute(const string& username, const string& attributename, const string& attributevalue);
	void RemoveAttribute(const string& username, const string& attributename);

	bool HasService( const string& user, const string& service);
	void AddService(const string& username, const string& servicename);
	void RemoveService( const string& username, const string& servicename);
	vector<string> GetServices(const string& username);

	void AddAcl(const string& username, const string& service, const string& entity);
    void RemoveAcl(const string& username, const string& service, const string& entity);
	bool ACLEmpty(const string& username, const string& service);
	bool HasACL(const string& username, const string& service, const string& entity);
	vector<string> GetACL(const string& username, const string& service);

	void AddIdentifier(const string& username, const string& service, const json& val);
	json GetIdentifiers(const string& username, const string& service);
	void UpdateIdentifiers(const string& username, const string& service, const json& val);

	void CreateApplication(const string& appname);

	virtual	~CryptoStorage ();
private:
	void Initialize();
	void New();
	void Read();
	void Write();

	json DecryptIdentifiers(const string& username, const string& service);
	void EncryptIdentifiers(const string& username, const string& service, const json& val);

	json AppDecryptIdentifiers(const string& appid);
	void AppEncryptIdentifiers(const string& appid, const json& val);


	bool hasApplication(const string& app);
private:
	const double version;
	double readversion;
	std::string path;
	bool undertest;

	SecVector<byte> key;
	Crypto filecrypto;
	Crypto idcrypto;
	AutoSeededRandomPool rnd;

	json data;

	static const vector<byte> iv;
};

typedef std::shared_ptr<CryptoStorage> CryptoStoragePtr;

#endif /* CRYPTOSTORAGE_H_ */
