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

#include <json/json.h>

#include "Crypto.h"

using namespace std;

class CryptoStorage
{
public:
	CryptoStorage (const string& path, const SecString& pwd);
	CryptoStorage (const string& path, const SecVector<byte>& key);

	bool HasUser(const string& user);
	void CreateUser(const string& username, const string& displayname="");
	void DeleteUser(const string& username);
	vector<string> GetUsers(void);

	bool HasAttribute( const string& username, const string& attributename);
	vector<string> GetAttributes(const string& username);
	string GetAttribute( const string& username, const string& attributename);
	void AddAttribute(const string& username, const string& attributename, const string attributevalue);
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

	void AddIdentifier(const string& username, const string& service, const Json::Value& val);
	Json::Value GetIdentifiers(const string& username, const string& service);
	void UpdateIdentifiers(const string& username, const string& service, const Json::Value& val);

	void CreateApplication(const string& appname);

	virtual	~CryptoStorage ();
private:
	void Initialize();
	void New();
	void Read();
	void Write();

	Json::Value DecryptIdentifiers(const string& username, const string& service);
	void EncryptIdentifiers(const string& username, const string& service, const Json::Value& val);

	bool hasApplication(const string& app);
private:
	const double version;
	double readversion;
	std::string path;

	SecVector<byte> key;
	Crypto filecrypto;
	Crypto idcrypto;
	AutoSeededRandomPool rnd;

	Json::FastWriter writer;
	Json::Reader reader;
	Json::Value data;
};

typedef std::shared_ptr<CryptoStorage> CryptoStoragePtr;

#endif /* CRYPTOSTORAGE_H_ */
