/*
 * SecopServer.h
 *
 *  Created on: Oct 22, 2013
 *      Author: tor
 */

#ifndef SECOPSERVER_H_
#define SECOPSERVER_H_

#include <memory>
#include <string>
#include <map>

#include <libutils/NetServer.h>
#include <libutils/Mutex.h>

#include <nlohmann/json.hpp>

#include "CryptoStorage.h"

#include "Config.h"

using namespace std;
using namespace Utils::Net;

using json = nlohmann::json;

#define API_VERSION 1.0

/*
 * Bit pattern for states
 *
 * Used for defining which state an action can
 * be executed in.
 *
 */
#define UNINITIALIZED	0x01
#define INITIALIZED		0x02
#define AUTHENTICATED	0x04

/*
 * Bit patterns for argument checks
 * (A bit uggly but effective)
 */
#define CHK_API	0x01
#define CHK_TID	0x02
#define CHK_USR	0x04
#define CHK_SRV	0x08
#define CHK_APPID 0x10
#define CHK_GRP 0x20
#define CHK_MEM 0x40
#define CHK_PWD 0x80

class SecopServer : public Utils::Net::NetServer
{
public:

	SecopServer (const string& socketpath, string  dbpath);

	virtual void Dispatch(SocketPtr con);

	virtual	~SecopServer ();
protected:
	void ProcessOneCommand(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void SendReply(UnixStreamClientSocketPtr& client, json& cmd);

	void DoInitialize(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoStatus(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAuthenticate(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoCreateUser(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoRemoveUser(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoUpdatePassword(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGetUsers(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGetUserGroups(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoAddAttribute(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoRemoveAttribute(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGetAttributes(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGetAttribute(UnixStreamClientSocketPtr& client, json& cmd, json& session);


	void DoGetServices(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAddService(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoRemoveService(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoGetACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAddACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoRemoveACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoHasACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoGetIdentifiers(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAddIdentifier(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoRemoveIdentifier(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoGroupAdd(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGroupsGet(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGroupAddMember(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGroupRemoveMember(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGroupGetMembers(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGroupRemove(UnixStreamClientSocketPtr& client, json& cmd, json& session);


	void DoCreateAppID(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoGetAppIDs(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoRemoveAppID(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoAppGetIdentifiers(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAppAddIdentifier(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAppRemoveIdentifier(UnixStreamClientSocketPtr& client, json& cmd, json& session);

	void DoAppAddACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAppGetACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAppRemoveACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);
	void DoAppHasACL(UnixStreamClientSocketPtr& client, json& cmd, json& session);

private:
	bool CheckArguments(UnixStreamClientSocketPtr& client, int what,const json& cmd);
	static bool CheckAPIVersion(const json& cmd);
	static bool CheckTID(const json& cmd);
	static bool CheckUsername(const json& cmd);
	static bool CheckPassword(const json &cmd);
	static bool CheckService(const json& cmd);
	static bool CheckAppID(const json &cmd);
	static bool CheckGroup(const json &cmd);
	static bool CheckMember(const json &cmd);

	bool IsAdmin(const string& user);
	bool AdminOrAllowed(const string& user, const string& policy);

	void SendErrorMessage(UnixStreamClientSocketPtr& client, const json& cmd, int errcode, const string& msg);
	void SendOK(UnixStreamClientSocketPtr& client, const json& cmd, const json& val = json());

	vector<string> GetUserGroups(const string& user);

	Utils::Mutex biglock;
	void HandleClient(UnixStreamClientSocketPtr client);
	static void* ClientThread(void* obj);

	unsigned char state;
	CryptoStoragePtr store;
	string dbpath;

	typedef void (SecopServer::*Action)(UnixStreamClientSocketPtr&, json&, json&);
	map<string,pair<unsigned char, Action>> actions;
};

typedef std::shared_ptr<SecopServer> SecopServerPtr;

#endif /* SECOPSERVER_H_ */
