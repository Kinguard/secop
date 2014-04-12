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

#include "json/json.h"
#include "CryptoStorage.h"

using namespace std;
using namespace Utils::Net;

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

class SecopServer : public Utils::Net::NetServer
{
public:

	SecopServer (const string& socketpath, const string& dbpath);

	virtual void Dispatch(SocketPtr con);

	virtual	~SecopServer ();
protected:
	void ProcessOneCommand(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void SendReply(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	void DoInitialize(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoStatus(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoAuthenticate(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);

	void DoCreateUser(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoRemoveUser(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoGetUsers(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);

	void DoGetServices(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoAddService(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoRemoveService(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);

	void DoGetACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoAddACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoRemoveACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoHasACL(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);

	void DoGetIdentifiers(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoAddIdentifier(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);
	void DoRemoveIdentifier(UnixStreamClientSocketPtr& client, Json::Value& cmd, Json::Value& session);

private:
	bool CheckArguments(UnixStreamClientSocketPtr& client, int what,const Json::Value& cmd);
	static bool CheckAPIVersion(const Json::Value& cmd);
	static bool CheckTID(const Json::Value& cmd);
	static bool CheckUsername(const Json::Value& cmd);
	static bool CheckService(const Json::Value& cmd);

	void SendErrorMessage(UnixStreamClientSocketPtr& client, const Json::Value& cmd, int errcode, const string& msg);
	void SendOK(UnixStreamClientSocketPtr& client, const Json::Value& cmd, const Json::Value& val = Json::nullValue);

	unsigned char state;
	CryptoStoragePtr store;
	string dbpath;
	Json::FastWriter writer;
	Json::Reader reader;
	typedef void (SecopServer::*Action)(UnixStreamClientSocketPtr&, Json::Value&, Json::Value&);
	map<string,pair<unsigned char, Action>> actions;
};

typedef std::shared_ptr<SecopServer> SecopServerPtr;

#endif /* SECOPSERVER_H_ */
