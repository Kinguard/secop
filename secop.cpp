#include <iostream>
#include <fstream>
#include <functional>

#include <libutils/Socket.h>
#include <libutils/NetServer.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <libutils/ArgParser.h>
#include <libutils/Application.h>

#include <json/json.h>

#include <unistd.h>

#include "SecopServer.h"
#include "Crypto.h"
#include "CryptoStorage.h"


using namespace std;
using namespace CryptoPP;
using namespace Utils;
using namespace Utils::Net;
using namespace std::placeholders;


class SecopApp: public DaemonApplication
{
public:
	/* Should perhaps change user/group to secop */
	SecopApp():DaemonApplication("secop","/var/run", "root", "root")
	{

	}

	virtual void Startup()
	{
		logg << Logger::Debug << "Starting up"<<lend;

		Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&SecopApp::SigTerm, this, _1) );
		Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&SecopApp::SigTerm, this, _1) );
		Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&SecopApp::SigHup, this, _1) );

		unlink(SOCKPATH);

	}

	virtual void Main()
	{
		this->secop = SecopServerPtr( new SecopServer( SOCKPATH, DBPATH) );

		chmod( SOCKPATH, 0666);

		this->secop->Run();
	}

	virtual void ShutDown()
	{
		unlink(SOCKPATH);
		logg << Logger::Debug << "Shutting down"<<lend;
	}

	void SigTerm(int signo)
	{
		logg << Logger::Info << "Got sigterm initiate shutdown"<<lend;
		this->secop->ShutDown();
	}

	void SigHup(int signo)
	{

	}

	virtual ~SecopApp()
	{

	}
private:
	SecopServerPtr secop;
};

int main(int argc, char** argv)
{
	logg.SetLevel(Logger::Debug);

	int ret;
	try
	{
		SecopApp app;

		ret = app.Start( argc, argv);
	}
	catch(std::runtime_error& err)
	{
		logg << Logger::Error << "Caught runtime exception " << err.what() << lend;
	}

	return ret;

}
