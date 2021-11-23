#include <iostream>
#include <fstream>
#include <functional>

#include <libutils/Socket.h>
#include <libutils/NetServer.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <libutils/ArgParser.h>
#include <libutils/Application.h>

#include <nlohmann/json.hpp>

#include <unistd.h>
#include <syslog.h>

#include "SecopServer.h"
#include "Crypto.h"
#include "CryptoStorage.h"


using namespace std;
using namespace CryptoPP;
using namespace Utils;
using namespace Utils::Net;
using namespace std::placeholders;

using json = nlohmann::json;

class SecopApp: public DaemonApplication
{
public:
	/* Should perhaps change user/group to secop */
	SecopApp():DaemonApplication("secop","/run", "root", "root")
	{

	}

	void Startup() override
	{
		// Divert logger to syslog
		openlog( "secop", LOG_PERROR, LOG_DAEMON);
		logg.SetOutputter( [](const string& msg){ syslog(LOG_INFO, "%s",msg.c_str());});
		logg.SetLogName("");

		logg << Logger::Debug << "Starting up"<<lend;

		Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&SecopApp::SigTerm, this, _1) );
		Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&SecopApp::SigTerm, this, _1) );
		Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&SecopApp::SigHup, this, _1) );

		unlink(SOCKPATH);

		this->options.AddOption( Option('D', "debug", Option::ArgNone,"0","Debug logging") );
	}

	void Main() override
	{
		if( this->options["debug"] == "1" )
		{
			logg << Logger::Info << "Increase logging to debug level "<<lend;
			logg.SetLevel(Logger::Debug);
		}

		this->secop = SecopServerPtr( new SecopServer( SOCKPATH, DBPATH) );

		chmod( SOCKPATH, 0666);

		this->secop->Run();
	}

	void ShutDown() override
	{
		unlink(SOCKPATH);
		logg << Logger::Info << "Shutting down"<<lend;
	}

	void SigTerm(int signo)
	{
		(void) signo;
		logg << Logger::Info << "Got sigterm initiate shutdown"<<lend;
		this->secop->ShutDown();
	}

	void SigHup(int signo)
	{
		(void) signo;
		logg << Logger::Debug << "Got sighup" << lend;
	}

private:
	SecopServerPtr secop;
};

int main(int argc, char** argv)
{
	logg.SetLevel(Logger::Info);

	int ret=0;
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
