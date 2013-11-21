#include <iostream>
#include <fstream>

#include <libutils/Socket.h>
#include <libutils/NetServer.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <libutils/ArgParser.h>

#include <unistd.h>
#include <signal.h>

#include "SecopServer.h"
#include "Crypto.h"
#include "CryptoStorage.h"

#include "json/json.h"

using namespace std;
using namespace CryptoPP;
using namespace Utils;
using namespace Utils::Net;

SecopServerPtr secop;

static void sighandler(int sig)
{
	logg << Logger::Debug << "Got signal "<<sig<< lend;
	switch(sig)
	{
	case SIGHUP:
		break;
	case SIGTERM:
	case SIGINT:
		logg << Logger::Info << "Got sigterm initiate shutdown"<<lend;
		secop->ShutDown();
		break;
	default:
		break;
	}
}

int main(int argc, char** argv)
{
	logg.SetLevel(Logger::Debug);

	logg << Logger::Debug << "Kryptoapp starting up"<<lend;

	ArgParser args;

	args.AddOptions({
						Option('d',"daemonize",Option::ArgNone,"0","Daemonize application"),
						Option('p',"pidfile", Option::ArgRequired, "/var/run/secop.pid", "Path to pidfile"),
						Option('u',"user", Option::ArgRequired, "secop", "User to run as"),
						Option('g',"group", Option::ArgRequired, "secop", "Group to run as"),
				});

	if( ! args.Parse(argc,argv) )
	{
		logg << Logger::Error << "Invalid arguments"<<lend;
		cerr << "Invalid arguments"<<endl;
		return 1;
	}

	if( args["daemonize"] == "1" )
	{
		// Daemonize
		if( daemon( 0, 0) < 0 )
		{
			logg << Logger::Error << "Failed to daemonize"<<lend;
			return 1;
		}
		logg << Logger::Info << "Daemonized"<<lend;
		ofstream of(args["pidfile"]);
		of<<getpid()<<endl;
		of.close();
	}

	unlink("/tmp/secop");
	secop = SecopServerPtr( new SecopServer("/tmp/secop","/tmp/secop.db") );

	struct sigaction action;

	action.sa_handler = sighandler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);

	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGHUP, &action, nullptr);

	secop->Run();

	secop.reset();

	logg << Logger::Debug << "Kryptoapp shutting down"<<lend;
	return 0;
}
