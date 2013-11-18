#include <iostream>

#include <libutils/Socket.h>
#include <libutils/NetServer.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>

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

	unlink("/tmp/secop");
	secop = SecopServerPtr( new SecopServer("/tmp/secop","/tmp/secop.db") );

	struct sigaction action;

	action.sa_handler = sighandler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);

	sigaction(SIGTERM, &action, nullptr);
	sigaction(SIGHUP, &action, nullptr);

	secop->Run();

	secop.reset();

	logg << Logger::Debug << "Kryptoapp shutting down"<<lend;
	return 0;
}
