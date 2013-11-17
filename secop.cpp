#include <iostream>

#include <crypto++/config.h>
#include <crypto++/cryptlib.h>
#include <crypto++/aes.h>
#include <crypto++/osrng.h>
#include <crypto++/modes.h>
#include <crypto++/base64.h>

#include <libutils/Socket.h>
#include <libutils/NetServer.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <unistd.h>

#include "SecopServer.h"
#include "Crypto.h"
#include "CryptoStorage.h"

#include "json/json.h"

using namespace std;
using namespace CryptoPP;
using namespace Utils;
using namespace Utils::Net;


int main(int argc, char** argv)
{
	logg.SetLevel(Logger::Debug);

#if 0
	AutoSeededRandomPool rnd;

	vector<byte> iv(AES::BLOCKSIZE);
	if( ! File::FileExists("/tmp/secop_iv.bin") )
	{
		rnd.GenerateBlock( &iv[0], iv.size() );
		File::WriteVector<vector<byte>>("/tmp/secop_iv.bin", iv, 0666 );
	}
	else
	{
		File::ReadVector<vector<byte>>("/tmp/secop_iv.bin", iv);
	}

	SecVector<byte> key(AES::MAX_KEYLENGTH);

	if( ! File::FileExists("/tmp/secop_key.bin") )
	{
		rnd.GenerateBlock( &key[0], key.size() );
		File::WriteVector<SecVector<byte>>("/tmp/secop_key.bin", key, 0666 );
	}
	else
	{
		File::ReadVector<SecVector<byte>>("/tmp/secop_key.bin", key);
	}

	CryptoStorage cs("/tmp/secop_db", key);

	if( ! cs.HasUser("tor" ))
	{
		cs.CreateUser("tor");
	}

	if( ! cs.HasService("tor","facebook") )
	{
		cs.AddService("tor","facebook");
	}
	cs.AddAcl("tor","facebook","google");


	Json::Value ident(Json::objectValue);
	ident["user"]="torsten";
	ident["password"]="secret2";
	ident["service"]="https://www.facebook.se";
	ident["comment"]="Ansiktsboken";

	Json::Value ids(Json::arrayValue);
	ids.append(ident);
	cs.UpdateIdentifiers("tor","facebook",ids);


	Json::Value ident1(Json::objectValue);
	ident1["user"]="torstens";
	ident1["password"]="secret";
	ident1["service"]="https://www.facebook.se";
	ident1["comment"]="Ansiktsboken!";

	cs.AddIdentifier("tor","facebook",ident1);


	//cs.DeleteUser("tor");
#endif

#if 1
	unlink("/tmp/secop");
	SecopServer s2("/tmp/secop","/tmp/secop.db");

	s2.Run();
#endif

#if 0
	Json::Value res(Json::objectValue);

	res["user"]="test";
	res["system"]="systest";

	Json::FastWriter writer;

	cout << writer.write(res)<<endl;




	Crypto c(key, key.size(),iv);
	string enced = c.Encrypt(res["user"].asString());
	cout << "Encrypted: ["<< enced  <<"]"<<endl;
	cout << "B64 encoded: ["<<Crypto::Base64Encode(enced)<<"]"<<endl;
	cout << "B64 decoded: ["<<Crypto::Base64Decode(Crypto::Base64Encode(enced))<<"]"<<endl;
	cout << "Decoded: ["<<c.Decrypt(enced)<<"]"<<endl;
#endif

	return 0;
}
