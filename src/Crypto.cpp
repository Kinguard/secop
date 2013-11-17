#include "Crypto.h"

#include <algorithm>

#include <libutils/Logger.h>

#include <crypto++/pwdbased.h>
#include <crypto++/sha.h>


using namespace std;
using namespace Utils;

vector<byte> Crypto::defaultiv;
vector<byte> Crypto::defaultsalt;

Crypto::Crypto(const SecVector<byte>& key, const vector<byte>& iv)
{
	this->Initialize(key, iv);
}

Crypto::Crypto ()
{
}

void
Crypto::Initialize ( const SecVector<byte>& key, const vector<byte>& iv )
{
	this->key = key;
	this->iv = iv;
#if 0
	this->e.SetKeyWithIV( &key[0], key.size(), &iv[0] );
	this->d.SetKeyWithIV( &key[0], key.size(), &iv[0] );
#endif
}

string Crypto::Encrypt(const string& plain)
{

	this->e.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string ciphered;

	StringSource s(plain, true,
		new StreamTransformationFilter( this->e,
			new StringSink(ciphered)
		)
	);

	return ciphered;
}
void

Crypto::Encrypt ( const vector<byte>& in, vector<byte>& out )
{

	this->e.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string enc;
	StringSource s( &in[0], in.size(), true,
			new StreamTransformationFilter( this->e,
					new StringSink(enc)
			)
		);

	out.resize(enc.size());
	copy(enc.begin(), enc.end(), out.begin() );
}

string Crypto::Decrypt(const string& encoded)
{
	this->d.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string plain;
	logg << Logger::Debug << "Decode string size "<<encoded.size()<<lend;
	StringSource s(encoded, true,
		new StreamTransformationFilter(this->d,
			new StringSink(plain)
		)
	);

	return plain;
}

void
Crypto::Decrypt ( const vector<byte>& in, vector<byte>& out )
{
	//Todo: investigate if the copy could be avoided.
	string plain = this->Decrypt(in);

	out.resize(plain.size());
	copy(plain.begin(), plain.end(), out.begin() );
}

string
Crypto::Decrypt ( const vector<byte>& in )
{
	this->d.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string plain;
	StringSource s( &in[0], in.size(), true,
			new StreamTransformationFilter( this->d,
					new StringSink(plain)
					)
			);
	return plain;
}


string Crypto::Base64Encode(const string& s)
{
	string encoded;

	StringSource ss( s, true,
			new Base64Encoder(
				new StringSink( encoded ), false
				)
		);

	return encoded;
}

string
Crypto::Base64Encode ( const vector<byte>& in )
{
	string encoded;
	ArraySource(&in[0], in.size(), true,
			new Base64Encoder(
				new StringSink( encoded ), false
				)
			);
	return encoded;
}

string Crypto::Base64Decode(const string& s)
{
	string decoded;

	StringSource ss( s, true,
			new Base64Decoder(
				new StringSink( decoded )
				)
		);

	return decoded;
}

void
Crypto::Base64Decode ( const string& s, vector<byte>& out )
{
	string decoded = Crypto::Base64Decode(s);
	out.resize( decoded.size() );
	std::copy(decoded.begin(), decoded.end(), out.begin() );
}

void
Crypto::Base64Decode ( const string& s, SecVector<byte>& out )
{
	//TODO: the string here is not allocated with wiped allocator
	string decoded = Crypto::Base64Decode(s);
	out.resize( decoded.size() );
	std::copy(decoded.begin(), decoded.end(), out.begin() );
}


SecVector<byte>
Crypto::PBKDF2 ( const SecString& passwd, size_t keylength, const vector<byte>& salt,
		unsigned int iter )
{
	SecVector<byte> ret(keylength);

	PKCS5_PBKDF2_HMAC<SHA512> df;

	int iters_done = df.DeriveKey(
		&ret[0], ret.size(),
		0,
		(const byte*)passwd.c_str(), passwd.length(),
		&salt[0],salt.size(),
		iter);

	return ret;
}

void
Crypto::SetDefaultIV ( const vector<byte>& iv )
{
	Crypto::defaultiv = iv;
}

void
Crypto::SetDefaultSalt ( const vector<byte>& salt )
{
	Crypto::defaultsalt = salt;
}


Crypto::~Crypto()
{
}
