#ifndef SECOP_CRYPTO_H
#define SECOP_CRYPTO_H

#include <string>
#include <vector>

#include <crypto++/config.h>
#include <crypto++/cryptlib.h>
#include <crypto++/aes.h>
#include <crypto++/osrng.h>
#include <crypto++/modes.h>
#include <crypto++/base64.h>

using namespace CryptoPP;
using namespace std;

template<typename T>
using SecVector = vector<T, AllocatorWithCleanup<T>>;

template<typename T>
using SecBasicString = basic_string<T, char_traits<T>, AllocatorWithCleanup<T>>;

typedef SecBasicString<char> SecString;

class Crypto {
public:
	Crypto();
	Crypto(const SecVector<byte>& key, const vector<byte>& iv=Crypto::defaultiv);

	void Initialize(const SecVector<byte>& key, const vector<byte>& iv=Crypto::defaultiv);

	string Encrypt(const string& s);
	void Encrypt(const vector<byte>& in, vector<byte>& out);
	string Decrypt(const string& s);
	void Decrypt(const vector<byte>& in, vector<byte>& out);
	string Decrypt(const vector<byte>& in);

	static string Base64Encode(const string& s);
	static string Base64Encode(const vector<byte>& in);

	static string Base64Decode(const string& s);
	static void Base64Decode(const string& s, vector<byte>& out);
	static void Base64Decode(const string& s, SecVector<byte>& out);

	static SecVector<byte> PBKDF2(
			const SecString& passwd, size_t keylength,
			const vector<byte>& salt=Crypto::defaultsalt, unsigned int iter=5000);

	static void SetDefaultIV(const vector<byte>& iv);
	static void SetDefaultSalt(const vector<byte>& salt);


	virtual ~Crypto();
private:

	SecVector<byte> key;
	vector<byte> iv;

	static vector<byte> defaultiv;
	static vector<byte> defaultsalt;

	CBC_Mode< AES >::Encryption e;
	CBC_Mode< AES >::Decryption d;
};

#endif
