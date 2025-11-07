#include "stdafx.h"

_NT_BEGIN

#include "cbor.h"
#include "key.h"
#include "WebKey.h"

void DumpBytes(PCSTR msg, const BYTE* pb, ULONG cb, ULONG dwFlags)
{
	PSTR psz = 0;
	ULONG cch = 0;
	while (CryptBinaryToStringA(pb, cb, dwFlags, psz, &cch))
	{
		if (psz)
		{
			if (msg) DbgPrint(msg);
			DbgPrint("%.*hs", cch, psz);
			DbgPrint("\r\n");
			break;
		}

		psz = (PSTR)alloca(cch);
	}
}

#define MAXUCHAR 0xff 

const CHAR _G_prefix[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

struct MYC : public CBOR
{
	int _M_Level;
	BOOLEAN _M_bNamed = FALSE;

	MYC(int Level = 0) : _M_Level(Level) {}

	PCSTR prefix()
	{
		if (_M_bNamed)
		{
			_M_bNamed = FALSE;
			return "";
		}
		return &_G_prefix[_countof(_G_prefix) - 1 - _M_Level];
	}

	virtual BOOL OnUint(ULONG64 i)
	{
		DbgPrint("%s%I64x\n", prefix(), i);

		return TRUE;
	}

	virtual BOOL OnInt(LONG64 i)
	{
		DbgPrint("%s-%I64x\n", prefix(), -i);
		return TRUE;
	}

	virtual BOOL OnBinary(PBYTE pb, ULONG cb)
	{
		DumpBytes(prefix(), pb, cb, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF);
		return TRUE;
	}

	virtual BOOL OnString(PCSTR psz, ULONG len)
	{
		DbgPrint("%s\"%.*s\"\n", prefix(), len, psz);
		return TRUE;
	}

	virtual BOOL BeginArray(ULONG n)
	{
		DbgPrint("%s[ // [%x]\n", prefix(), n);
		_M_Level++;
		return TRUE;
	}

	virtual BOOL BeginMap(ULONG n)
	{
		DbgPrint("%s{ // [%x]\n", prefix(), n);
		_M_Level++;
		return TRUE;
	}

	virtual BOOL OnSpec(T7 v)
	{
		PCSTR pref = prefix();
		switch (v)
		{
		case t_false:
			DbgPrint("%sfalse\n", pref);
			break;
		case t_true:
			DbgPrint("%strue\n", pref);
			break;
		case t_null:
			DbgPrint("%snull\n", pref);
			break;
		case t_undefined:
			DbgPrint("%sundefined\n", pref);
			break;
		}
		return TRUE;
	}

	virtual BOOL EndArray()
	{
		_M_Level--;
		DbgPrint("%s]\n", prefix());
		return TRUE;
	}

	virtual BOOL EndMap()
	{
		_M_Level--;
		DbgPrint("%s}\n", prefix());
		return TRUE;
	}

	virtual BOOL GetItem(PCSTRING name, ULONG /*i*/, CBOR** pp)
	{
		if (name)
		{
			if (MAXUSHORT + (ULONG_PTR)name->Buffer < 2 * MAXUSHORT)
			{
				DbgPrint("%s%d : ", prefix(), (ULONG)(ULONG_PTR)name->Buffer);
			}
			else
			{
				DbgPrint("%s\"%Z\" : ", prefix(), name);
			}

			_M_bNamed = TRUE;
		}

		*pp = this;
		return TRUE;
	}
};

struct MyGetPubKey : public CBOR, public CERT_ECC_SIGNATURE
{
	CBOR skip;
	PBYTE _M_pbModulus;
	PBYTE _M_pbExponent;
	PCWSTR _M_pszAlgId;
	ULONG _M_dwMagic;
	ULONG _M_cbModulus;
	ULONG _M_cbExponent;

	// WEBAUTHN_COSE_ALGORITHM_
	LONG _M_lAlg = 0;

	// 2	EC2 Elliptic Curve Keys
	// 3	RSA key
	enum { ktEC2 = 2, ktRSA = 3 };
	LONG _M_kType = 0;

	enum { eNone, eAlg, eKeyType, eCrv, eR, eS, eModules, eExponent } eType = eNone;

	virtual BOOL OnString(PCSTR /*psz*/, ULONG /*len*/)
	{
		return FALSE;
	}

	virtual BOOL BeginArray(ULONG /*n*/)
	{
		return FALSE;
	}

	virtual BOOL OnSpec(T7 /*v*/)
	{
		return TRUE;
	}

	virtual BOOL OnBinary(PBYTE pb, ULONG cb)
	{
		switch (eType)
		{
		case eS:
			s.pbData = pb, s.cbData = cb;
			break;
		case eR:
			r.pbData = pb, r.cbData = cb;
			break;
		case eModules:
			_M_pbModulus = pb, _M_cbModulus = cb;
			break;
		case eExponent:
			_M_pbExponent = pb, _M_cbExponent = cb;
			break;
		default: return FALSE;
		}
		return TRUE;
	}

	virtual BOOL OnUint(ULONG64 i)
	{
		if (i < MAXDWORD)
		{
			switch (eType)
			{
			case eKeyType:
				_M_kType = (ULONG)i;

				switch (i)
				{
				case ktEC2:
				case ktRSA:
					return TRUE;
				}
				break;

			case eCrv:
				switch (i)
				{
				case 1:// NIST P-256
					return WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 == _M_lAlg;
				case 2:// NIST P-384
					return WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384 == _M_lAlg;
				case 3:// NIST P-521
					return WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512 == _M_lAlg;
				}
				break;
			}

			return FALSE;
		}

		return FALSE;
	}

	virtual BOOL OnInt(LONG64 i)
	{
		switch (eType)
		{
		case eAlg:

			_M_lAlg = (LONG)i;

			switch (_M_kType)
			{
			case ktEC2:
				switch (i)
				{
				case WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256:
					_M_pszAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
					_M_dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
					return TRUE;

				case WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384:
					_M_pszAlgId = BCRYPT_ECDSA_P384_ALGORITHM;
					_M_dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
					return TRUE;

				case WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512:
					_M_pszAlgId = BCRYPT_ECDSA_P521_ALGORITHM;
					_M_dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
					return TRUE;
				}
				break;

			case ktRSA:
				switch (i)
				{
				case WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA256:
				case WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA384:
				case WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA512:

					_M_pszAlgId = BCRYPT_RSA_ALGORITHM;
					_M_dwMagic = BCRYPT_RSAPUBLIC_MAGIC;
					return TRUE;
				}
				break;
			}
		}

		return FALSE;
	}

	virtual BOOL GetItem(PCSTRING name, ULONG /*i*/, CBOR** pp)
	{
		eType = eNone;

		*pp = &skip;

		if (name)
		{
			switch ((ULONG_PTR)name->Buffer)
			{
			case 1:// kty
				eType = eKeyType;
				break;

			case 3:// alg
				eType = eAlg;
				break;

			case -1://crv or RSA modulus
				switch (_M_kType)
				{
				case ktEC2:
					eType = eCrv;
					break;
				case ktRSA:
					eType = eModules;
					break;
				default:
					return FALSE;
				}
				break;

			case -2:
				switch (_M_kType)
				{
				case ktEC2:
					eType = eR;
					break;
				case ktRSA:
					eType = eExponent;
					break;
				default:
					return FALSE;
				}
				break;

			case -3:
				switch (_M_kType)
				{
				case ktEC2:
					eType = eS;
					break;
				default:
					return FALSE;
				}
				break;
			}

			if (eType)
			{
				*pp = this;
			}
		}

		return TRUE;
	}

	NTSTATUS ImportECC(_Out_ PBYTE pb, _Out_ ULONG* pcbPubKey)
	{
		ULONG cbKey = r.cbData;

		if (cbKey != s.cbData || 0x80 < cbKey - 1)
		{
			return NTE_NO_KEY;
		}

		ULONG cb = sizeof(BCRYPT_ECCKEY_BLOB) + cbKey * 2;

		PBCRYPT_ECCKEY_BLOB ecc = (PBCRYPT_ECCKEY_BLOB)pb;

		ecc->dwMagic = _M_dwMagic;
		ecc->cbKey = cbKey;

		pb += sizeof(BCRYPT_ECCKEY_BLOB);

		memcpy((PBYTE)memcpy(pb, r.pbData, cbKey) + cbKey, s.pbData, cbKey);

		BCRYPT_KEY_HANDLE hKey;
		NTSTATUS status = ImportKey(_M_pszAlgId, BCRYPT_ECCPUBLIC_BLOB, &hKey, (PBYTE)ecc, cb);
		if (0 <= status)
		{
			BCryptDestroyKey(hKey);
			*pcbPubKey = cb;
		}

		return status;
	}

	NTSTATUS Import(_Out_ PBYTE pbPubKey, _Out_ ULONG* pcbPubKey, _Out_ BOOL* pbECC)
	{
		switch (_M_kType)
		{
		case ktRSA:
			*pbECC = FALSE;
			//todo
			break;

		case ktEC2:
			*pbECC = TRUE;
			return ImportECC(pbPubKey, pcbPubKey);
		}

		return NTE_NOT_SUPPORTED;
	}
};

void DumpCOSE_Key(PBYTE pb, ULONG cb)
{
	MYC cbr{};
	BOOL b = 0 != cbr.decode(pb, cb, &cb);
	DbgPrint("COSE_Key=%x, %x bytes left\n", b, cb);
}

#pragma pack(push, 1)
// https://w3c.github.io/webauthn/#sctn-authenticator-data
struct WEBAUTHN_AUTHENTICATOR_DATA
{
	UCHAR RpIdHash[SHA256_HASH_SIZE];// SHA-256 hash of the RP ID of credential 
	union {
		UCHAR Flags; // 0x45
		struct {
			UCHAR UP : 1; // 0x01 - user is present.
			UCHAR RFU1 : 1; // 0x02
			UCHAR UV : 1; // 0x04 - user is verified.
			UCHAR BE : 1; // 0x08 - public key credential source is backup eligible.
			UCHAR BS : 1; // 0x10 - public key credential source is currently backed up.
			UCHAR RFU2 : 1; // 0x20
			UCHAR AT : 1; // 0x40 - Attested credential data included
			UCHAR ED : 1; // 0x80 - Extension data included 
		};
	};
	ULONG SignCount; // big-endian
	GUID AAGuid; // {ee041bce-25e5-4cdb-8f86-897fd6418464}
	USHORT credentialIdLength; // big-endian.
	UCHAR credentialId[]; // encoded private key

	PUCHAR GetData()
	{
		return &credentialId[_byteswap_ushort(credentialIdLength)];
	}

	ULONG GetSize(ULONG cb)
	{
		return cb - sizeof(WEBAUTHN_AUTHENTICATOR_DATA) - _byteswap_ushort(credentialIdLength);
	}

	BOOL IsValid(ULONG cb)
	{
		return sizeof(WEBAUTHN_AUTHENTICATOR_DATA) < cb &&
			_byteswap_ushort(credentialIdLength) <= cb - sizeof(WEBAUTHN_AUTHENTICATOR_DATA) && AT;
	}
};
#pragma pack(pop)

BOOL GetPublicKey(
	_In_ WEBAUTHN_AUTHENTICATOR_DATA* AuthData,
	_In_ ULONG cbAuthData,
	_Out_ PBYTE* ppbPubKey,
	_Out_ ULONG* pcbPubKey,
	_Out_ void** pAAGuid,
	_Out_ BOOL* pbECC)
{
	if (AuthData->IsValid(cbAuthData))
	{
		*pAAGuid = &AuthData->AAGuid;

		if (cbAuthData = AuthData->GetSize(cbAuthData))
		{
			PBYTE pb = AuthData->GetData();

			DumpCOSE_Key(pb, cbAuthData);

			MyGetPubKey cbr{};
			if (cbr.decode(pb, cbAuthData, &cbAuthData))
			{
				*ppbPubKey = pb;
				return 0 <= cbr.Import(pb, pcbPubKey, pbECC);
			}
		}
	}

	return FALSE;
};

// Verify that is a valid signature over the concatenation of authenticatorData and clientDataHash 
// using the attestation public key in attestnCert with the algorithm specified in alg.

NTSTATUS CalcHash(_In_ PBYTE pbAuthenticatorData,
	_In_ ULONG cbAuthenticatorData,
	_Inout_ PBYTE pbClientDataHash)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	// we use WEBAUTHN_HASH_ALGORITHM_SHA_256

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, 0, 0)))
	{
		BCRYPT_HASH_HANDLE hHash;
		status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, 0, 0, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			// SHA256(AuthenticatorData + ClientDataHash)

			0 <= (status = BCryptHashData(hHash, pbAuthenticatorData, cbAuthenticatorData, 0)) &&
				0 <= (status = BCryptHashData(hHash, pbClientDataHash, SHA256_HASH_SIZE, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbClientDataHash, SHA256_HASH_SIZE, 0));

			BCryptDestroyHash(hHash);
		}
	}

	return status;
}

_NT_END