#include "stdafx.h"
#include "resource.h"

_NT_BEGIN

#include "store.h"
#include "Key.h"
#include "WebKey.h"
#include "msg.h"

template <typename T>
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
}

extern volatile const UCHAR guz;

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PBYTE pb, _In_ ULONG cb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType, pb, cb,
		CRYPT_DECODE_ALLOC_FLAG |
		CRYPT_DECODE_NOCOPY_FLAG |
		CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG |
		CRYPT_DECODE_SHARE_OID_STRING_FLAG,
		0, ppv, pcb ? pcb : &cb) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_DATA_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

ULONG GetRid(PSID Sid)
{
	return *RtlSubAuthoritySid(Sid, *RtlSubAuthorityCountSid(Sid) - 1);
}

PBYTE reverse_memcpy(PBYTE Destination, const BYTE* Source, size_t Length)
{
	if (Length)
	{
		Source += Length;
		do
		{
			*Destination++ = *--Source;
		} while (--Length);
	}

	return Destination;
}

#define RPID L"www.rsa.com"

HRESULT DisplayStore(HWND hwndDlg, HCERTSTORE hStore);

BOOL IsKeyExist(HWND hwnd, PSID Sid)
{
	BYTE buf[0x200];

	PBYTE pbId, pbKey;
	ULONG cbId, cbKey;

	if (S_OK == GetFKData(GetRid(Sid), buf, sizeof(buf), &pbId, &cbId, &pbKey, &cbKey))
	{
		return IDYES != ShowErrorBox(hwnd, STATUS_OBJECT_NAME_EXISTS, L"Overwrite Existing Key ?", MB_YESNO|MB_ICONQUESTION);
	}
	return FALSE;
}

HRESULT MakeCredential(HWND hwnd, PSID UserSid, PCWSTR pwszName, PCWSTR pwszRpId = RPID)
{
	if (IsKeyExist(hwnd, UserSid))
	{
		return ERROR_CANCELLED;
	}

	UCHAR sha256[SHA256_HASH_SIZE], ClientData[2 * SHA256_HASH_SIZE + 1];
	ULONG cbHash = sizeof(sha256), cch = _countof(ClientData);

	if (0 > BCryptGenRandom(0, sha256, sizeof(sha256), BCRYPT_USE_SYSTEM_PREFERRED_RNG) ||
		!CryptBinaryToStringA(sha256, sizeof(sha256), CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, (PSTR)ClientData, &cch) ||
		!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, ClientData, cch, sha256, &cbHash) ||
		sizeof(sha256) != cbHash)
	{
		return E_FAIL;
	}

	WEBAUTHN_RP_ENTITY_INFORMATION RpInformation = {
		WEBAUTHN_API_VERSION_1,
		pwszRpId,
		L"Friendly name of the Relying Party"
	};

	WEBAUTHN_USER_ENTITY_INFORMATION UserInformation = {
		WEBAUTHN_API_VERSION_1,
		RtlLengthSid(UserSid), (PBYTE)UserSid,
		pwszName,
		0,
		pwszName
	};

	WEBAUTHN_COSE_CREDENTIAL_PARAMETER PubKeyCredParam = {
		WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
		WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
		WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256
	};

	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS PubKeyCredParams = {
		1, &PubKeyCredParam
	};

	WEBAUTHN_CLIENT_DATA WebAuthNClientData = {
		WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, cch, ClientData, WEBAUTHN_HASH_ALGORITHM_SHA_256
	};

	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS WebAuthNMakeCredentialOptions = {
		WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
		60 * 1000 * 60 * 3, {}, {}, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, FALSE/*bRequireResidentKey*/,
		WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,//WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY //,
		WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
	};

	PWEBAUTHN_CREDENTIAL_ATTESTATION pWebAuthNCredentialAttestation;

	HRESULT hr = WebAuthNAuthenticatorMakeCredential(hwnd, &RpInformation, &UserInformation, &PubKeyCredParams,
		&WebAuthNClientData, &WebAuthNMakeCredentialOptions, &pWebAuthNCredentialAttestation);

	if (S_OK == hr)
	{
		void* pAAGuid;
		PBYTE pbPubKey;
		ULONG cbPubKey;

		ULONG cbAuthenticatorData = pWebAuthNCredentialAttestation->cbAuthenticatorData;
		PBYTE pbAuthenticatorData = pWebAuthNCredentialAttestation->pbAuthenticatorData;

		BOOL bECC;

		if (pWebAuthNCredentialAttestation->cbCredentialId <= 1024 &&
			0 <= CalcHash(pbAuthenticatorData, cbAuthenticatorData, sha256) &&
			GetPublicKey((WEBAUTHN_AUTHENTICATOR_DATA*)pbAuthenticatorData,
				cbAuthenticatorData, &pbPubKey, &cbPubKey, &pAAGuid, &bECC))
		{
			if (WEBAUTHN_ATTESTATION_DECODE_COMMON == pWebAuthNCredentialAttestation->dwAttestationDecodeType)
			{
				PWEBAUTHN_COMMON_ATTESTATION att = (PWEBAUTHN_COMMON_ATTESTATION)pWebAuthNCredentialAttestation->pvAttestationDecode;
				PCERT_ECC_SIGNATURE peccsign;

				if (0 <= (hr = Decode(X509_ECC_SIGNATURE, att->pbSignature, att->cbSignature, &peccsign)))
				{
					ULONG cbSig = peccsign->r.cbData + peccsign->s.cbData;
					PBYTE pbSig = (PBYTE)alloca(cbSig);

					reverse_memcpy(reverse_memcpy(pbSig,
						peccsign->r.pbData, peccsign->r.cbData),
						peccsign->s.pbData, peccsign->s.cbData);

					LocalFree(peccsign);

					BOOL attestnCertOk = FALSE;
					BCRYPT_KEY_HANDLE hKey;

					if (DWORD cX5c = att->cX5c)
					{
						PWEBAUTHN_X5C pX5c = att->pX5c;

						HCERTSTORE hStore = HR(hr, CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0, 0, 0, 0));
						PCCERT_CONTEXT pCertContext;

						do
						{
							if (hStore)
							{
								hr = BOOL_TO_ERROR(CertAddEncodedCertificateToStore(hStore, X509_ASN_ENCODING,
									pX5c->pbData, pX5c->cbData, CERT_STORE_ADD_NEW, &pCertContext));
							}
							else
							{
								pCertContext = HR(hr, CertCreateCertificateContext(
									X509_ASN_ENCODING, pX5c->pbData, pX5c->cbData));
							}

							if (NOERROR == hr && !attestnCertOk)
							{
								if (HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
									&pCertContext->pCertInfo->SubjectPublicKeyInfo, 0, 0, &hKey)))
								{
									hr = BCryptVerifySignature(hKey, 0, sha256, sizeof(sha256), pbSig, cbSig, 0);

									BCryptDestroyKey(hKey);

									if (0 <= hr)
									{
										if (PCERT_EXTENSION Extension = CertFindExtension(
											"1.3.6.1.4.1.45724.1.1.4", // id-fido-gen-ce-aaguid
											pCertContext->pCertInfo->cExtension,
											pCertContext->pCertInfo->rgExtension))
										{
											PDATA_BLOB pdb;
											if (0 <= Decode(X509_OCTET_STRING, &Extension->Value, &pdb))
											{
												attestnCertOk = sizeof(GUID) == pdb->cbData &&
													!memcmp(pAAGuid, pdb->pbData, sizeof(GUID));
												LocalFree(pdb);
											}
										}
									}
								}
								CertFreeCertificateContext(pCertContext);
							}

						} while (pX5c++, --cX5c);//!attestnCertOk &&

						if (hStore)
						{
							DisplayStore(hwnd, hStore);
							CertCloseStore(hStore, 0);
						}
					}
					else
					{
						// If x5c is not present, self attestation is in use.
						// https://w3c.github.io/webauthn/#self-attestation

						if (0 <= (hr = ImportKey(&hKey, pbPubKey, cbPubKey)))
						{
							attestnCertOk = (S_OK == (hr = BCryptVerifySignature(hKey, 0, sha256, sizeof(sha256), pbSig, cbSig, 0)));
							BCryptDestroyKey(hKey);
						}
					}

					if (attestnCertOk)
					{
						hr = RegisterFK(GetRid(UserSid),
							pWebAuthNCredentialAttestation->pbCredentialId,
							pWebAuthNCredentialAttestation->cbCredentialId,
							pbPubKey, cbPubKey);
					}
				}
			}
		}

		WebAuthNFreeCredentialAttestation(pWebAuthNCredentialAttestation);
	}
	else
	{
		WebAuthNGetErrorName(hr);
		WebAuthNGetW3CExceptionDOMError(hr);
	}

	return hr;
}

HRESULT MakeCred(HWND hwnd)
{
	HANDLE hToken;
	if (OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		PVOID stack = alloca(guz);

		union {
			PVOID buf;
			PTOKEN_USER ptu;
		};

		ULONG cb = 0, rcb = sizeof(TOKEN_USER) + SECURITY_SID_SIZE(2 + SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT);

		NTSTATUS status;
		do
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryInformationToken(hToken, TokenUser, buf, cb, &rcb);

		} while (STATUS_BUFFER_TOO_SMALL == status);

		NtClose(hToken);

		if (0 <= status)
		{
			OBJECT_ATTRIBUTES oa = { sizeof(oa) };
			LSA_HANDLE hPolicy;
			if (0 <= (status = LsaOpenPolicy(0, &oa, POLICY_LOOKUP_NAMES, &hPolicy)))
			{
				PWSTR name = 0;
				PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;
				PLSA_TRANSLATED_NAME Names = 0;

				if (0 <= (status = LsaLookupSids2(hPolicy, 0, 1, &ptu->User.Sid, &ReferencedDomains, &Names)))
				{
					status = STATUS_INTERNAL_ERROR;

					UNICODE_STRING z = {};
					PCUNICODE_STRING DomainName = &z;
					ULONG DomainIndex = Names->DomainIndex;
					if (DomainIndex < ReferencedDomains->Entries)
					{
						DomainName = &ReferencedDomains->Domains[DomainIndex].Name;
					}

					LONG cch = 0;
					while (0 < (cch = _snwprintf(name, cch, L"%wZ\\%wZ", DomainName, &Names->Name)))
					{
						if (name)
						{
							status = STATUS_SUCCESS;
							break;
						}

						name = (PWSTR)alloca(++cch * sizeof(WCHAR));
					}
				}

				LsaFreeMemory(Names);
				LsaFreeMemory(ReferencedDomains);
				LsaClose(hPolicy);

				if (0 <= status)
				{
					return MakeCredential(hwnd, ptu->User.Sid, name);
				}
			}
		}

		return status;
	}

	return RtlGetLastNtStatus();
}

HRESULT GetAssertion(HWND hwnd, ULONG Rid, PCWSTR pwszRpId = RPID)
{
	UCHAR sha256[SHA256_HASH_SIZE], ClientData[2 * SHA256_HASH_SIZE + 1];
	ULONG cbHash = sizeof(sha256), cch = _countof(ClientData);

	if (0 > BCryptGenRandom(0, sha256, sizeof(sha256), BCRYPT_USE_SYSTEM_PREFERRED_RNG) ||
		!CryptBinaryToStringA(sha256, sizeof(sha256), CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, (PSTR)ClientData, &cch) ||
		!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, ClientData, cch, sha256, &cbHash) ||
		sizeof(sha256) != cbHash)
	{
		return E_FAIL;
	}

	WEBAUTHN_CLIENT_DATA WebAuthNClientData{
		WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, cch, ClientData, WEBAUTHN_HASH_ALGORITHM_SHA_256
	};

	WEBAUTHN_CREDENTIAL Credentials = {
		WEBAUTHN_CREDENTIAL_CURRENT_VERSION, 0, 0, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
	};

	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS WebAuthNGetAssertionOptions = {
		WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
		60000, { 1, &Credentials }, {},
		WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
		WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED//WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY //
	};

	BYTE buf[0x200];

	PBYTE pbKey;
	ULONG cbKey;

	HRESULT hr = GetFKData(Rid, buf, sizeof(buf), &Credentials.pbId, &Credentials.cbId, &pbKey, &cbKey);

	if (0 <= hr)
	{
		BCRYPT_KEY_HANDLE hKey;

		if (0 <= (hr = ImportKey(&hKey, pbKey, cbKey)))
		{
			PWEBAUTHN_ASSERTION pWebAuthNAssertion;

			if (S_OK == (hr = WebAuthNAuthenticatorGetAssertion(hwnd, pwszRpId, &WebAuthNClientData,
				&WebAuthNGetAssertionOptions, &pWebAuthNAssertion)))
			{
				if (0 <= (hr = CalcHash(
					pWebAuthNAssertion->pbAuthenticatorData,
					pWebAuthNAssertion->cbAuthenticatorData, sha256)))
				{
					PCERT_ECC_SIGNATURE peccsign;

					if (0 <= (hr = Decode(X509_ECC_SIGNATURE,
						pWebAuthNAssertion->pbSignature, pWebAuthNAssertion->cbSignature, &peccsign)))
					{
						ULONG cbSig = peccsign->r.cbData + peccsign->s.cbData;
						PBYTE pbSig = (PBYTE)alloca(cbSig);

						reverse_memcpy(reverse_memcpy(pbSig,
							peccsign->r.pbData, peccsign->r.cbData),
							peccsign->s.pbData, peccsign->s.cbData);

						LocalFree(peccsign);

						hr = BCryptVerifySignature(hKey, 0, sha256, sizeof(sha256), pbSig, cbSig, 0);
					}
				}

				WebAuthNFreeAssertion(pWebAuthNAssertion);
			}
			else
			{
				WebAuthNGetErrorName(hr);
				WebAuthNGetW3CExceptionDOMError(hr);
			}

			BCryptDestroyKey(hKey);
		}
	}

	return hr;
}

NTSTATUS GetAssertion(HWND hwnd)
{
	HANDLE hToken;
	NTSTATUS status;
	if (OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		PVOID stack = alloca(guz);

		union {
			PVOID buf;
			PTOKEN_USER ptu;
		};

		ULONG cb = 0, rcb = sizeof(TOKEN_USER) + SECURITY_SID_SIZE(2 + SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT);

		do
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryInformationToken(hToken, TokenUser, buf, cb, &rcb);

		} while (STATUS_BUFFER_TOO_SMALL == status);

		NtClose(hToken);

		if (0 <= status)
		{
			status = GetAssertion(hwnd, GetRid(ptu->User.Sid));
		}
	}
	else
	{
		status = RtlGetLastNtStatus();
	}

	return status;
}

INT_PTR CALLBACK DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static const ULONG _S_cx[] = { SM_CXSMICON, SM_CXICON };
	static const ULONG _S_cy[] = { SM_CYSMICON, SM_CYICON };
	static const ULONG _S_it[] = { ICON_SMALL, ICON_BIG };

	switch (uMsg)
	{
	case WM_COMMAND:
		switch (wParam)
		{
		case IDYES:
			ShowErrorBox(hwnd, GetAssertion(hwnd), L"GetAssertion");
			break;
		case IDNO:
			ShowErrorBox(hwnd, MakeCred(hwnd), L"MakeCredential");
			break;
		case IDCANCEL:
			EndDialog(hwnd, lParam);
			break;
		}
		break;

	case WM_DESTROY:
		if (HICON* phi = (HICON*)GetWindowLongPtrW(hwnd, DWLP_USER))
		{
			uMsg = _countof(_S_it);
			do 
			{
				if (HICON hi = *phi++)
				{
					DestroyIcon(hi);
				}
			} while (--uMsg);
		}
		break;

	case WM_INITDIALOG:
		SetWindowLongPtrW(hwnd, DWLP_USER, lParam);
		uMsg = _countof(_S_it) - 1;
		HICON hi, * phi = reinterpret_cast<HICON*>(lParam);

		do 
		{
			if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDI_MAIN_ICO),
				GetSystemMetrics(_S_cx[uMsg]), GetSystemMetrics(_S_cy[uMsg]), &hi))
			{
				*phi++ = hi;
				SendMessageW(hwnd, WM_SETICON, _S_it[uMsg], (LPARAM)hi);
			}
		} while (uMsg--);

		break;
	}

	return 0;
}

void WINAPI ep(void*)
{
	HICON hi[2] = {};
	ExitProcess((UINT)DialogBoxParamW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, DlgProc, (LPARAM)hi));
}

_NT_END