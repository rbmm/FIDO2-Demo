#pragma once

#define SHA256_HASH_SIZE 32

struct WEBAUTHN_AUTHENTICATOR_DATA;

BOOL GetPublicKey(
	_In_ WEBAUTHN_AUTHENTICATOR_DATA* AuthData,
	_In_ ULONG cbAuthData,
	_Out_ PBYTE* ppbPubKey,
	_Out_ ULONG* pcbPubKey,
	_Out_ void** pAAGuid,
	_Out_ BOOL* pbECC);

// Verify that is a valid signature over the concatenation of authenticatorData and clientDataHash 
// using the attestation public key in attestnCert with the algorithm specified in alg.

NTSTATUS CalcHash(_In_ PBYTE pbAuthenticatorData, _In_ ULONG cbAuthenticatorData, _Inout_ PBYTE pbClientDataHash);
