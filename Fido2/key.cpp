#include "stdafx.h"

_NT_BEGIN

#include "key.h"

NTSTATUS ImportKey(_In_ PCWSTR pszAlgId, _In_ PCWSTR pszBlobType, _Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE pbKey, _In_ ULONG cbKey)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, MS_PRIMITIVE_PROVIDER, 0)))
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, pszBlobType, phKey, pbKey, cbKey, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS ImportKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE pbKey, _In_ ULONG cbKey)
{
	PCWSTR pszAlgId;
	PCWSTR pszBlobType = BCRYPT_ECCPUBLIC_BLOB;

	switch (reinterpret_cast<BCRYPT_KEY_BLOB*>(pbKey)->Magic)
	{
	case BCRYPT_RSAPUBLIC_MAGIC:
		pszAlgId = BCRYPT_RSA_ALGORITHM;
		pszBlobType = BCRYPT_RSAPUBLIC_BLOB;
		break;

	case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
		pszAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
		break;

	case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
		pszAlgId = BCRYPT_ECDSA_P384_ALGORITHM;
		break;

	case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
		pszAlgId = BCRYPT_ECDSA_P521_ALGORITHM;
		break;

	default:
		return STATUS_NOT_SUPPORTED;
	}

	return ImportKey(pszAlgId, pszBlobType, phKey, pbKey, cbKey);
}

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ UCHAR** ppb, _Out_ ULONG* pcb)
{
	UNICODE_STRING ObjectName;

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb,
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			FILE_STANDARD_INFORMATION fsi;

			if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
			{
				if (PUCHAR pb = new UCHAR[fsi.EndOfFile.LowPart])
				{
					if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
					{
						delete[] pb;
					}
					else
					{
						*ppb = pb;
						*pcb = (ULONG)iosb.Information;
					}
				}
			}

			NtClose(hFile);
		}
	}

	return status;
}

NTSTATUS ImportKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszFile)
{
	PBYTE pbKey;
	ULONG cbKey;
	NTSTATUS hr = ReadFromFile(pszFile, &pbKey, &cbKey);

	if (0 <= hr)
	{
		hr = ImportKey(phKey, pbKey, cbKey);
		LocalFree(pbKey);
	}

	return hr;
}

_NT_END