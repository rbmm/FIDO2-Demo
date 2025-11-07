#pragma once

NTSTATUS ImportKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE pbKey, _In_ ULONG cbKey);
NTSTATUS ImportKey(_In_ PCWSTR pszAlgId, _In_ PCWSTR pszBlobType, _Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE pbKey, _In_ ULONG cbKey);
NTSTATUS ImportKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszFile);
