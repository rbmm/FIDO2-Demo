#include "stdafx.h"

_NT_BEGIN

#include "store.h"

extern volatile const UCHAR guz = 0;

struct FIDO_KEY {
	ULONG cbId, cbKey;
	UCHAR buf[];

	void* operator new(size_t s, ULONG cbId, ULONG cbKey)
	{
		return LocalAlloc(LMEM_FIXED, s + cbId + cbKey);
	}

	void operator delete(void* pv)
	{
		LocalFree(pv);
	}
};

static const WCHAR _G_FkName[] = L"\\Registry\\MACHINE\\SOFTWARE\\Microsoft\\UserData\\rbmm";

HRESULT GetFKData(ULONG Rid,
	PBYTE pb,
	ULONG cb,
	PBYTE* ppbId,
	ULONG* pcbId,
	PBYTE* ppbKey,
	ULONG* pcbKey)
{
	HANDLE hKey;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, _G_FkName);

	NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &oa);

	if (0 <= status)
	{
		WCHAR sz[16];
		swprintf_s(sz, _countof(sz), L"%x", Rid);
		RtlInitUnicodeString(&ObjectName, sz);

		status = ZwQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, pb, cb, &cb);

		NtClose(hKey);

		if (0 <= status)
		{
			if (REG_BINARY == reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64>(pb)->Type)
			{
				if (sizeof(FIDO_KEY) < (cb = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64>(pb)->DataLength))
				{
					cb -= sizeof(FIDO_KEY);
					FIDO_KEY* pfk = (FIDO_KEY*)reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64>(pb)->Data;

					if (pfk->cbId + pfk->cbKey == cb && pfk->cbId < cb)
					{
						*ppbId = pfk->buf;
						*ppbKey = pfk->buf + pfk->cbId;
						*pcbId = pfk->cbId;
						*pcbKey = pfk->cbKey;

						return STATUS_SUCCESS;
					}
				}
			}

			return STATUS_BAD_DATA;
		}
	}

	return status;
}

HRESULT RegisterFK(ULONG Rid, PBYTE pbId, ULONG cbId, PBYTE pbKey, ULONG cbKey)
{
	HANDLE hKey;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, _G_FkName);

	NTSTATUS status = ZwCreateKey(&hKey, KEY_WRITE, &oa, 0, 0, 0, 0);

	if (0 <= status)
	{
		WCHAR sz[16];
		swprintf_s(sz, _countof(sz), L"%x", Rid);
		RtlInitUnicodeString(&ObjectName, sz);

		union {
			ULONG64 align;
			KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 kvpi;
		};
		status = STATUS_NO_MEMORY;

		if (FIDO_KEY* pfk = new(cbId, cbKey) FIDO_KEY)
		{
			pfk->cbId = cbId, pfk->cbKey = cbKey;
			memcpy((PBYTE)memcpy(pfk->buf, pbId, cbId) + cbId, pbKey, cbKey);

			status = ZwSetValueKey(hKey, &ObjectName, 0, REG_BINARY, pfk, FIELD_OFFSET(FIDO_KEY, buf[cbId + cbKey]));
			delete pfk;
		}

		NtClose(hKey);
	}
	return status;
}

_NT_END