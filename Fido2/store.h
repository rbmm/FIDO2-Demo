#pragma once

HRESULT GetFKData(ULONG Rid,
	PBYTE pb,
	ULONG cb,
	PBYTE* ppbId,
	ULONG* pcbId,
	PBYTE* ppbKey,
	ULONG* pcbKey);

HRESULT RegisterFK(ULONG Rid, PBYTE pbId, ULONG cbId, PBYTE pbKey, ULONG cbKey);
