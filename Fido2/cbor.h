#pragma once

struct CBOR
{
	enum T7 { t_false, t_true, t_null, t_undefined };

	enum {
		t_uint, t_int, t_bin, t_string, t_array, t_map, t_enum
	};

	PBYTE encode(_Out_writes_(cb) PBYTE /*pb*/, _In_ ULONG /*cb*/, _Out_ ULONG* /*pcb*/)
	{
		return 0;
	}

	PBYTE decode(_In_reads_bytes_(cb) PBYTE pb, _In_ ULONG cb, _Out_ ULONG* pcb);

	virtual BOOL OnUint(ULONG64 /*i*/)
	{
		return TRUE;
	}

	virtual BOOL OnInt(LONG64 /*i*/)
	{
		return TRUE;
	}

	virtual BOOL OnBinary(PBYTE /*pb*/, ULONG /*cb*/)
	{
		return TRUE;
	}

	virtual BOOL OnString(PCSTR /*psz*/, ULONG /*len*/)
	{
		return TRUE;
	}

	virtual BOOL BeginArray(ULONG /*n*/)
	{
		return TRUE;
	}

	virtual BOOL BeginMap(ULONG /*n*/)
	{
		return TRUE;
	}

	virtual BOOL GetItem(PCSTRING /*name*/, ULONG /*i*/, CBOR** pp)
	{
		*pp = this;
		return TRUE;
	}

	virtual BOOL OnSpec(T7 /*v*/)
	{
		return TRUE;
	}

	virtual BOOL EndArray()
	{
		return TRUE;
	}

	virtual BOOL EndMap()
	{
		return TRUE;
	}
};

PBYTE encode_int(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, ULONG64 value, UCHAR type);

PBYTE encode_enum(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, CBOR::T7 t);

PBYTE encode_bin(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, LONG len, UCHAR type, const void* pv);

inline PBYTE encode_string(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, _In_ PCSTR pcsz)
{
	return encode_bin(pb, pcb, (ULONG)strlen(pcsz), CBOR::t_string, pcsz);
}

inline PBYTE encode_bin(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, _In_ LONG len, const void* pv)
{
	return encode_bin(pb, pcb, len, CBOR::t_bin, pv);
}

inline PBYTE encode_map(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, ULONG nItems)
{
	return encode_int(pb, pcb, nItems, CBOR::t_map);
}

inline PBYTE encode_array(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, ULONG nItems)
{
	return encode_int(pb, pcb, nItems, CBOR::t_array);
}

inline PBYTE encode_int(_Out_writes_(cb) PBYTE pb, _Inout_ LONG* pcb, LONG64 value)
{
	return 0 > value ? encode_int(pb, pcb, -1 - value, CBOR::t_int) : encode_int(pb, pcb, value, CBOR::t_uint);
}

