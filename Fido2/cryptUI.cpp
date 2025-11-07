#include "stdafx.h"

_NT_BEGIN

typedef BOOL(WINAPI* PFNCFILTERPROC) (
	PCCERT_CONTEXT  pCertContext,
	BOOL* pfInitialSelectedCert,
	void* pvCallbackData
	);

typedef
BOOL(WINAPI* PFNCCERTDISPLAYPROC)(
	_In_  PCCERT_CONTEXT pCertContext,
	_In_  HWND hWndSelCertDlg,
	_In_  void* pvCallbackData
	);

typedef struct CRYPTUI_SELECTCERTIFICATE_STRUCTW {
	DWORD dwSize;
	HWND hwndParent;
	DWORD dwFlags;
	PCWSTR szTitle;
	DWORD dwDontUseColumn;
	PCWSTR szDisplayString;
	PFNCFILTERPROC pFilterCallback;
	PFNCCERTDISPLAYPROC pDisplayCallback;
	void* pvCallbackData;
	DWORD cDisplayStores;
	HCERTSTORE* rghDisplayStores;
	DWORD cStores;
	HCERTSTORE* rghStores;
	DWORD cPropSheetPages;
	LPCPROPSHEETPAGE rgPropSheetPages;
	HCERTSTORE hSelectedCertStore;
} *PCRYPTUI_SELECTCERTIFICATE_STRUCTW;

EXTERN_C
WINBASEAPI
PCCERT_CONTEXT WINAPI CryptUIDlgSelectCertificateW(
	__in  const CRYPTUI_SELECTCERTIFICATE_STRUCTW* pcsc
);

HRESULT DisplayStore(HWND hwndDlg, HCERTSTORE hStore)
{
	CRYPTUI_SELECTCERTIFICATE_STRUCTW csc = { sizeof(csc), hwndDlg };
	csc.cDisplayStores = 1;
	csc.cStores = 1;
	csc.rghStores = &hStore;
	csc.rghDisplayStores = &hStore;
	if (PCCERT_CONTEXT pCertContext = CryptUIDlgSelectCertificateW(&csc))
	{
		CertFreeCertificateContext(pCertContext);
		return S_OK;
	}

	return GetLastError();
}

_NT_END