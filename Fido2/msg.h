#pragma once

int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR lpCaption, UINT uType = MB_OK);
int CustomMessageBox(HWND hWnd, PCWSTR lpText, PCWSTR lpszCaption, UINT uType);
