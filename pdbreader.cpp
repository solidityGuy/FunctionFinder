#include <iostream>
#include <dia2.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <atlbase.h>

int main(void) {
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (hr != S_OK) {
		fprintf(stderr, "Error: CoInitializeEx");
	}
	CComPtr<IDiaDataSource> pSource;
	hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&pSource);
	if (FAILED(hr))
	{
		printf("HR value: %08x", hr);
	}

	const char* szFilename = "C:\\Users\\USERNAME\\source\\repos\\myprogram\\Debug\\myprogram.pdb";
	wchar_t wszFilename[_MAX_PATH];
	mbstowcs(wszFilename, szFilename, sizeof(wszFilename) / sizeof(wszFilename[0]));
	if (FAILED(pSource->loadDataFromPdb(wszFilename)))
	{
		if (FAILED(pSource->loadDataForExe(wszFilename, NULL, NULL)))
		{
			printf("Error: loadDataFromPdb/Exe");
		}
	}
	
	IDiaSession* pSession;
	if (FAILED(pSource->openSession(&pSession)))
	{
		printf("Error: openSession");
	}

	IDiaEnumTables* pTables;
	if (FAILED(pSession->getEnumTables(&pTables)))
	{
		printf("Error: getEnumTables");
	}
	IDiaTable* pTable;
	DWORD celt = 1;
	while (SUCCEEDED(hr = pTables->Next(1, &pTable, &celt)) && celt == 1)
	{

		BSTR bstrTableName;
		LONG blongTableCount;
		if (pTable->get_name(&bstrTableName) != 0)
		{
			fprintf(stderr, "Error: get_name");
		}
		printf("Found table: %ws\t", bstrTableName);

		if (pTable->get_Count(&blongTableCount) != 0)
		{
			fprintf(stderr, "Error: get_Count");
		}
		
		printf("Count of elements: %ld\n", blongTableCount);

		IDiaEnumSymbols* pUnknown = NULL;
		if (pTable->QueryInterface(__uuidof(IDiaEnumSymbols), (void**) &pUnknown) == S_OK) {
			printf("Supports Symbol module\n");
			CComPtr<IDiaSymbol> pSymbol;

			for (LONG i = 0; i < blongTableCount; i++)
			{
				if (pUnknown->Item(i, &pSymbol) != S_OK) {
					fprintf(stderr, "Error: pUnknown->Item");
				}
				
				BOOL isFunction;
				if (pSymbol->get_function(&isFunction) == S_OK) {
					if (isFunction == TRUE) {

						BSTR symName;
						if (pSymbol->get_name(&symName) == S_OK) {
							printf("Symbol name: %S\n", symName);
							
							ULONGLONG length;
							if (pSymbol->get_length(&length) == S_OK) {
								printf("Length of symbol: %I64u\n", length);
							}
							DWORD ret;
							if (pSymbol->get_locationType(&ret) == S_OK) {
								switch (ret) {
									case LocIsStatic:
										printf("LocIsStatic\n");
										break;
									case LocIsThisRel:
										printf("LocIsThisRel\n");
										break;
								}
							}
							if (pSymbol->get_relativeVirtualAddress(&ret) == S_OK) {
								printf("RVA: 0x%0.5x\n", ret);
							}
							ULONGLONG va;
							if (pSymbol->get_virtualAddress(&va) == S_OK) {
								printf("VA: %I64u\n", va);
							}
							
						}
					}
				}
				
				pSymbol = NULL;

			}
			const void* BaseAddress = (const void*) 0x4119e0;
			
		}



	}
	return 0;
}