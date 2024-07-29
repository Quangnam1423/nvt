#include <stdio.h>
#include <Windows.h>

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint()
{
	CHAR moduleName[128] = "";
	GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
	MessageBoxA(NULL, moduleName, "Obligatory PE Injection", NULL);
	return 0;
}

void printMemoryContent(HANDLE process, PVOID address, SIZE_T size) {
    BYTE* buffer = (BYTE*)malloc(size);  // Thay new bằng malloc
    SIZE_T bytesRead;
    if (ReadProcessMemory(process, address, buffer, size, &bytesRead)) {
        for (SIZE_T i = 0; i < bytesRead; i++) {
            printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    } else {
        DWORD error = GetLastError();
        printf("Failed to read memory. Error: %d\n", error);
    }
    free(buffer);  // Thay delete[] bằng free
}

int main()
{
    int x;

	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Open the target process
	HANDLE targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1172);
	// Allocate memory in the target process
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// Calculate delta
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Check if relocation table exists
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
        // Relocate localImage
        PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (relocationTable->SizeOfBlock > 0)
        {
            DWORD relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

            for (DWORD i = 0; i < relocationEntriesCount; i++)
            {
                if (relocationRVA[i].Offset)
                {
                    PDWORD_PTR patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                    *patchedAddress += deltaImageBase;
                }
            }
            relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
        }
    } else {
        printf("No relocation table found.\n");
    }

	// Write memory into target process
	if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) {
		VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
		CloseHandle(targetProcess);
		VirtualFree(localImage, 0, MEM_RELEASE);
		return 1;
	}
	// Start the injected PE
	DWORD_PTR injectionEntryPointAddress = (DWORD_PTR)InjectionEntryPoint + deltaImageBase;
	HANDLE remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)injectionEntryPointAddress, NULL, 0, NULL);
	if (remoteThread == NULL) {
		VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
		CloseHandle(targetProcess);
		VirtualFree(localImage, 0, MEM_RELEASE);
		return 1;
	}

	// Clean up
	CloseHandle(remoteThread);
	VirtualFreeEx(targetProcess, targetImage, 0, MEM_RELEASE);
	CloseHandle(targetProcess);
	VirtualFree(localImage, 0, MEM_RELEASE);
    scanf("%d", &x);
	return 0;
}
