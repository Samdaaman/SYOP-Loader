#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

#define FUNC __attribute__((section(".func")))

#define ALIGN_STACK()                                                          \
  __asm__ __volatile__(                                                        \
      "mov %%rsp, %%rax;" /* Move stack pointer to rax */                      \
      "and $0xF, %%rax;"  /* Check if aligned to 16 bytes */                   \
      "jz aligned;"       /* If aligned, jump to aligned If not aligned,       \
                             adjust the stack pointer */                       \
      "sub $8, %%rsp;"    /* Decrease stack pointer by 8 bytes */              \
      "xor %0, %0;"       /* Optionally zero out the allocated space */        \
      "aligned:"                                                               \
      :        /* No output operands */                                        \
      : "r"(0) /* Input operand (to zero out) */                               \
      : "%rax" /* Clobbered register */                                        \
  );

// typedef UINT(WINAPI *WinExecPtr)(LPCSTR lpCmdLine, UINT uCmdShow);

typedef HMODULE(WINAPI *LoadLibraryA_t)(IN LPCSTR lpLibFileName);
typedef FARPROC(WINAPI *GetProcAddress_t)(IN HMODULE hModule, IN LPCSTR lpProcName);


FUNC int my_wcscmp(const wchar_t *s1, const wchar_t *s2) {
  while (*s1 != L'\0' && *s2 != L'\0') {
    if (*s1 != *s2) {
      return (*s1 < *s2) ? -1 : 1;
    }

    s1++;
    s2++;
  }

  if (*s1 == L'\0' && *s2 == L'\0') {
    return 0;
  }

  return (*s1 == L'\0') ? -1 : 1;
}

FUNC int my_strcmp(const char *str1, const char *str2) {
  while (*str1 != '\0' && *str2 != '\0') {
    if (*str1 != *str2) {
      return (*str1 < *str2) ? -1 : 1;
    }
    str1++;
    str2++;
  }

  if (*str1 == '\0' && *str2 == '\0') {
    return 0;
  }

  return (*str1 == '\0') ? -1 : 1;
}

FUNC PLDR_DATA_TABLE_ENTRY GetDllLdr(PPEB_LDR_DATA ldr, wchar_t *name) {
  PLIST_ENTRY item = ldr->InMemoryOrderModuleList.Blink;
  PLDR_DATA_TABLE_ENTRY dll = NULL;

  do {
    dll = CONTAINING_RECORD(item, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    if (my_wcscmp(dll->FullDllName.Buffer, name) == 0) {
      return dll;
    }

    item = item->Blink;
  } while (item != NULL);

  return NULL;
}

FUNC PPEB GetPEB(void) {
  uint64_t value = 0;

  // Inline assembly to read from the GS segment
  asm volatile("movq %%gs:%1, %0"
               : "=r"(value)            // output
               : "m"(*(uint64_t *)0x60) // input
               :                        // no clobbered registers
  );

  return (PPEB)value;
}

FUNC void FindFunc(PVOID library_base, const char *name, void **func_ptr)
{
  // Get PE headers
  PVOID pe_hdrs = (PVOID)(library_base + ((PIMAGE_DOS_HEADER)library_base)->e_lfanew);

  // Get Export Address Table RVA
  DWORD eat_rva = *(PDWORD)(pe_hdrs + 0x88);

  // Get address of Export Address Table
  PIMAGE_EXPORT_DIRECTORY eat = (PIMAGE_EXPORT_DIRECTORY)(library_base + eat_rva);

  // Get address of function names table
  PDWORD name_rva = (PDWORD)(library_base + eat->AddressOfNames);

  // Loop over imports
  int found_offset = -1;
  for (int i = 0; i < eat->NumberOfNames; i++)
  {
    char *tmp = (char *)(library_base + name_rva[i]);
    if (my_strcmp(tmp, name) == 0) {
      found_offset = i;
    }
  }
  if (found_offset == -1)
  {
    *(int*)0 = 0; // crash :)
  }

  // Get function ordinal
  PWORD ordinals = (PWORD)(library_base + eat->AddressOfNameOrdinals);
  WORD ordinal = ordinals[found_offset];

  // Get function pointer
  PDWORD func_rvas = (PDWORD)(library_base + eat->AddressOfFunctions);
  DWORD func_rva = func_rvas[ordinal];
  *func_ptr = (library_base + func_rva);
}


int start(void) {
  PPEB peb = GetPEB();

  wchar_t dll_name[] = L"C:\\Windows\\System32\\KERNEL32.DLL";

  // Get address of kernel32.dll
  PLDR_DATA_TABLE_ENTRY kernel32_ldr = GetDllLdr(peb->Ldr, dll_name);
  PVOID kernel32 = kernel32_ldr->DllBase;

  // Find LoadLibraryA
  const char LoadLibraryA_s[] = "LoadLibraryA";
  typedef HMODULE(WINAPI *LoadLibraryA_t)(IN LPCSTR lpLibFileName);
  LoadLibraryA_t LoadLibraryA = NULL;
  FindFunc(kernel32, LoadLibraryA_s, (void**)&LoadLibraryA);
  
  // Find GetProcAddress
  const char GetProcAddress_s[] = "GetProcAddress";
  typedef FARPROC(WINAPI *GetProcAddress_t)(IN HMODULE hModule, IN LPCSTR lpProcName);
  GetProcAddress_t GetProcAddress = NULL;
  FindFunc(kernel32, GetProcAddress_s, (void**)&GetProcAddress);

  typeof(CreateProcessA) *CreateProcessA = NULL;
  FindFunc(kernel32, "CreateProcessA", (void**)&CreateProcessA);
  
  STARTUPINFOA si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  CreateProcessA(
    NULL,                // Application name
    "calc.exe",          // Command line
    NULL,                // Process handle not inheritable
    NULL,                // Thread handle not inheritable
    FALSE,               // Set handle inheritance to FALSE
    0,                   // No creation flags
    NULL,                // Use parent's environment block
    NULL,                // Use parent's starting directory 
    &si,                 // Pointer to STARTUPINFO structure
    &pi                  // Pointer to PROCESS_INFORMATION structure
  );

  return 0;
}