#ifndef CONFIG_H

#define CONFIG_H

#ifdef STAGED
#define STAGER_HOST L"<STAGER_HOST>"
#define STAGER_PORT (13337)
#define STAGER_PATH L"<STAGER_PATH>"
#else
#define SHELLCODE_HEX "<SHELLCODE_HEX>"
#endif

#endif