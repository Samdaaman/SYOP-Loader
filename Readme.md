# Start Your Own Process Loader (aka SYOP Loader)

This is a proof-of-concept shellcode loader that starts a sacrificial process (notepad.exe) before injecting something bad (ie meterpreter) into it.

## Setup
This repo requires a slightly patched version of the `c-to-shellcode` project to compile
```sh
# Setup c-to-shellcode
git clone https://github.com/Print3M/c-to-shellcode
cd c-to-shellcode
git checkout e9fa3bbea2f7b79c81e7024d3df2d05662b631dc
cd ..
git apply ./c-to-shellcode.patch

# Check mingw (mine is 10-win32 20220113)
x86_64-w64-mingw32-gcc-win32 --version
```

## Building
```sh
python3 c-to-shellcode/c-to-shellcode.py payload.c
```
This will produce three files in the `bin` directory:

- `payload.bin` - Position independent shellcode of the loader
- `payload.exe` - Debug version of the loader that is linked as a normal exe and with logging
- `loader.exe` - An example exe which you can use for testing the loader shellcode. It will load and execute the same shellcode within `payload.bin`.

