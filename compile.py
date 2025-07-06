#!/usr/bin/env python3
#
# Name  : c-to-shellcode.py
# Author: Print3M
# GitHub: https://github.com/Print3M
import os
from pathlib import Path
import subprocess
import sys


def args(arr: list[str]):
    return " ".join(arr)


def run_cmd(cmd: str):
    subprocess.run(cmd, text=True, check=True, shell=True)
    print(f"[+] {cmd}")


LOADER_PAYLOAD_STR = ":PAYLOAD:"

CC = "x86_64-w64-mingw32-gcc-win32"
EXE_PAYLOAD_CFLAGS = args([
    "-fPIC",
    "-mconsole",
    "-Os",
    "-DENABLE_DEBUG",
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Wformat",
])
BIN_PAYLOAD_CFLAGS = args([
    "-Os",
    "-fPIC",
    "-nostdlib",
    "-nostartfiles",
    "-ffreestanding",
    "-fno-asynchronous-unwind-tables",
    "-fno-ident",
    "-e start",
    "-s",
    "-Werror",
    "-Wall",
    "-Wextra",
])

if __name__ == "__main__":
    ORIG_CWD = Path(os.getcwd())
    ROOT = Path(__file__).parent
    input_file = Path(ROOT / 'payload.c').absolute()
    os.chdir(ROOT)
    output_dir = input_file.parent / 'bin'
    output_file_o = output_dir / f'{input_file.name.rsplit(".")[0]}.o'
    output_file_bin = output_dir / f'{input_file.name.rsplit(".")[0]}.bin'
    output_file_exe = output_dir / f'{input_file.name.rsplit(".")[0]}.exe'
    output_file_loader = output_dir / f'loader.exe'

    # Compile payload C code to object file
    run_cmd(f"{CC} -c {input_file} -o {output_file_o} {BIN_PAYLOAD_CFLAGS}")

    # Produce flat binary with payload
    run_cmd(f"ld -T assets/linker.ld {output_file_o} -o {output_file_bin}")

    # Produce PE .exe with payload (WinAPI included)
    # run_cmd(f"{CC} -c {input_file} -o {output_file_o} {EXE_PAYLOAD_CFLAGS} -DENABLE_LOG_DEBUG")
    # run_cmd(f"{CC} {output_file_o} -o {output_file_exe} {EXE_PAYLOAD_CFLAGS}")
    run_cmd(f"{CC} {input_file} -o {output_file_exe} {EXE_PAYLOAD_CFLAGS}")

    # Convert flat binary into C array of bytes
    with open(output_file_bin, "rb") as f:
        bytes = bytearray(f.read())

    size = len(bytes)
    print(f"[+] Binary payload size: {size} bytes")

    payload = ""
    for byte in bytes:
        payload += "\\" + hex(byte).lstrip("0")

    # Inject payload into loader source code
    for loader in ['loader_exe', 'loader_svc']:
        with open(f"assets/{loader}.c", "r") as f:
            loader_source = f.read()

        loader_source = loader_source.replace(LOADER_PAYLOAD_STR, payload)

        with open(f"bin/{loader}.c", "w") as f:
            f.write(loader_source)

        # Compile loader
        run_cmd(f"{CC} bin/{loader}.c -o {output_dir / f'{loader}.exe'}")

    print("")
    if ORIG_CWD in output_dir.parents:
        output_dir_rel = output_dir.relative_to(ORIG_CWD)
    else:
        output_dir_rel = output_dir # fallback
    print(f"[+] Outputs in {output_dir_rel} are ready!")
