import os
import zio
import time
import json
import logging
import argparse
import subprocess

from multiprocessing import Pool


parser = argparse.ArgumentParser(description="Match ACFG from BIN_FEATURE_DB")
parser.add_argument('-c', '--config', type=str, help='specify the config file', required=True)
parser.add_argument('-p', '--path', type=str, help='specify the BIN_FEATURE_DB path', required=True)
args = parser.parse_args()

if not os.path.exists(args.path):
    print("incorrect BIN_FEATURE_DB path")
    exit(1)

if not os.path.exists(args.config):
    print("incorrect config path")
    exit(1)


def getIda(path: str, config: dict):
    io = zio.zio(["file", path])
    if '64' in io.recvall().decode('latin-1'):
        ida_path = config["ida_64"]
    else:
        ida_path = config["ida"]
    if not io.is_closed():
        io.close()
    return ida_path


def execute(path: str, script: str, config: dict, timeout=None):
    exe = getIda(path, config)
    try:
        os.system(f"rm '{path}'.*")
        logging.info(f"Loading {path} with scanner")

        tmp_env = os.environ.copy()
        tmp_env["BIN_FEATURE_DB_PATH"] = args.path

        if "nios2" in path:
            # because ida does not support NIOS2
            command = [
                exe, "-A", "-b0", "-pnios2",
                f"-S{os.getcwd()}/scripts/{script}.py",
                f"-L{os.getcwd()}/logs/ida-{script}-{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}.log",
                path
            ]
        else:
            command = [
                exe, "-A", "-b0",
                f"-S{os.getcwd()}/scripts/{script}.py",
                f"-L{os.getcwd()}/logs/ida-{script}-{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}.log",
                path
            ]
        if timeout is not None:
            proc = subprocess.run(command, timeout=60, env=tmp_env)
        else:
            proc = subprocess.Popen(command, env=tmp_env)
        proc.wait()
        # TODO
        os.system(f"rm '{path}'.*")

    except Exception as e:
        logging.info(f"Error occur with {str(Exception)} as {str(e)}")
        pass


def run(to_extract: str):
    white_list_function = [
        'atoi', 'checksum', 'csum', 'memcmp', 'memcpy', 'memmove', 'recvfrom', 'sendto', 'recv', 'send', 'snprintf',
        'sprintf', 'sscanf', 'strcat', 'strcmp', 'strcpy', 'strncat', 'strncmp', 'strncpy', 'strtol', 'getenv', 'strchr',
        'strlen', 'strnlen', 'strrchr', 'strtoul', 'memset',
    ]
    if not os.path.exists(to_extract):
        return False
    config = json.load(open(args.config, "r"))

    o2func_path = os.path.join(to_extract, "1.txt")
    if os.path.exists(o2func_path):
        o2func_raw = open(o2func_path, "r").read()
        for line in o2func_raw.split('\n'):
            line_s = line.split('    ')
            if len(line_s) == 2:
                file_name, func_name = line_s[0].strip(), line_s[1].strip()
                if func_name in white_list_function and file_name in os.listdir(to_extract):
                    print("Found", file_name)
                    execute(os.path.join(to_extract, file_name), "feature_extractor_from_o", config, timeout=-1)
                    print("Extracted", file_name)

        return ".o with mapping extracted"

    for file in os.listdir(to_extract):
        if file.endswith(".so") or file.endswith(".6"):
            # and ("arm" in file or "mips" in file or "amd64" in file) \
            # and ("mips64" not in file):
            execute(os.path.join(to_extract, file), "features_extractor", config)
            print(file)
        elif file.endswith(".o"):
            for white_function in white_list_function:
                if white_function in file:
                    execute(os.path.join(to_extract, file), "features_extractor_from_o", config, timeout=-1)
                    print(file)
    return "extracted"


if __name__ == "__main__":
    # run("/Users/c0ss4ck/Downloads/xtensa-esp32s3-elf/xtensa-esp32s3-elf/lib/libc/")
    # run("/Users/c0ss4ck/Projects/C0ss4ck/datacon/DumbMatcher/BinDB/1206/")
    to_downloads = [
        # '/zephyr-sdk-mips32r2/2.2/sysroots/mips32r2-zephyr-elf/usr/lib/el/libc.a',
        # '/zephyr-sdk-mips32r2/2.2/sysroots/mips32r2-zephyr-elf/usr/lib/libc.a',
        # '/zephyr-sdk-mips32r2/2.2/sysroots/mips32r2-zephyr-elf/usr/lib/soft-float/el/libc.a',
        # '/zephyr-sdk-mips32r2/2.2/sysroots/mips32r2-zephyr-elf/usr/lib/soft-float/libc.a',
        # '/zephyr-sdk-xtensa/2.2/sysroots/xtensa-zephyr-elf/usr/lib/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/thumb/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7-m/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/fpu/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/fpu/fpv5-sp-d16/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/fpu/fpv5-d16/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/softfp/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/softfp/fpv5-sp-d16/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv7e-m/softfp/fpv5-d16/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/fpu/libc.a',
        '/zephyr-sdk-armv5/2.2/sysroots/armv5-zephyr-eabi/usr/lib/armv6-m/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/nomul/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/nomul/fpu-60-1/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/nomul/fpu-60-2/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/fpu-60-1/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/mulx/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/mulx/fpu-60-1/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/mulx/fpu-60-2/libc.a',
        # '/zephyr-sdk-nios2/2.2/sysroots/nios2-zephyr-elf/usr/lib/fpu-60-2/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/quarkse2_em/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/hs34/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/em/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/archs/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/nps400/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/hs/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/em4_dmips/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/em4/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/hs38_linux/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc600/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc600_mul32x16/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arcem/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/hs38/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc601/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc700/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/quarkse_em/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc601_norm/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc601_mul32x16/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/em4_fpuda/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc600_mul64/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/em4_fpus/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc601_mul64/libc.a',
        # '/zephyr-sdk-arcv2/2.2/sysroots/arc-zephyr-elf/usr/lib/arc600_norm/libc.a'
    ]
    args = []
    for to_download in to_downloads:
        dirt = f"./BinDB/1209/{to_download[:-2].replace('/', '_')}"
        args.append(dirt)
        # run(dirt)
    with Pool(6) as p:
        rets = p.map_async(run, args).get()
        print(rets)