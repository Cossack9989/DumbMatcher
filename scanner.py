import os
import zio
import time
import json
import logging
import argparse
import subprocess


parser = argparse.ArgumentParser(description="Scan binaries from DataCon 2022 IoT Challenge 2")
parser.add_argument('-c', '--config', type=str, help='specify a config file', required=True)
parser.add_argument('-e', '--extract', type=str, help='specify where to store extracted info', required=True)
args = parser.parse_args()

if not os.path.exists(args.extract):
    print("incorrect EXTRACT_TO path")
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


def execute(path: str, script: str, config: dict):
    exe = getIda(path, config)
    try:
        logging.info(f"Loading {path} with scanner")
        tmp_env = os.environ.copy()
        tmp_env["EXTRACT_TO"] = args.extract
        command = [
            exe, "-A", "-b0",
            f"-S{os.getcwd()}/scripts/{script}.py",
            f"-L{os.getcwd()}/logs/ida-{script}-{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}.log",
            path
        ]
        proc = subprocess.Popen(command)
        proc.wait()
        # TODO
        os.system(f"rm '{path}'.*")

    except Exception as e:
        logging.info(f"Error occur with {str(Exception)} as {str(e)}")
        pass


def scan(scan_config: dict):

    dir_to_be_scanned = scan_config["DIR_TO_BE_SCANNED"]
    if not isinstance(dir_to_be_scanned, str):
        return False
    if not os.path.exists(dir_to_be_scanned):
        return False

    for file in os.listdir(dir_to_be_scanned):
        execute(os.path.join(dir_to_be_scanned, file), "features_scanner", scan_config)

    return True


if __name__ == "__main__":
    if not os.path.exists(args.config):
        print("What's wrong with you ?")
    try:
        config = json.load(open(args.config))
        status = scan(config)
        assert status
    except Exception as e:
        print("What's wrong with your config ????")
        print(f"{e}")
