import subprocess
import argparse
from multiprocessing import Pool
from fuzz import QEMUFuzz


def run_fuzz_on_target(target, round):
    # python3 ~/truman/scripts/python/fuzz.py -e --fork -t virtio-scsi --tool truman
    cmd = f"python3 ~/truman/scripts/python/fuzz.py -e --fork -t {target} --tool truman"
    print(f"[+] fuzz {target}, round {round}")
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)

def main(args):
    targets = filter(lambda x: "virtio" in x, QEMUFuzz.target2file)
    tasks = []
    for target in targets:
        for i in range(args.repeat):
            tasks.append((target, i))
    
    with Pool(processes = min(len(tasks), args.jobs)) as pool:
        pool.starmap(run_fuzz_on_target, tasks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--jobs', type=int, default=12)
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    main(args)