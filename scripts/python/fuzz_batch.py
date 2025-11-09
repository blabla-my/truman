import subprocess
import argparse
from multiprocessing import Pool
from fuzz import QEMUFuzz


def run_fuzz_on_target(target, round, asan = False):
    # python3 ~/truman/scripts/python/fuzz.py -e --fork -t virtio-scsi --tool truman
    if asan:
        cmd = f"python3 ~/truman/scripts/python/fuzz.py --asan --fork -t {target} --tool truman"
    else:
        cmd = f"python3 ~/truman/scripts/python/fuzz.py -e --fork -t {target} --tool truman"
    print(f"[+] fuzz {target}, round {round}")
    print(f"[CMD] {cmd}")
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)

def main(args):
    targets = filter(lambda x: "virtio" in x, QEMUFuzz.target2file)
    tasks = []
    for target in targets:
        for i in range(args.repeat):
            tasks.append((target, i, args.asan))
    
    with Pool(processes = min(len(tasks), args.jobs)) as pool:
        pool.starmap(run_fuzz_on_target, tasks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--jobs', type=int, default=12)
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--asan', action='store_true', default=False)
    args = parser.parse_args()
    main(args)