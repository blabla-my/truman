import subprocess
import argparse
import shlex
from pathlib import Path
from multiprocessing import Pool
from fuzz import QEMUFuzz


def run_fuzz_on_target(output, seq, target, round, asan = False, fork = False):
    # python3 ~/truman/scripts/python/fuzz.py -e --fork -t virtio-scsi --tool truman
    fork_arg = "--fork" if fork else ""
    output_arg = f"-o {shlex.quote(str(output))}" if output else ""
    if asan:
        cmd = f"sleep {seq} && python3 ~/truman/scripts/python/fuzz.py --asan {fork_arg} -t {target} --tool truman {output_arg}"
    else:
        cmd = f"sleep {seq} && python3 ~/truman/scripts/python/fuzz.py -e {fork_arg} -t {target} --tool truman {output_arg}"
    print(f"[+] fuzz {target}, round {round}")
    print(f"[CMD] {cmd}")
    p = subprocess.run(cmd, shell=True, text=True)

def main(args):
    targets = filter(lambda x: "virtio" in x, QEMUFuzz.target2file)
    tasks = []
    for seq,target in enumerate(targets):
        for i in range(args.repeat):
            tasks.append((args.output, seq, target, i, args.asan, args.fork))
    
    with Pool(processes = min(len(tasks), args.jobs)) as pool:
        pool.starmap(run_fuzz_on_target, tasks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--jobs', type=int, default=12)
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--asan', action='store_true', default=False)
    parser.add_argument('--fork', action='store_true', default=False)
    parser.add_argument('-o', '--output', type=Path, default=None,
                        help='Output root directory passed to fuzz.py')
    args = parser.parse_args()
    main(args)
