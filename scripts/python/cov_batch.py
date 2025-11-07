import json
import subprocess
import argparse
import pandas as pd
from multiprocessing import Pool
from fuzz import QEMUFuzz
from pathlib import Path

fuzz_dir:Path = None

def get_target_dir(target) -> Path:
    for subdir in fuzz_dir.resolve().iterdir():
        if subdir.is_dir() and target in subdir.name:
            return subdir
    return Path(None)

def run_cov_on_target(target):

    target_dir:Path = get_target_dir(target)
    json_result:Path = target_dir / "final_cov" / target /  f"{target}.json"
    csv_result:Path = target_dir / "final_cov" / target / f"{target}.csv"

    for i in range(2):
        if json_result.exists():
            with open(json_result, "r") as f:
                coverage = json.load(f)
            return [target, QEMUFuzz.target2file[target], coverage]
        elif csv_result.exists():
            with open(csv_result, "r") as f:
                df = pd.read_csv(f, index_col=0)
                coverage = pd.to_numeric(df['Coverage'].astype(str).str.replace('%', ''), errors='coerce').fillna(0).to_list()
            return [target, QEMUFuzz.target2file[target], coverage]
        else:
            # python3 /home/lmy/truman/scripts/python/collect_coverage.py --base out/fuzz/evaluation_1104/ --filter 1104
            cmd = f"python3 ~/truman/scripts/python/collect_coverage.py --base {fuzz_dir} --filter {target} --trend -w1"
            print(f"[+] collect cov for {target}")
            p = subprocess.run(cmd, shell=True)#, capture_output=True, text=True)
    

def main(args):
    targets = filter(lambda x: "virtio" in x, QEMUFuzz.target2file)
    tasks = []
    for target in targets:
        for i in range(args.repeat):
            tasks.append((target,))
    
    with Pool(processes = min(len(tasks), args.jobs)) as pool:
        results = pool.starmap(run_cov_on_target, tasks)
    with open(fuzz_dir / "coverage_trend.json", "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] coverage trend dumped to {fuzz_dir / 'coverage_trend.json'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--jobs', type=int, default=8)
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--base', type=Path, required=True, help="fuzz output directory")

    args = parser.parse_args()
    fuzz_dir = args.base
    main(args)