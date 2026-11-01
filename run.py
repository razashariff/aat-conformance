#!/usr/bin/env python3
"""Run a verifier over the corpus and compare against each vector's declared result.

  python3 run.py                      # the bundled verifier (aatc/)
  python3 run.py --cmd "./myverifier" # any verifier: called as  <cmd> <trail.jsonl> <context.json>,
                                      # must print one JSON object {"verdict","completeness","merkle",...}

A verifier CONFORMS when verdict, completeness and merkle match on every normative vector.
Error and warning codes are reported separately; matching them is RECOMMENDED, not required.
"""
import argparse, json, os, shlex, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def codes(xs):
    return {x.split("@")[0] for x in xs}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", help="external verifier command")
    ap.add_argument("--only", help="run vectors whose id starts with this")
    ap.add_argument("-v", action="store_true", help="show every vector")
    a = ap.parse_args()
    if not a.cmd:
        sys.path.insert(0, HERE)
        from aatc.verify import verify_files
    vdir = os.path.join(HERE, "vectors")
    ids = sorted(os.listdir(vdir))
    if a.only:
        ids = [i for i in ids if i.startswith(a.only)]
    core_fail, code_miss, n_norm = [], [], 0
    for vid in ids:
        d = os.path.join(vdir, vid)
        meta = json.load(open(os.path.join(d, "vector.json")))
        exp = meta["expected"]
        trail, ctx = os.path.join(d, "trail.jsonl"), os.path.join(d, "context.json")
        if a.cmd:
            p = subprocess.run(shlex.split(a.cmd) + [trail, ctx], capture_output=True, text=True)
            try:
                got = json.loads(p.stdout)
            except ValueError:
                got = {"verdict": "error", "completeness": "", "merkle": "", "errors": [p.stderr.strip()[:200]], "warnings": []}
        else:
            got = verify_files(trail, ctx)
        same = all(got.get(k) == exp[k] for k in ("verdict", "completeness", "merkle"))
        missing = (set(exp["errors_include"]) - codes(got.get("errors", []))) | (set(exp["warnings_include"]) - codes(got.get("warnings", [])))
        if meta["normative"]:
            n_norm += 1
            if not same:
                core_fail.append((vid, exp, got))
        if same and missing:
            code_miss.append((vid, sorted(missing), got.get("errors", []) + got.get("warnings", [])))
        if a.v or not same:
            mark = "ok  " if same else ("FAIL" if meta["normative"] else "info")
            print(f"{mark} {vid:60s} {got.get('verdict')}/{got.get('completeness')}/{got.get('merkle')}"
                  + ("" if same else f"   expected {exp['verdict']}/{exp['completeness']}/{exp['merkle']}  got errors={got.get('errors')}"))
    print()
    print(f"normative vectors: {n_norm}   conform: {n_norm - len(core_fail)}   fail: {len(core_fail)}")
    print(f"informative vectors: {len(ids) - n_norm}")
    print(f"code mismatches (recommended, not required): {len(code_miss)}")
    for vid, miss, gotc in code_miss:
        print(f"   {vid}: expected {miss}, reported {gotc}")
    sys.exit(1 if core_fail else 0)


if __name__ == "__main__":
    main()
