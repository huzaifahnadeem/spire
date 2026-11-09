#!/usr/bin/env python3
"""
log_export.py - Export these SCADA YAML logs into MonPoly (MFOTL) monitoring input.

Merges one or more log files (conf4/conf6/hmi/...) into a single time-ordered trace,
tags each event with its source, and writes MonPoly input:

  * trace.sig        - signature (typed predicate declarations)
  * trace.log        - the merged, time-ordered log  (offline mode only)
  * mirror_*.mfotl   - generated mirror policies (optional; on by default)
  * FIELDMAP.md      - documents the positional argument of every predicate

This script only generates MonPoly input. The same merged trace could in principle be
targeted at other runtime-verification tools (Reelay's JSON, RTLola's CSV, DejaVu, ...),
and MonPoly's near-siblings VeriMon / CppMon consume the very same signature + formula +
trace format - but converting to those other tools is NOT done here.

Two modes:
  * offline (default): writes trace.log, then you run
        monpoly -sig trace.sig -formula <policy>.mfotl -log trace.log
  * live (--live): tails the YAML files and streams MonPoly log lines to stdout, so you
    pipe straight into MonPoly (which reads the trace from stdin when -log is omitted):
        python3 log_export.py A.yaml B.yaml --live | monpoly -sig OUT/trace.sig -formula OUT/<policy>.mfotl

Event -> predicate mapping:
  predicate name := sanitized value of --predicate-field (default data_stream), so
  RTU_PROXY_MAIN_MSG -> predicate rtu_proxy_main_msg. Arguments := ordered flattened
  fields (default: from.system_ID then every data.message_content leaf, sorted).
  Timestamps := the integer microsecond id key (rescale with --time-unit).

Usage:
  python3 log_export.py conf4.yaml conf6.yaml hmi.yaml
  python3 log_export.py conf4.yaml conf6.yaml --window 100000 --no-policy
  python3 log_export.py conf4.yaml conf6.yaml --mirror RTU_PROXY_MAIN_MSG,RTU_PROXY_SHADOW_MSG
  python3 log_export.py conf4.yaml conf6.yaml --live --from-start | monpoly -sig monitor_export/trace.sig -formula monitor_export/<policy>.mfotl
"""

import argparse
import itertools
import os
import re
import sys
import time
from collections import deque

#sys.path.insert(0, "../scripts/")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from logdiff_aligned import load_entries, flatten, get_dotted

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
TIME_DIV = {"us": 1, "ms": 1000, "s": 1_000_000}
END_MARKER = "# === End Entry ==="


def sanitize(s):
    s = re.sub(r"[^0-9A-Za-z]+", "_", str(s)).strip("_").lower()
    if not s:
        s = "x"
    if s[0].isdigit():
        s = "f_" + s
    return s


def leaf(path):
    return sanitize(path.split(".")[-1])


def infer_type(values):
    seen_float = False
    for v in values:
        if isinstance(v, bool):
            return "string"
        if isinstance(v, int):
            continue
        if isinstance(v, float):
            seen_float = True
        else:
            return "string"
    return "float" if seen_float else "int"


def fmt_monpoly(v, unquoted):
    if isinstance(v, bool):
        return f'"{v}"'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    s = str(v)
    if unquoted or IDENT_RE.match(s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ----------------------------- collection -----------------------------------

class Rec:
    __slots__ = ("ts", "pred", "system", "stream", "flat")

    def __init__(self, ts, pred, system, stream, flat):
        self.ts, self.pred, self.system, self.stream, self.flat = ts, pred, system, stream, flat


def make_rec(id_, body, predicate_field):
    try:
        ts = int(id_)
    except (TypeError, ValueError):
        return None
    flat = {p: v for p, v in flatten(body)}
    stream = get_dotted(body, predicate_field)
    return Rec(ts, sanitize(stream), get_dotted(body, "from.system_ID"), stream, flat)


def collect(files, predicate_field):
    recs = []
    for path in files:
        for id_, body in load_entries(path):
            r = make_rec(id_, body, predicate_field)
            if r is None:
                print(f"warning: skipping entry with non-integer id in {path}",
                      file=sys.stderr)
                continue
            recs.append(r)
    recs.sort(key=lambda r: r.ts)
    return recs


def build_schema(recs, field_override, extra_fields):
    """Return (arg_paths_by_pred, types_by_pred)."""
    if field_override:
        global_order = list(field_override)
    else:
        mc = sorted({p for r in recs for p in r.flat if p.startswith("data.message_content.")})
        global_order = ["from.system_ID"] + mc + list(extra_fields)

    by_pred = {}
    for r in recs:
        by_pred.setdefault(r.pred, []).append(r)

    arg_paths, types = {}, {}
    for pred, group in by_pred.items():
        present = [p for p in global_order
                   if all(g.flat.get(p) is not None for g in group)]
        dropped = [p for p in global_order if p not in present]
        if dropped:
            print(f"note: predicate {pred!r} omits fields absent from some of its events: "
                  f"{', '.join(dropped)}", file=sys.stderr)
        arg_paths[pred] = present
        types[pred] = {p: infer_type([g.flat[p] for g in group]) for p in present}
    return arg_paths, types


# ----------------------------- MonPoly writers ------------------------------

def write_signature(arg_paths, types, path):
    with open(path, "w") as fh:
        for pred in sorted(arg_paths):
            arg_types = ", ".join(types[pred][p] for p in arg_paths[pred])
            fh.write(f"{pred}({arg_types})\n")


def write_fieldmap(arg_paths, types, path, time_unit, div):
    with open(path, "w") as fh:
        fh.write("# MonPoly argument map\n\n")
        fh.write(f"Timestamps are in **{time_unit}** (scaled from the microsecond id key; "
                 f"divisor {div}). Metric intervals in the policies are in the same unit.\n\n")
        for pred in sorted(arg_paths):
            fh.write(f"## `{pred}`\n\n| pos | variable | field path | type |\n"
                     "|----|----|----|----|\n")
            for i, p in enumerate(arg_paths[pred]):
                fh.write(f"| {i} | `{leaf(p)}` | `{p}` | {types[pred][p]} |\n")
            fh.write("\n")


def build_app(rec, arg_paths, unquoted):
    """Render one event as a MonPoly predicate application, or (None, reason)."""
    paths = arg_paths.get(rec.pred)
    if paths is None:
        return None, f"unknown predicate {rec.pred!r} (not in startup schema)"
    if any(rec.flat.get(p) is None for p in paths):
        return None, f"event of {rec.pred!r} missing an expected field"
    vals = ", ".join(fmt_monpoly(rec.flat[p], unquoted) for p in paths)
    return f"{rec.pred}({vals})", None


def write_log_file(recs, arg_paths, path, div, unquoted):
    with open(path, "w") as fh:
        for ts_scaled, group in itertools.groupby(recs, key=lambda r: r.ts // div):
            apps = []
            for r in group:
                app, reason = build_app(r, arg_paths, unquoted)
                if app is not None:
                    apps.append(app)
            if apps:
                fh.write(f"@{ts_scaled} " + " ".join(apps) + "\n")


# ----------------------------- policies -------------------------------------

def _pick_mirror(recs, arg_paths, mirror):
    counts = {}
    for r in recs:
        counts[r.pred] = counts.get(r.pred, 0) + 1
    if mirror:
        a, b = (sanitize(x) for x in mirror.split(","))
        if a not in arg_paths or b not in arg_paths:
            return None
        return a, b
    ranked = sorted(counts, key=lambda p: -counts[p])
    for i in range(len(ranked)):
        for j in range(i + 1, len(ranked)):
            a, b = ranked[i], ranked[j]
            if arg_paths[a] == arg_paths[b] and len(arg_paths[a]) >= 2:
                return a, b
    return None


def build_mirror_formula(arg_paths, a, b, window):
    """Violation form: an `a` event with no `b` carrying the same content within window."""
    paths_a = arg_paths[a]                       # a and b share a schema
    sys_var = leaf(paths_a[0])                   # first arg = from.system_ID
    content = [leaf(p) for p in paths_a[1:]]      # shared payload variables
    args_here = ", ".join([sys_var] + content)
    args_other = ", ".join([sys_var + "_b"] + content)   # different system, same content
    inner = f"(EXISTS {sys_var}_b. {b}({args_other}))"
    return (f"{a}({args_here})\n"
            f"  AND NOT ( (ONCE[0,{window}] {inner})\n"
            f"            OR (EVENTUALLY[0,{window}] {inner}) )\n")


def write_policies(recs, arg_paths, out_dir, window, mirror, time_unit):
    """Write directional + combined mirror policies. Returns (paths, notes)."""
    pair = _pick_mirror(recs, arg_paths, mirror)
    if pair is None:
        p = os.path.join(out_dir, "mirror_placeholder.mfotl")
        with open(p, "w") as fh:
            fh.write("TRUE\n")
        return [p], ["no two predicates share a schema; wrote a TRUE placeholder"]

    a, b = pair
    f_ab = build_mirror_formula(arg_paths, a, b, window)
    f_ba = build_mirror_formula(arg_paths, b, a, window)
    combined = f"( {f_ab.strip()} )\nOR\n( {f_ba.strip()} )\n"

    p_ab = os.path.join(out_dir, f"mirror_{a}_to_{b}.mfotl")
    p_ba = os.path.join(out_dir, f"mirror_{b}_to_{a}.mfotl")
    p_both = os.path.join(out_dir, f"mirror_{a}_{b}_either.mfotl")
    with open(p_ab, "w") as fh:
        fh.write(f_ab)
    with open(p_ba, "w") as fh:
        fh.write(f_ba)
    with open(p_both, "w") as fh:
        fh.write(combined)

    notes = [
        f"forward:  every `{a}` mirrored by `{b}` within {window} {time_unit}  "
        f"({os.path.basename(p_ab)})",
        f"reverse:  every `{b}` mirrored by `{a}` within {window} {time_unit}  "
        f"({os.path.basename(p_ba)})",
        f"either:   one monitor catching a violation in either direction  "
        f"({os.path.basename(p_both)})",
    ]
    return [p_ab, p_ba, p_both], notes


# ----------------------------- live tailing ---------------------------------

def extract_blocks(buf):
    blocks = []
    while True:
        idx = buf.find(END_MARKER)
        if idx == -1:
            break
        cut = idx + len(END_MARKER)
        blocks.append(buf[:cut])
        buf = buf[cut:]
    return blocks, buf


def parse_block(block):
    import yaml
    try:
        doc = yaml.safe_load(block)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or len(doc) != 1:
        return None
    (id_, body), = doc.items()
    if not isinstance(body, dict):
        return None
    return id_, body


class Tailer:
    def __init__(self, path, from_start):
        self.path = path
        self.buf = ""
        self.pos = 0
        if not from_start and os.path.exists(path):
            self.pos = os.path.getsize(path)   # skip existing content

    def poll(self):
        out = []
        if not os.path.exists(self.path):
            return out
        size = os.path.getsize(self.path)
        if size < self.pos:                    # truncated / rotated
            self.pos = 0
            self.buf = ""
        if size > self.pos:
            with open(self.path) as fh:
                fh.seek(self.pos)
                self.buf += fh.read()
                self.pos = fh.tell()
            blocks, self.buf = extract_blocks(self.buf)
            for blk in blocks:
                parsed = parse_block(blk)
                if parsed is not None:
                    out.append(parsed)
        return out


def _emit_safe(bufs, wm, div, out, last_ts, flush):
    """Emit all buffered records whose order is now settled, grouped by timestamp."""
    n = len(bufs)
    while True:
        cand, cand_ts = None, None
        for i, b in enumerate(bufs):
            if b and (cand is None or b[0][0] < cand_ts):
                cand, cand_ts = i, b[0][0]
        if cand is None:
            break
        if not flush:
            safe = all(wm[j] is not None and wm[j] >= cand_ts
                       for j in range(n) if j != cand)
            if not safe:
                break
        apps = []
        for b in bufs:
            while b and b[0][0] == cand_ts:
                apps.append(b.popleft()[1])
        if last_ts is not None and cand_ts < last_ts:
            print(f"warning: dropping out-of-order timestamp {cand_ts} < {last_ts}",
                  file=sys.stderr)
            continue
        out.write(f"@{cand_ts} " + " ".join(apps) + "\n")
        last_ts = cand_ts
    return last_ts


def run_live(files, arg_paths, predicate_field, div, from_start, poll, max_delay,
             unquoted, out=sys.stdout):
    tailers = [Tailer(f, from_start) for f in files]
    bufs = [deque() for _ in files]
    wm = [None] * len(files)
    last_new = [time.time()] * len(files)
    last_ts = None
    warned = set()
    try:
        while True:
            now = time.time()
            got = False
            for i, t in enumerate(tailers):
                for id_, body in t.poll():
                    rec = make_rec(id_, body, predicate_field)
                    if rec is None:
                        continue
                    app, reason = build_app(rec, arg_paths, unquoted)
                    if app is None:
                        if reason not in warned:
                            print(f"warning: {reason}", file=sys.stderr)
                            warned.add(reason)
                        continue
                    ts = rec.ts // div
                    bufs[i].append((ts, app))
                    wm[i] = ts if wm[i] is None else max(wm[i], ts)
                    last_new[i] = now
                    got = True
            # Unblock emission if a source has been silent past --max-delay: assume it
            # will not retroactively emit an older-timestamped event.
            if max_delay > 0:
                overall = max([w for w in wm if w is not None], default=None)
                if overall is not None:
                    for i in range(len(files)):
                        if now - last_new[i] >= max_delay:
                            wm[i] = overall if wm[i] is None else max(wm[i], overall)
            last_ts = _emit_safe(bufs, wm, div, out, last_ts, flush=False)
            if got:
                out.flush()
            time.sleep(poll)
    except KeyboardInterrupt:
        _emit_safe(bufs, wm, div, out, last_ts, flush=True)
        out.flush()


# ----------------------------- README ---------------------------------------

def write_readme(out_dir, policy_notes, window, time_unit, gen_policy):
    with open(os.path.join(out_dir, "README.md"), "w") as fh:
        fh.write("# MonPoly export\n\n")
        fh.write("Merged, time-ordered trace of the input logs, as MonPoly input.\n\n")
        fh.write("## Offline\n\n```\nmonpoly -sig trace.sig -formula <policy>.mfotl -log trace.log\n```\n\n")
        fh.write("## Live\n\n"
                 "MonPoly reads the trace from stdin when `-log` is omitted, so pipe into it:\n\n"
                 "```\npython3 log_export.py A.yaml B.yaml --live \\\n"
                 "    | monpoly -sig trace.sig -formula <policy>.mfotl\n```\n\n")
        if gen_policy:
            fh.write("## Policies\n\n"
                     "MonPoly's `-formula` takes a single policy, so the two mirror "
                     "directions are separate files (run one monitor each), plus a "
                     "combined either-direction file:\n\n")
            for note in policy_notes:
                fh.write(f"- {note}\n")
            fh.write("\n")
        fh.write("`FIELDMAP.md` lists the positional argument of every predicate for "
                 f"writing further policies. Timestamps/intervals are in `{time_unit}` "
                 f"(window = {window}).\n")


# ----------------------------- main -----------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Export SCADA YAML logs to MonPoly (MFOTL) monitoring input.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out-dir", default="/tmp/log_export/")
    ap.add_argument("--predicate-field", default="data_stream",
                    help="field whose value names the predicate (default data_stream)")
    ap.add_argument("--field", action="append", default=[], metavar="PATH",
                    help="explicit ordered argument field paths (repeatable); overrides "
                         "the default of system_ID + message_content leaves")
    ap.add_argument("--extra-field", action="append", default=[], metavar="PATH",
                    help="add a field to the default argument set (repeatable)")
    ap.add_argument("--time-unit", choices=["us", "ms", "s"], default="us",
                    help="MonPoly timestamp unit (default us = raw microsecond ids)")
    ap.add_argument("--window", type=int, default=100000,
                    help="mirror-policy time window in --time-unit (default 100000)")
    ap.add_argument("--mirror", metavar="A,B",
                    help="stream names (raw or sanitized) to mirror; default auto-detects "
                         "the two most frequent predicates with a shared schema")
    ap.add_argument("--no-policy", action="store_true",
                    help="do not generate the .mfotl policies (they are generated by default)")
    ap.add_argument("--unquoted-strings", action="store_true",
                    help="never quote string values in the MonPoly log")
    ap.add_argument("--live", action="store_true",
                    help="tail the YAML files and stream MonPoly log lines to stdout "
                         "(pipe into monpoly with -log omitted)")
    ap.add_argument("--from-start", action="store_true",
                    help="in --live, replay existing entries first; default skips to the "
                         "end and emits only newly appended entries")
    ap.add_argument("--poll", type=float, default=0.5, metavar="SECONDS",
                    help="live poll interval (default 0.5)")
    ap.add_argument("--max-delay", type=float, default=0.0, metavar="SECONDS",
                    help="live: if one file is silent this long, stop waiting for it and "
                         "emit the others (assumes it won't emit older timestamps). "
                         "0 = wait indefinitely to preserve strict ordering")
    args = ap.parse_args(argv)

    for f in args.files:
        if not os.path.exists(f):
            print(f"error: file not found: {f}", file=sys.stderr)
            return 2

    os.makedirs(args.out_dir, exist_ok=True)
    div = TIME_DIV[args.time_unit]

    # Build the schema from the current file contents (needed for the signature and
    # policies in both modes).
    recs = collect(args.files, args.predicate_field)
    if not recs:
        print("error: no usable entries found (need some existing entries to infer the "
              "signature)", file=sys.stderr)
        return 2
    arg_paths, types = build_schema(recs, args.field, args.extra_field)

    sig_path = os.path.join(args.out_dir, "trace.sig")
    fmap_path = os.path.join(args.out_dir, "FIELDMAP.md")
    write_signature(arg_paths, types, sig_path)
    write_fieldmap(arg_paths, types, fmap_path, args.time_unit, div)

    policy_paths, policy_notes = [], []
    if not args.no_policy:
        policy_paths, policy_notes = write_policies(
            recs, arg_paths, args.out_dir, args.window, args.mirror, args.time_unit)

    if args.live:
        # All human-readable output goes to stderr; stdout carries the MonPoly trace.
        print(f"schema + policies written to {args.out_dir}/", file=sys.stderr)
        first_policy = policy_paths[0] if policy_paths else "<policy>.mfotl"
        print("pipe this into MonPoly, e.g.:", file=sys.stderr)
        print(f"    python3 {os.path.basename(sys.argv[0])} {' '.join(args.files)} "
              f"--live{' --from-start' if args.from_start else ''} "
              f"| monpoly -sig {sig_path} -formula {first_policy}", file=sys.stderr)
        mode = "from start" if args.from_start else "from end (new entries only)"
        print(f"streaming live ({mode}); Ctrl-C to stop\n", file=sys.stderr)
        run_live(args.files, arg_paths, args.predicate_field, div, args.from_start,
                 args.poll, args.max_delay, args.unquoted_strings)
        return 0

    # offline
    log_path = os.path.join(args.out_dir, "trace.log")
    write_log_file(recs, arg_paths, log_path, div, args.unquoted_strings)
    write_readme(args.out_dir, policy_notes, args.window, args.time_unit,
                 not args.no_policy)

    preds = sorted(arg_paths)
    print(f"Exported {len(recs)} events across {len(preds)} predicate(s): {', '.join(preds)}")
    for note in policy_notes:
        print(f"  {note}")
    print(f"  files written to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
