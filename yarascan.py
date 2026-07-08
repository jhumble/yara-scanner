#!/usr/bin/env python3.13
import os
import yara_x as yx
import sys
import datetime
import re
import binascii
import glob
import shutil

import json
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from utils import recursive_all_files
from time import sleep, time
from argparse import ArgumentParser
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count
from hashlib import md5
from pprint import pprint


DEFAULT_RULES_DIR = '/home/jhumble/RE/ice-53-yara-rules/'


def build_arg_parser():
    """Build the CLI argument parser. Kept in a helper so tests / other
    entry points can grab it without side effects."""
    p = ArgumentParser(
        prog='yarascan.py',
        usage='yarascan.py [-S SIG[::RULE[,RULE...]]] [OPTIONS] [FILE_OR_DIR]...',
        description='YARA scanner wrapper with cached compile, grep-like output, and profiling.',
    )
    p.add_argument('paths', nargs='*', metavar='FILE_OR_DIR',
        help='files or directories to scan (recursed)')
    p.add_argument('-S', '--signatures', action='append', default=None,
        help="compiled .cyar file, .yar file, or directory of YARA rules. "
             "Append '::rule_name' (optionally comma-separated) to restrict "
             "scanning to those rules from that source. Repeat -S to combine "
             "multiple sources.")
    p.add_argument('-T', '--Threshold', dest='threshold', type=float, default=3.0,
        help="minimum %%-of-mean cost for a rule or pattern to appear in "
             "the -P output. Default=3.0 (i.e. >=300%% of the mean).")
    p.add_argument('-N', '--top', dest='top_n', type=int, default=5,
        help='cap on rows per table in -P output. Default=5. Use 0 for uncapped.')
    p.add_argument('-p', '--performance', action='store_true', default=False,
        help='Enable progress and performance profiling')
    p.add_argument('-P', '--Profile', dest='profile', action='store_true', default=False,
        help='Native yara-x profiler. Prints per-rule and per-pattern cost '
             'tables. Requires yara-x built with the rules-profiling feature '
             '(see README).')
    p.add_argument('-s', '--strings', action='store_true', default=False,
        help='output matching strings')
    p.add_argument('-C', '--categorize', dest='categorize_dir', default=False,
        help='categorize the scanned samples into directories by rule name')
    p.add_argument('-o', '--offset', action='store_true', default=False,
        help='show match string offsets')
    p.add_argument('-t', '--threads', dest='num_threads', type=int, default=None,
        help='number of threads/workers')
    p.add_argument('-c', '--context', type=int, default=5,
        help='number of bytes of context before and after matches')
    p.add_argument('-l', '--line', action='store_true', default=False,
        help='Output entire line match occurs on')
    p.add_argument('-j', '--json', default=False,
        help='json output file')
    p.add_argument('-n', '--negative', action='store_true', default=False,
        help='Output files having no matches')
    p.add_argument('-w', '--wide', action='store_true', default=False,
        help='Mark matching wide/utf-16le strings')
    p.add_argument('--max-strings', dest='max_strings', type=int, default=5,
        help='Max strings to print per rule')
    p.add_argument('--max-offsets', dest='max_offsets', type=int, default=5,
        help='Max offsets to print per string')
    p.add_argument('-d', '--disassemble', choices=['64', '32'], default=None,
        help='Disassemble matching bytes using 32/64 bit mode as provided')
    return p


options = build_arg_parser().parse_args()
args = options.paths  # positional target files/dirs (was args from optparse)
options.user_provided_signatures = options.signatures is not None
if not options.signatures:
    options.signatures = [DEFAULT_RULES_DIR]

# Parse optional '::rule1,rule2' suffix per -S to restrict which rules fire from that source.
options.parsed_signatures = []
for raw in options.signatures:
    if '::' in raw:
        path, rules_str = raw.rsplit('::', 1)
        names = set(r.strip() for r in rules_str.split(',') if r.strip())
    else:
        path, names = raw, None
    options.parsed_signatures.append((path, names))
options.signatures = [p for p, _ in options.parsed_signatures]

# Populated by collect_rule_files / main. Maps rulefile namespace -> set of allowed rule names.
# Special key '*' means restrict regardless of namespace (used for .cyar fast-path).
rule_filter = {}
printable = re.compile(rb'^[\x20-\x7e\x0a]*$')
printable_wide = re.compile(rb'^([\x20-\x7e]\x00)*$')

def percent_printable(string):
    string = string.replace(b'\x00', b'')
    if len(string) == 0:
        return 0
    printable_count = 0
    for c in string:
        if (c <= 0x7f and c >= 0x20) or c == b'\n' or c == b'\r' or c == b'\t':
            printable_count += 1
    return float(printable_count)/float(len(string))

if options.num_threads is None:
    options.num_threads = max(min(cpu_count()//2, 24), 1)



class bcolors:
    if sys.stdout.isatty():
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
    else:
        HEADER = ''
        OKBLUE = ''
        OKGREEN = ''
        WARNING = ''
        FAIL = ''
        ENDC = ''
        BOLD = ''
        UNDERLINE = ''


class MatchShim:
    """Shim around a yara-x Rule so downstream code (filter_match, output
    rendering) can keep using the yara-python attribute names.

    Populated eagerly at scan time so the worker doesn't hand off references
    into scanner-owned memory. Match bytes (matched_data) are populated
    lazily by iterate_matches, which reads them from the scanned file.
    """
    __slots__ = ('rule', 'namespace', 'meta', 'tags', 'strings')

    def __init__(self, rule):
        self.rule = rule.identifier
        self.namespace = rule.namespace
        # yara-x returns metadata string values as either str or bytes depending
        # on the rule; normalize to str so downstream code doesn't have to
        # branch. Non-string types (int, float, bool) pass through unchanged.
        self.meta = {
            k: (v.decode('utf-8', errors='replace') if isinstance(v, (bytes, bytearray)) else v)
            for k, v in rule.metadata
        }
        self.tags = tuple(rule.tags)
        self.strings = [PatternShim(p) for p in rule.patterns]


class PatternShim:
    __slots__ = ('identifier', 'instances')

    def __init__(self, pattern):
        self.identifier = pattern.identifier
        self.instances = [InstanceShim(m) for m in pattern.matches]


class InstanceShim:
    """Offset + length of a match; matched_data is filled in by iterate_matches
    which knows the scanned file's path."""
    __slots__ = ('offset', 'length', 'matched_data')

    def __init__(self, m):
        self.offset = m.offset
        self.length = m.length
        self.matched_data = None


def rules_hash(file_list):
    """Content-based hash of the rule sources. Robust to git checkouts touching
    mtime without changing content. Benchmarked at ~17ms on 5.6 MiB of rules."""
    h = md5()
    for path in sorted(file_list):
        h.update(os.path.basename(path).encode())
        with open(path, 'rb') as fp:
            h.update(fp.read())
    return h.hexdigest()


def _humanize_time(sec):
    """Format a seconds float compactly. 0.0012 -> '1.2ms', 3.5 -> '3.5s'."""
    if sec >= 1.0:
        return '%.2fs' % sec
    if sec >= 0.001:
        return '%.1fms' % (sec * 1000)
    if sec >= 1e-6:
        return '%.1fus' % (sec * 1e6)
    return '%.0fns' % (sec * 1e9)


# Column width for the "rule" / "rule::pattern" column in the -P output.
# Wide enough to fit most real names without truncation on ice-53-scale
# rulesets; when we have to truncate, we prefer to shorten the namespace
# and rule identifiers and keep the pattern identifier intact -- the
# pattern is the actionable field for tuning.
_PROFILE_NAME_COL = 80


def _fmt_name_col(*parts, width=_PROFILE_NAME_COL):
    """Format identifiers joined by '::' into a fixed-width column.

    If the joined string overruns width, truncate the earlier parts with
    a horizontal-ellipsis (…) but keep the LAST part intact -- for
    the patterns table this is the pattern identifier, which is the
    field you actually want to see. Rules table calls this with just
    (namespace, rule) so 'rule' plays the role of the preserved part.
    """
    joined = '::'.join(parts)
    if len(joined) <= width:
        return joined.ljust(width)
    # Overrun. Reserve room for the last part in full plus its '::' separator.
    last = parts[-1]
    # Guard: if the pattern alone is longer than the width, just show it
    # truncated -- there's nothing better to do.
    if len(last) + 2 >= width:
        return last[:width]
    remaining = width - len(last) - 2  # room for '::last'
    head_parts = list(parts[:-1])
    # Distribute the remaining budget across the head parts. Separators
    # between them cost '::' per join.
    sep_cost = 2 * (len(head_parts) - 1) if len(head_parts) > 1 else 0
    budget_for_ids = remaining - sep_cost
    # Split evenly; give any extra chars to the first identifier since
    # namespaces are typically longer.
    per = max(4, budget_for_ids // len(head_parts))
    leftover = budget_for_ids - per * len(head_parts)
    trimmed = []
    for i, p in enumerate(head_parts):
        cap = per + (leftover if i == 0 else 0)
        if len(p) <= cap:
            trimmed.append(p)
        else:
            trimmed.append(p[: max(1, cap - 1)] + '…')
    return ('::'.join(trimmed) + '::' + last).ljust(width)


def _profile_supported():
    """Probe whether yara-x was built with the rules-profiling feature.

    yara_x.Scanner.slowest_rules raises RuntimeError with a build hint
    when the feature is off. We build a trivial scanner + call the method
    once at startup so the -P branch can fall back cleanly."""
    try:
        c = yx.Compiler()
        c.add_source('rule _yx_probe { condition: true }')
        yx.Scanner(c.build()).slowest_rules(0)
        return True
    except Exception:
        return False


def _collect_compile_warnings(parsed_signatures):
    """Compile each rule source with a fresh Compiler and collect its structured
    warnings. Returned as a dict keyed by (rule_name, pattern_ident) so we can
    annotate the profile table with per-pattern signals.

    Note: this is a *second* compile pass on top of build_rules(). It's cheap
    (yara-x compile is fast) and only runs under -P. Kept separate so we
    don't have to change build_rules' return signature."""
    warns = {}   # (rule, pattern) -> list[str]
    for path, _names in parsed_signatures:
        if os.path.isdir(path):
            candidates = recursive_all_files(path, 'yar')
        elif os.path.isfile(path):
            candidates = [path]
        else:
            continue
        for rulefile in candidates:
            try:
                c = yx.Compiler(relaxed_re_syntax=True)
                c.define_global('path', "TEMPORARY_EXT_VAR_VALUE")
                c.define_global('normalized_path', "TEMPORARY_EXT_VAR_VALUE")
                with open(rulefile) as fp:
                    c.add_source(fp.read(), origin=rulefile)
                c.build()
                for w in c.warnings():
                    # Text form looks like: "warning[slow_pattern]: ..."
                    # We match on the code and pull rule + pattern out of
                    # the location context. yara-x's warnings API is
                    # structured but somewhat opaque; parse conservatively.
                    text = str(w)
                    if 'slow_pattern' not in text:
                        continue
                    # yara-x embeds "rule <name>" and "$<pattern>" tokens
                    # in the rendered warning; grep them.
                    rm = re.search(r'rule\s+"([^"]+)"', text)
                    pm = re.search(r'string\s+"(\$[^"]+)"', text)
                    if rm and pm:
                        warns.setdefault((rm.group(1), pm.group(1)), []).append('may-slow')
            except Exception:
                # Compile errors are already surfaced by build_rules; ignore here.
                pass
    return warns


# Per-worker-process state for the -P parallel path. Populated by
# _profile_worker_init at worker startup; read on every chunk.
_profile_scanner = None


def _profile_worker_init(yxc_path):
    """ProcessPoolExecutor initializer for -P workers. Deserializes the
    .yxc rules blob once per worker so subsequent chunks reuse the Scanner."""
    global _profile_scanner
    with open(yxc_path, 'rb') as fp:
        rules = yx.Rules.deserialize_from(fp)
    _profile_scanner = yx.Scanner(rules)


def _profile_worker_chunk(files_chunk):
    """Scan a chunk of files in a worker process. Returns snapshot-of-just-this-chunk
    profiling data so the main can safely sum across chunks without double-counting.

    We call clear_profiling_data() BEFORE each chunk so the Scanner's cumulative
    counters restart at zero. The snapshot at the end of the chunk therefore only
    reflects the current chunk's work, and main can straightforwardly sum
    per-(ns, rule, pattern) time across all chunk results.
    """
    from time import perf_counter
    _profile_scanner.clear_profiling_data()
    per_file_cost = {}
    match_counts = {}  # (ns, rule, pattern) -> match count
    errors = []
    for fname in files_chunk:
        t0 = perf_counter()
        try:
            stats = _profile_scanner.scan_file_stats(fname)
        except Exception as e:
            errors.append((fname, str(e)))
            continue
        per_file_cost[fname] = perf_counter() - t0
        for key, cnt in stats.items():
            match_counts[key] = match_counts.get(key, 0) + cnt
    # Chunk-only snapshot (safe to sum because we clear'd at the start).
    slowest_rules = list(_profile_scanner.slowest_rules(1_000_000))
    slowest_patterns = list(_profile_scanner.slowest_patterns(1_000_000))
    return {
        'per_file_cost': per_file_cost,
        'match_counts': match_counts,
        'slowest_rules': slowest_rules,
        'slowest_patterns': slowest_patterns,
        'errors': errors,
    }


def run_profile_native(compiled_rules, yxc_path, scan_targets, options, warnings_by_pattern):
    """Native profiler using yara-x's Scanner.slowest_rules / slowest_patterns.

    Runs in parallel via ProcessPoolExecutor to scale across cores. Each worker
    owns its own Scanner (yara-x's Python binding does NOT release the GIL, so
    threading would serialize -- see fix for main scan phase). Files are
    dispatched in small chunks (default 100) so we get near-real-time progress
    updates and workload balances across workers naturally.

    Chunk-level aggregation avoids double-counting: each worker calls
    clear_profiling_data() before each chunk and returns the chunk's snapshot;
    main sums per-(ns, rule, pattern).
    """
    # Expand target dirs into files
    flat_files = []
    for t in scan_targets:
        if os.path.isdir(t):
            flat_files.extend(recursive_all_files(t))
        elif os.path.isfile(t):
            flat_files.append(t)
    if not flat_files:
        print('[!]\tNo files to scan after expanding targets: %s' % scan_targets)
        return

    threshold = options.threshold
    top_n = options.top_n
    MATCH_CAP = 1_000_000

    # Chunk size trades off progress-update granularity against overhead per
    # task submission / result marshal. Target ~4x num_workers chunks so
    # every worker gets multiple chunks (load balancing) but cap chunk size
    # at 100 files so we get sub-second progress ticks on large corpora.
    # On 160 files/8 workers: 5-file chunks, 32 chunks total.
    # On 160k files/8 workers: 100-file chunks (capped), ~1600 chunks total.
    CHUNK_SIZE = max(1, min(100, len(flat_files) // (options.num_threads * 4)))
    chunks = [flat_files[i:i + CHUNK_SIZE]
              for i in range(0, len(flat_files), CHUNK_SIZE)]

    # Aggregates on the main side.
    per_file_cost = {}
    match_counts = {}          # (ns, rule, pattern) -> total match count
    agg_pattern_time = {}      # (ns, rule, pattern) -> summed matching_time
    agg_rule_condition = {}    # (ns, rule) -> summed condition_exec_time

    is_tty = sys.stderr.isatty()
    profile_start = time()
    files_done = 0

    with ProcessPoolExecutor(
        max_workers=options.num_threads,
        initializer=_profile_worker_init,
        initargs=(yxc_path,),
    ) as ex:
        futures = [ex.submit(_profile_worker_chunk, c) for c in chunks]
        for fut in as_completed(futures):
            result = fut.result()
            per_file_cost.update(result['per_file_cost'])
            for k, v in result['match_counts'].items():
                match_counts[k] = match_counts.get(k, 0) + v
            for p in result['slowest_patterns']:
                key = (p['namespace'], p['rule'], p['pattern'])
                agg_pattern_time[key] = agg_pattern_time.get(key, 0) + p['matching_time']
            for r in result['slowest_rules']:
                key = (r['namespace'], r['rule'])
                agg_rule_condition[key] = agg_rule_condition.get(key, 0) + r['condition_exec_time']
            for fname, err in result['errors']:
                print('[!]\tFailed scanning %s: %s' % (fname, err))
            files_done += len(result['per_file_cost']) + len(result['errors'])
            # Progress
            if is_tty:
                sys.stderr.write('\rprofiled %d/%d files' % (files_done, len(flat_files)))
                sys.stderr.flush()
            elif files_done % 5000 < CHUNK_SIZE:  # rate-limit to ~every 5k files
                sys.stderr.write('profiled %d/%d files\n' % (files_done, len(flat_files)))
    if is_tty:
        sys.stderr.write('\n')
    wallclock = time() - profile_start

    # Build the slowest_rules / slowest_patterns lists the render code expects.
    # Rules: pattern time comes from summing the per-pattern aggregate up by
    # rule; condition time comes from the aggregate_rule_condition dict.
    # (yara-x's slowest_rules has a 100ms condition floor per chunk, so if a
    # rule's condition never crossed that in any single chunk, condition time
    # underrepresents. Pattern time is always accurate because slowest_patterns
    # has no floor after our lib patch.)
    agg_rule_pattern = {}
    for (ns, rule, _pat), t in agg_pattern_time.items():
        agg_rule_pattern[(ns, rule)] = agg_rule_pattern.get((ns, rule), 0) + t
    slowest_rules = sorted([
        {
            'namespace': ns,
            'rule': rule,
            'condition_exec_time': agg_rule_condition.get((ns, rule), 0),
            'pattern_matching_time': pat_time,
        }
        for (ns, rule), pat_time in agg_rule_pattern.items()
    ], key=lambda r: -(r['condition_exec_time'] + r['pattern_matching_time']))
    slowest_patterns = sorted([
        {'namespace': ns, 'rule': rule, 'pattern': pat, 'matching_time': t}
        for (ns, rule, pat), t in agg_pattern_time.items()
    ], key=lambda p: -p['matching_time'])

    # ---- Rules table --------------------------------------------------------
    total_rule_time = sum(r['condition_exec_time'] + r['pattern_matching_time']
                          for r in slowest_rules)
    mean_rule = (total_rule_time / len(slowest_rules)) if slowest_rules else 0
    # slowest_patterns has no time floor (our lib patch); slowest_rules
    # inherits yara-x's per-scan 100ms condition-time floor, so
    # condition_exec_time in the rules table underrepresents for rules with
    # only mild condition cost. Pattern time in the rules table is always
    # accurate because it's aggregated from per-pattern data.
    print('===== yarascan -P (%d files, %d chunks x%d workers, wallclock %.1fs) =====\n'
          % (len(flat_files), len(chunks), options.num_threads, wallclock))
    print('Rules (mean total cost %s, threshold >=%.0f%% of mean):'
          % (_humanize_time(mean_rule), threshold * 100))
    print('    %-10s %-6s  %-*s  notes' % ('cost', '%mean', _PROFILE_NAME_COL, 'rule'))
    n_shown = 0
    for r in slowest_rules:
        if top_n and n_shown >= top_n:
            break
        total = r['condition_exec_time'] + r['pattern_matching_time']
        pct = (total / mean_rule) if mean_rule else 0
        if pct < threshold:
            break  # sorted descending, so we can stop scanning
        notes = []
        if r['condition_exec_time'] > 0.001:
            notes.append('condition %s' % _humanize_time(r['condition_exec_time']))
        print('    %-10s %5.0f%%  %s  %s'
              % (_humanize_time(total), pct * 100,
                 _fmt_name_col(r['namespace'], r['rule']),
                 ' '.join(notes)))
        n_shown += 1
    if n_shown == 0:
        print('    (nothing above threshold)')
    print()

    # ---- Patterns table -----------------------------------------------------
    total_pat_time = sum(p['matching_time'] for p in slowest_patterns)
    mean_pat = (total_pat_time / len(slowest_patterns)) if slowest_patterns else 0
    print('Patterns (mean matching time %s, threshold >=%.0f%% of mean):'
          % (_humanize_time(mean_pat), threshold * 100))
    print('    %-10s %-6s  %-*s  notes' % ('cost', '%mean', _PROFILE_NAME_COL, 'rule::pattern'))
    n_shown = 0
    for p in slowest_patterns:
        if top_n and n_shown >= top_n:
            break
        pct = (p['matching_time'] / mean_pat) if mean_pat else 0
        if pct < threshold:
            break
        notes = []
        # Compile-time warning?
        if (p['rule'], p['pattern']) in warnings_by_pattern:
            notes.extend(warnings_by_pattern[(p['rule'], p['pattern'])])
        # Firehose / cap-hit?
        mc = match_counts.get((p['namespace'], p['rule'], p['pattern']), 0)
        if mc >= MATCH_CAP:
            notes.append('capped @%dM matches' % (mc // 1_000_000))
        elif mc >= 100_000:
            notes.append('%d matches' % mc)
        print('    %-10s %5.0f%%  %s  %s'
              % (_humanize_time(p['matching_time']), pct * 100,
                 _fmt_name_col(p['namespace'], p['rule'], p['pattern']),
                 ' '.join(notes)))
        n_shown += 1
    if n_shown == 0:
        print('    (nothing above threshold)')
    print()

    # ---- Top files by cost --------------------------------------------------
    if per_file_cost:
        top_files = sorted(per_file_cost.items(), key=lambda kv: -kv[1])[:5]
        print('--- top 5 files by wall time ---')
        for fname, c in top_files:
            if c > 0:
                print('    %-10s %s' % (_humanize_time(c), fname))



class Progress:
    """Live scan progress. Read by a ticker thread, written by the main
    completion loop. All fields are ints so += on a single writer thread is
    correct-enough (the ticker only reads and never observes a corrupted
    partial write in CPython)."""
    __slots__ = ('bytes_scanned', 'match_count', 'files_scanned', 'scan_size', 'start')

    def __init__(self, scan_size):
        self.bytes_scanned = 0
        self.match_count = 0
        self.files_scanned = 0
        self.scan_size = scan_size
        self.start = time()

    def render(self):
        elapsed = time() - self.start
        if elapsed <= 0 or self.bytes_scanned == 0:
            eta = 'N/A'
        else:
            bps = self.bytes_scanned / elapsed
            remaining_sec = max(0, int((self.scan_size - self.bytes_scanned) / bps))
            eta = str(datetime.timedelta(seconds=remaining_sec))
        sys.stderr.write('\r\x1b[K' + 'Progress: (%s/%s)\tETA: %s\tMatches: %d' % (
            human_size(self.bytes_scanned), human_size(self.scan_size),
            eta, self.match_count))
        sys.stderr.flush()


def _progress_ticker(progress, stop_event, interval=1.0):
    """Print progress every `interval` seconds until stop_event is set.
    stop_event.wait() lets us exit immediately on shutdown without
    burning through a full sleep cycle first."""
    while not stop_event.is_set():
        progress.render()
        stop_event.wait(interval)


# Per-worker-process state. Set up by _worker_init when a worker starts,
# then read by _worker_scan_one on each task. Kept as module globals so we
# don't have to ship Rules through the pickle path.
_worker_scanner = None
_worker_rule_filter = None


def _worker_init(yxc_path, worker_rule_filter):
    """Initialize a worker process. Called once when the worker starts.
    Loads the serialized rules from disk (one deserialize per process,
    reused across every scan the worker runs). yara-x's Scanner is
    single-threaded but each worker process only runs one scan at a time,
    so a per-process global Scanner is safe."""
    global _worker_scanner, _worker_rule_filter
    with open(yxc_path, 'rb') as fp:
        rules = yx.Rules.deserialize_from(fp)
    _worker_scanner = yx.Scanner(rules)
    _worker_rule_filter = worker_rule_filter


def _worker_scan_one(fname, size):
    """Run one scan in a worker process. Uses the per-process globals set
    by _worker_init. Returns (fname, size, matches_or_None, error_string_or_None)."""
    try:
        results = _worker_scanner.scan_file(fname)
        matches = [MatchShim(r) for r in results.matching_rules]
        matches = [m for m in matches
                   if not filter_match(m, fname, rule_filter=_worker_rule_filter)]
        return fname, size, matches, None
    except Exception as e:
        return fname, size, None, str(e)


def scan_one(rules, fname, size):
    """Thread-mode fallback (kept for single-file quick scans / debugging)."""
    try:
        scanner = yx.Scanner(rules)
        results = scanner.scan_file(fname)
        matches = [MatchShim(r) for r in results.matching_rules]
        matches = [m for m in matches if not filter_match(m, fname)]
        return fname, size, matches, None
    except Exception as e:
        return fname, size, None, e


#catch ctrl-c (SIGINT) and exit
def signal_handler(signal,frame):
    sys.exit(0)

def human_size(nbytes):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    if nbytes == 0: return '0 B'
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%s' % float('%.3g' % nbytes)).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

def filter_match(match, fname, rule_filter=None):
    if rule_filter is None:
        # Fall back to the module-level default (main-block scenario).
        rule_filter = globals().get('rule_filter', {})
    try:
        # Per-source rule filter from '-S path::rule_name[,rule_name...]'.
        if rule_filter:
            allowed = rule_filter.get('*')
            if allowed is None:
                allowed = rule_filter.get(match.namespace)
            if allowed is not None and match.rule not in allowed:
                return True
        for key in ['file_name', 'full_path']:
            if key in match.meta:
                passed = False         
                negate = False
                value = match.meta[key].lower()
                if value.startswith('!'):
                    value = value[1:]
                    negate = True
                for search in value.split(','):
                    if key == 'file_name':
                        fname = os.path.basename(fname)
                    if 'sub:' in search:
                        ns = search.replace('sub:', '')
                        if ns in fname.lower():
                            #print(f'{ns} in {fname}')
                            passed = True
                    else:
                        if (search == fname.lower() and not negate) or (search != fname.lower() and negate):
                            passed = True

                if (not passed and not negate) or (passed and negate):
                    return True 
                """
                if not passed:
                    if negate:
                        return False
                    else:
                        return True
                """

        if 'file_ext' in match.meta:
            passed = False
            negate = False
            value = match.meta['file_ext'].lower()
            if value.startswith('!'):
                value = value[1:]
                negate = True
            for search in value.split(','):
                if fname.lower().endswith(search):
                    passed = True
            if (not passed and not negate) or (passed and negate):
                return True 
            
        return False
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        



def collect_rule_files(parsed_signatures):
    """Expand parsed -S entries into (file_list, rule_filter).

    parsed_signatures: iterable of (path, rule_names_or_None).
    Returns (files, rule_filter) where rule_filter maps namespace (rulefile
    basename without .yar) -> set of allowed rule names. Namespaces absent
    from the map are unrestricted. A namespace that appears once without a
    filter overrides any restrictions added for the same namespace elsewhere.
    """
    files, seen = [], set()
    restricted = {}
    unrestricted = set()
    for sig, rule_names in parsed_signatures:
        if os.path.isdir(sig):
            candidates = recursive_all_files(sig, 'yar')
        elif os.path.isfile(sig):
            candidates = [sig]
        else:
            if options.user_provided_signatures:
                print('[!]\tSignature path does not exist: %s' % (sig))
            continue
        for f in candidates:
            real = os.path.realpath(f)
            if real not in seen:
                seen.add(real)
                files.append(f)
            ns = os.path.splitext(os.path.basename(f))[0]
            if rule_names is None:
                unrestricted.add(ns)
            else:
                restricted.setdefault(ns, set()).update(rule_names)
    rf = {ns: names for ns, names in restricted.items() if ns not in unrestricted}
    return files, rf

def build_rules(parsed_signatures):
    """Compile all rule sources into a yara_x.Rules object, caching to /tmp/<content-hash>.yxc.

    yara-x's Compiler tolerates errors: add_source() raises on the first
    error in a source, but you can catch it and keep adding more sources.
    So we do a single pass with per-file try/except rather than a
    test_compile step + batch compile.

    Returns (compiled_rules, rule_filter, yxc_path). yxc_path is on-disk
    so worker processes in a ProcessPoolExecutor can deserialize it
    without shipping a Rules object through pickle.
    """
    file_list, this_rule_filter = collect_rule_files(parsed_signatures)
    _hash = rules_hash(file_list)
    path = os.path.join('/tmp/', '%s.yxc' % (_hash))
    if os.path.isfile(path):
        print('[*]\tUp to date compiled rules already exist at %s. Using those' % (path))
        with open(path, 'rb') as fp:
            return yx.Rules.deserialize_from(fp), this_rule_filter, path

    start = time()
    c = yx.Compiler(relaxed_re_syntax=True)
    c.define_global('path', "TEMPORARY_EXT_VAR_VALUE")
    c.define_global('normalized_path', "TEMPORARY_EXT_VAR_VALUE")
    ok = 0
    for rulefile in file_list:
        ns = os.path.splitext(os.path.basename(rulefile))[0]
        c.new_namespace(ns)
        try:
            with open(rulefile) as fp:
                c.add_source(fp.read(), origin=rulefile)
            ok += 1
        except Exception as e:
            print('rule %s failed to compile! Error: %s' % (rulefile, e))
    try:
        compiled_rules = c.build()
    except Exception as e:
        print('Exception in Compiler.build(): %s' % e)
        raise
    elapsed = time() - start
    try:
        with open(path, 'wb') as fp:
            compiled_rules.serialize_into(fp)
        os.chmod(path, 0o666)
    except Exception as e:
        print('[!]\tFailed to save compiled rules %s: %s' % (path,e))
    compiled_size = os.stat(path).st_size

    if options.performance:
        print('[*]\tCompiled %s / %s rule files in %s seconds.' % (ok, len(file_list), round(elapsed,2)))
        print('[*]\tCompiled rule size is %s' % (human_size(compiled_size,)))
    return compiled_rules, this_rule_filter, path

def offset_to_line(fname, offset, match_len):
    size = os.stat(fname).st_size
    block_size = 1024
    idx = offset - block_size
    if idx < 0:
        idx = 0

    with open(fname, 'rb') as fp:
        while True:
            to_read = min(offset-idx, block_size)
            fp.seek(idx)
            #print 'reading %s bytes from %s' % (to_read, idx)
            buf = fp.read(to_read)
            start_line_idx = idx + buf.rfind('\n')
            #print 'found newline @ %s' % (start_line_idx)
            if start_line_idx != -1:
                fp.seek(start_line_idx+1)
                to_read = offset-start_line_idx-1
                #print 'before = %s-%s' % (start_line_idx+1, start_line_idx+1+to_read)
                before = fp.read(to_read)
                break
            if idx == 0:
                fp.seek(0)
                before = fp.read(offset)
                break
            idx -= block_size
        
        while True:
            idx = offset + match_len
            fp.seek(idx)
            to_read = min(block_size, size-idx)
            #print 'reading %s bytes from %s' % (to_read, idx)
            buf = fp.read(to_read)
            end_line_idx = idx + buf.find('\n')
            #print 'found newline @ %s' % (end_line_idx)
            if end_line_idx != -1:
                fp.seek(offset+match_len)
                after = fp.read(end_line_idx - (offset+match_len))
                break
            if idx >= size:
                fp.seek(offset+match_len)
                after = fp.read()
                break
            idx += block_size

    #print ('[%s] [%s]' % (before, after)).replace('\n', '')
    return before, after
            

def hexlify(string):
    string = binascii.hexlify(string).upper().decode()
    return ' '.join(string[i:i+2] for i in range(0, len(string), 2))

def disassemble(fname, bytedict, prefer='32', context=5):
    #TODO Or just read in the original file and pD at the right offset. We could even output the entire function
    # if the match falls fully within it and it is small enough.
    #TODO Color line red if part of match, yellow if it falls in the middle of the instruction
    #create a temporary R2 instance
    bytestring = b''.join([bytedict['before'], bytedict['string'], bytedict['after']])
    code_length = len(bytestring)
    match_start = len(bytedict['before'])
    match_end = len(bytedict['before']) + len(bytedict['string'])

    offset_re = re.compile('0x([0-9a-f]{8})',re.IGNORECASE)
    r2 = r2pipe.open('malloc://%s' % (code_length))
    code = ''
    order = ['64', '32']
    order.remove(prefer)
    order.insert(0,prefer)
    bytestring = binascii.hexlify(bytestring).decode()
    try:
        r2.cmd('e asm.bits = %s' % (order[0]))
        r2.cmd('wx %s' % (bytestring))
        code = r2.cmd('pD %s' % (code_length))
        #code = r2.cmd('pad %s' % bytestring)
    except:
        r2.cmd('e asm.bits = %s' % (order[1]))
        r2.cmd('wx %s' % (bytestring))
        code = r2.cmd('pD %s' % (code_length))
        #code = r2.cmd('pad %s' % bytestring)

    #Take the disassembled block, extract the offset for each instruction and colorize those that are part of the actual match
    colorized = []
    for line in code.splitlines():
        try:
            offset = int(offset_re.search(line).group(0),16)
        except Exception as e:
            continue
            
        if offset >= match_start and offset < match_end:
            colorized.append(bcolors.FAIL + line +  bcolors.ENDC)
        else:
            colorized.append(line)

    r2.cmd('quit')
    return '\n'.join(colorized)

def clean_string(string):
    return string.decode('latin1').encode('unicode_escape').decode('utf-8')#.replace('\r', '\\r').replace('\n', '\\n')

def format_string_output(string, offset=None, fname=None, context=0, line=False):
    hex_format = False
    before = b""
    after = b""
    if offset and fname and line:
        #print '***%s***' % (string.replace('\n',''))
        before, after = offset_to_line(fname, offset, len(string))
        
    elif offset is not None and fname and context > 0:
        try:
            size = os.stat(fname).st_size
            with open(fname,'rb') as fp:
                bytes_before=min(context, offset-context)
                if bytes_before > 0:
                    fp.seek(offset - bytes_before)
                    before = fp.read(bytes_before)#.decode('unicode_escape')
                else:
                    fp.seek(0)
                    before = fp.read(offset)
                bytes_after=min(context, size-offset)
                if bytes_after > 0:
                        #print 'seek to %x + %x' % (offset, len(string))
                    fp.seek(offset+len(string))
                    after = fp.read(bytes_after)#.decode('unicode_escape')
                        #print 'bytes after = %s' % (hexlify(after))
                else:
                    after = b''

            #fseek and grab context bytes, add color markers
            pass
        except:
            print('Failed to get context for %s %s %s' % (fname, offset, string))
            import traceback
            print(traceback.format_exc())
            
    wide = False 
    if printable_wide.match(string):
        rtn = string.decode('utf-16le')
        wide = True
    elif percent_printable(before + string + after) > .75:
        rtn = clean_string(string)
    else:
        rtn = hexlify(string)
        hex_format = True

    raw_bytes = {'before': before, 'string': string, 'after': after}
    if offset and fname and context > 0 or line:
        if hex_format:
            rtn = '%s %s%s%s %s' % (hexlify(before), bcolors.FAIL, rtn, bcolors.ENDC, hexlify(after))
        else:
            rtn = '%s%s%s%s%s' % (clean_string(before), bcolors.FAIL, rtn, bcolors.ENDC, clean_string(after))
    return raw_bytes, hex_format, wide, rtn
    

def preexec_function():
    # Ignore SIGINT by setting handler to SIG_IGN
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def iterate_matches(patterns, fname):
    """Yield (offset, identifier, matched_data) for each match instance.

    yara-x's Match only exposes offset+length; we read matched_data from the
    scanned file here. Opens the file once per invocation (typically per
    matching rule per file) rather than once per match.
    """
    # collect (offset, length, identifier) so we can do one file read.
    per_instance = []
    for pattern in patterns:
        for inst in pattern.instances:
            per_instance.append(inst)
    if not per_instance:
        return
    try:
        with open(fname, 'rb') as fp:
            for inst in per_instance:
                fp.seek(inst.offset)
                inst.matched_data = fp.read(inst.length)
    except Exception:
        # If reading fails for any reason, downstream will surface the empty bytes.
        pass
    for pattern in patterns:
        name = pattern.identifier
        for inst in pattern.instances:
            yield inst.offset, name, inst.matched_data or b''


if __name__ == '__main__':
    if options.disassemble:
        import r2pipe

    if options.performance:
        print('[*]\tScanning with %s threads.' % (options.num_threads))

    # Collect scan targets and pre-compute total size for progress reporting.
    scanlist = []
    for arg in args:
        scanlist += recursive_all_files(arg)
    jobs = []       # list of (fname, size)
    scan_size = 0
    for f in scanlist:
        try:
            size = os.stat(f).st_size
        except OSError:
            continue
        if size != 0:
            jobs.append((f, size))
            scan_size += size

    # -P uses yara-x's native profiling API (Scanner.slowest_rules /
    # slowest_patterns). Requires a wheel built with `maturin build
    # --features rules-profiling`; see README.
    if options.profile:
        if not _profile_supported():
            print('[!]\tThis yara-x wheel was built without the rules-profiling feature.')
            print('[!]\tBuild the profiling-enabled wheel:')
            print('[!]\t    cd ~/tools/yara-x/py && maturin build --release --features rules-profiling')
            print('[!]\t    pip install --user --force-reinstall --no-deps ../target/wheels/yara_x-*.whl')
            sys.exit(1)
        compiled_rules, rule_filter, yxc_path = build_rules(options.parsed_signatures)
        warnings_by_pattern = _collect_compile_warnings(options.parsed_signatures)
        run_profile_native(compiled_rules, yxc_path, args, options, warnings_by_pattern)
        sys.exit(0)
    elif len(options.parsed_signatures) == 1 and os.path.isfile(options.parsed_signatures[0][0]) \
            and options.parsed_signatures[0][0].endswith('.yxc'):
        # Precompiled yara-x rules fast path
        yxc_path, names = options.parsed_signatures[0]
        try:
            with open(yxc_path, 'rb') as fp:
                compiled_rules = yx.Rules.deserialize_from(fp)
            rule_filter = {'*': names} if names else {}
        except Exception:
            compiled_rules, rule_filter, yxc_path = build_rules(options.parsed_signatures)
    else:
        compiled_rules, rule_filter, yxc_path = build_rules(options.parsed_signatures)

    if options.categorize_dir:
        os.makedirs(options.categorize_dir, exist_ok=True)

    # Scan jobs. Each worker thread lazily creates one yx.Scanner (thread-local)
    # and reuses it across scans -- yara-x Scanners are single-threaded but
    # cheap to create once per thread.
    progress = Progress(scan_size)
    results = []
    is_tty_stderr = sys.stderr.isatty()

    # Ticker thread for real-time progress. Only started when -p is set and
    # stderr is a tty -- piped/captured runs get no ticker output.
    stop_ticker = threading.Event()
    ticker_thread = None
    if options.performance and is_tty_stderr:
        ticker_thread = threading.Thread(
            target=_progress_ticker, args=(progress, stop_ticker), daemon=True)
        ticker_thread.start()

    # yara-x's Python binding does not release the GIL during scan_file, so
    # threading serializes at ~100% single-thread CPU. We use processes to
    # get real parallelism -- each worker deserializes the .yxc once at
    # startup and reuses the same Scanner for every scan it runs.
    try:
        with ProcessPoolExecutor(
            max_workers=options.num_threads,
            initializer=_worker_init,
            initargs=(yxc_path, rule_filter),
        ) as ex:
            futures = [ex.submit(_worker_scan_one, f, sz) for f, sz in jobs]
            for fut in as_completed(futures):
                fname, size, matches, err = fut.result()
                progress.bytes_scanned += size
                progress.files_scanned += 1
                if err is not None:
                    print('Exception scanning %s (%s): %s' % (fname, human_size(size), err))
                    continue
                if matches:
                    progress.match_count += 1
                    results.append({'matches': matches, 'fname': fname})
                elif options.negative:
                    results.append({'matches': [], 'fname': fname})
    except KeyboardInterrupt:
        print('\nInterrupted; outputting results collected so far')
    finally:
        stop_ticker.set()
        if ticker_thread is not None:
            ticker_thread.join(timeout=1.5)
    if options.performance and is_tty_stderr:
        progress.render()
        sys.stderr.write('\n')

    if options.json:
        json_results = {}
        for res in results:
            match_map = {m.rule: m.meta for m in res['matches']}
            if match_map:
                json_results[res['fname']] = match_map
        with open(options.json, 'w') as fp:
            json.dump(json_results, fp)
    else:
        for res in results:
            if not res['matches'] and not options.negative:
                continue
            header = False
            # With -n, always emit the filename for no-match files so they can
            # be picked up in "which files had zero hits" surveys.
            if not res['matches'] and options.negative:
                print(res['fname'])
                continue

            for matchobj in res['matches']:
                if not filter_match(matchobj, res['fname']):
                    if not header:
                        print(res['fname'])
                        header = True
                    if options.categorize_dir:
                        d = os.path.join(options.categorize_dir, matchobj.rule)
                        os.makedirs(d, exist_ok=True)
                        shutil.copy(res['fname'], d) 
                    strings = {}
                    if options.strings:
                        for offset, name, data in iterate_matches(matchobj.strings, res['fname']):
                            raw_bytes, printable, wide, string = format_string_output(string=data, offset=offset, fname=res['fname'], context=options.context, line=options.line)
                            string = string.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                            if name not in strings:
                                strings[name] = {}
                            if string not in strings[name]:
                                if wide:
                                    strings[name][string] = {'bytes': raw_bytes, 'offsets': [], 'printable': printable, 'wide': True}
                                else:
                                    strings[name][string] = {'bytes': raw_bytes, 'offsets': [], 'printable': printable, 'wide': False}
                            if offset not in strings[name][string]['offsets']:
                                strings[name][string]['offsets'].append(offset)
                    
                    print('    %s/%s' % (matchobj.namespace, matchobj.rule))
                        
                    if options.strings:
                        for name, string_dict in strings.items():
                            for string in list(string_dict.keys())[:options.max_strings]:
                                offsets = string_dict[string]['offsets']
                                for offset in offsets[:options.max_offsets]:
                                    if string_dict[string]['wide'] and options.wide:
                                        string = string + bcolors.OKBLUE + ' utf-16le' + bcolors.ENDC
                                    if options.offset: 
                                        try:
                                            print('        %s:0x%x:    %s' % (name, offset, string))
                                        except Exception as e:
                                            print('error: %s' % (e))
                                    else:
                                        try:
                                            print('        %s' % (string))
                                            continue
                                        except Exception as e:
                                            print('error: %s' % (e))
                                    if options.disassemble and string_dict[string]['printable']:
                                        try:
                                            dis = disassemble(res['fname'], string_dict[string]['bytes'], options.disassemble, context=options.context)
                                            print(' '*12 + dis.replace('\n', '\n' + ' '*12))
                                        except Exception as e:
                                            print('Failed to disassemble %s: %s' % (string_dict[string]['bytes'], e))
                                            import traceback
                                            print(traceback.format_exc())
                    print()
    
    if options.performance:
        elapsed = time() - progress.start
        rate = human_size(progress.bytes_scanned / elapsed) if elapsed > 0 else 'N/A'
        print('[*]\tProcessed %s files in %s seconds. %s/s' % (
            progress.files_scanned, round(elapsed, 2), rate))
