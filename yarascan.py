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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        help="threshold used in profiling to determine if a rule's runtime "
             "is abnormal. Default=3, which returns any rules taking 3x "
             "longer than average or 1/3x or less of average")
    p.add_argument('-p', '--performance', action='store_true', default=False,
        help='Enable progress and performance profiling')
    p.add_argument('-P', '--Profile', dest='profile', action='store_true', default=False,
        help='Profile rules searching for performance issues, overlapping '
             'detection, and error 30')
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


# Path to a separately-built yara CLI compiled with --enable-profiling.
# yara-python 4.5.x's profiling_info() is broken against current libyara
# (issue VirusTotal/yara-python#155), so -P shells out to this binary.
# Build instructions live in the README. Falls back to a notice if missing.
PROFILED_YARA_BIN = os.path.expanduser(
    '~/tools/yara-scanner/yara-profiling/bin/yara')


def run_profile_via_cli(rule_files, scan_targets, threshold):
    """Run the profiled yara CLI against scan_targets and report per-rule outliers.

    rule_files    : list of source .yar rule file paths, or (namespace, path) pairs.
                    Passed as positional [ns:]path args to the CLI. Compiled
                    format is not portable between yara-python/yara-x and the
                    standalone CLI, so we always feed source files.
    scan_targets  : positional list of files/dirs from argv. Dirs are expanded.
    threshold     : -T value. Rule is flagged if cost/mean_cost > threshold.
    """
    import subprocess

    if not os.path.exists(PROFILED_YARA_BIN):
        print('[!]\tProfiled yara CLI not found at %s' % PROFILED_YARA_BIN)
        print('[!]\tBuild it with `./configure --enable-profiling '
              '--prefix=~/tools/yara-scanner/yara-profiling && make install` '
              '(see README). Skipping -P.')
        return

    # Expand dirs into a flat file list. The CLI only emits profiling output
    # when invoked against a single file (its directory-scan branch uses
    # multiple scanner threads and skips the profiling print). So we iterate
    # in Python and accumulate per-rule costs across invocations.
    flat_files = []
    for t in scan_targets:
        if os.path.isdir(t):
            flat_files.extend(recursive_all_files(t))
        elif os.path.isfile(t):
            flat_files.append(t)
    if not flat_files:
        print('[!]\tNo files to scan after expanding targets: %s' % scan_targets)
        return

    # Build the [ns:]path positional args. Namespace defaults to file basename
    # without extension (same convention as compile_rule/build_rules).
    rule_args = []
    for entry in rule_files:
        if isinstance(entry, tuple):
            ns, path = entry
        else:
            ns = os.path.splitext(os.path.basename(entry))[0]
            path = entry
        rule_args.append('%s:%s' % (ns, path))

    is_tty = sys.stderr.isatty()
    profile_start = time()
    try:
        block_re = re.compile(r'^\s*(\d+)\s+(\S+):(\S+):\s*$')
        results = {}  # accumulator: <ns>::<rule> -> summed cost
        per_file_cost = {}  # fname -> total cost summed across rules
        for i, fname in enumerate(flat_files, 1):
            try:
                proc = subprocess.run(
                    [PROFILED_YARA_BIN, '-w'] + rule_args + [fname],
                    capture_output=True, text=True, errors='replace')
            except Exception as e:
                print('[!]\tFailed scanning %s: %s' % (fname, e))
                continue
            in_block = False
            file_cost = 0
            for line in proc.stdout.splitlines():
                if 'PROFILING INFORMATION' in line:
                    in_block = True
                    continue
                if in_block and line.startswith('=='):
                    in_block = False
                    continue
                if not in_block:
                    continue
                m = block_re.match(line)
                if m:
                    cost = int(m.group(1))
                    key = '%s::%s' % (m.group(2), m.group(3))
                    results[key] = results.get(key, 0) + cost
                    file_cost += cost
            per_file_cost[fname] = file_cost
            # Progress: only rewrite on TTY; otherwise print sparsely so
            # piped/captured output stays readable.
            if is_tty:
                sys.stderr.write('\rprofiled %d/%d files' % (i, len(flat_files)))
                sys.stderr.flush()
            elif i % 50 == 0 or i == len(flat_files):
                sys.stderr.write('profiled %d/%d files\n' % (i, len(flat_files)))
        if is_tty:
            sys.stderr.write('\n')
        profile_elapsed = time() - profile_start

        if not results:
            print('[!]\tNo profiling info captured. CLI exit=%s' % proc.returncode)
            tail = '\n'.join(proc.stdout.splitlines()[-20:])
            if proc.stderr.strip():
                print('--- stderr (tail) ---\n%s' % '\n'.join(
                    proc.stderr.splitlines()[-20:]))
            if tail:
                print('--- stdout (tail) ---\n%s' % tail)
            return

        # Mean of non-zero costs (zero-cost rules dominate the count when only
        # a few rules actually fired; including them yields a tiny mean that
        # makes every non-trivial rule look like an "outlier").
        nonzero = [c for c in results.values() if c > 0]
        if not nonzero:
            print('[!]\tAll rules profiled at cost=0. Nothing to compare.')
            return
        mean_cost = sum(nonzero) / len(nonzero)

        # Only flag SLOW outliers. The "fast outlier" check from the legacy
        # implementation flooded the output with rules at cost=1-10 (rules
        # whose atoms matched once or twice but the condition didn't fire)
        # because the mean is heavily skewed by a handful of very-expensive
        # rules. Symmetric-around-mean thresholding doesn't survive that
        # skew, and slow outliers are what we actually want to find.
        outliers = []
        for key, cost in results.items():
            if cost == 0:
                continue
            relative = cost / mean_cost
            if relative > threshold:
                outliers.append((relative, key, cost))
        outliers.sort(reverse=True)

        print('===== yarascan -P: per-rule outliers '
              '(threshold=%g, mean nonzero cost=%.0f, n_rules=%d, '
              'files=%d, profile-wallclock=%.1fs) ====='
              % (threshold, mean_cost, len(results), len(flat_files),
                 profile_elapsed))
        for relative, key, cost in outliers:
            print('{0:60}\t{1:>14}\t{2:>8.1f}%'.format(key, cost,
                                                       relative * 100.0))
        if not outliers:
            print('(no outliers above threshold)')

        # Top files by total cost -- useful for "which file is making the
        # corpus expensive?" pivoting after rule-level results.
        if per_file_cost:
            top_files = sorted(per_file_cost.items(), key=lambda kv: -kv[1])[:5]
            print('\n--- top 5 files by total cost ---')
            for fname, c in top_files:
                if c > 0:
                    print('{0:>14}\t{1}'.format(c, fname))
    except Exception as e:
        print('[!]\tprofile invocation failed: %s' % e)



_thread_local = threading.local()


def _get_scanner(rules):
    """One yara-x Scanner per worker thread (Scanner is not thread-safe;
    Rules is). Reused across submissions so we don't pay Scanner init per file."""
    s = getattr(_thread_local, 'scanner', None)
    if s is None:
        s = yx.Scanner(rules)
        _thread_local.scanner = s
    return s


def scan_one(rules, fname, size):
    """Scan a single file. Returns (fname, size, matches_or_None, error_or_None)."""
    try:
        scanner = _get_scanner(rules)
        scan_results = scanner.scan_file(fname)
        matches = [MatchShim(r) for r in scan_results.matching_rules]
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

def filter_match(match, fname):
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

    Returns (compiled_rules, rule_filter) so callers can thread rule_filter
    through explicitly rather than relying on a module-level global.
    """
    file_list, this_rule_filter = collect_rule_files(parsed_signatures)
    _hash = rules_hash(file_list)
    path = os.path.join('/tmp/', '%s.yxc' % (_hash))
    if os.path.isfile(path):
        print('[*]\tUp to date compiled rules already exist at %s. Using those' % (path))
        with open(path, 'rb') as fp:
            return yx.Rules.deserialize_from(fp), this_rule_filter

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
    return compiled_rules, this_rule_filter

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

    # -P short-circuits: shells out to the profiled yara CLI with the source
    # rule files as [ns:]path positional args. Compiled-rules format is not
    # portable between yara-x's Rules and the standalone CLI's .cyar.
    if options.profile:
        rule_files, rule_filter = collect_rule_files(options.parsed_signatures)
        run_profile_via_cli(rule_files, args, options.threshold)
        sys.exit(0)
    elif len(options.parsed_signatures) == 1 and os.path.isfile(options.parsed_signatures[0][0]) \
            and options.parsed_signatures[0][0].endswith('.yxc'):
        # Precompiled yara-x rules fast path
        path, names = options.parsed_signatures[0]
        try:
            with open(path, 'rb') as fp:
                compiled_rules = yx.Rules.deserialize_from(fp)
            rule_filter = {'*': names} if names else {}
        except Exception:
            compiled_rules, rule_filter = build_rules(options.parsed_signatures)
    else:
        compiled_rules, rule_filter = build_rules(options.parsed_signatures)

    if options.categorize_dir:
        os.makedirs(options.categorize_dir, exist_ok=True)

    # Scan jobs. Each worker thread lazily creates one yx.Scanner (thread-local)
    # and reuses it across scans -- yara-x Scanners are single-threaded but
    # cheap to create once per thread.
    start = time()
    bytes_scanned = 0
    match_count = 0
    files_scanned = 0
    results = []
    is_tty_stderr = sys.stderr.isatty()

    def _report_progress():
        elapsed = time() - start
        if elapsed <= 0 or bytes_scanned == 0:
            eta = 'N/A'
        else:
            bps = bytes_scanned / elapsed
            eta = str(datetime.timedelta(seconds=int((scan_size - bytes_scanned) / bps)))
        sys.stderr.write('\r\x1b[K' + 'Progress: (%s/%s)\tETA: %s\tMatches: %d' % (
            human_size(bytes_scanned), human_size(scan_size), eta, match_count))
        sys.stderr.flush()

    try:
        with ThreadPoolExecutor(max_workers=options.num_threads) as ex:
            futures = [ex.submit(scan_one, compiled_rules, f, sz) for f, sz in jobs]
            for fut in as_completed(futures):
                fname, size, matches, err = fut.result()
                bytes_scanned += size
                files_scanned += 1
                if err is not None:
                    print('Exception scanning %s (%s): %s' % (fname, human_size(size), err))
                    continue
                if matches:
                    match_count += 1
                    results.append({'matches': matches, 'fname': fname})
                elif options.negative:
                    results.append({'matches': [], 'fname': fname})
                if options.performance and is_tty_stderr:
                    _report_progress()
    except KeyboardInterrupt:
        print('\nInterrupted; outputting results collected so far')
    if options.performance and is_tty_stderr:
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
        elapsed = time() - start
        print('[*]\tProcessed %s files in %s seconds. %s/s' % (files_scanned,round(elapsed,2), human_size(bytes_scanned/elapsed)))
