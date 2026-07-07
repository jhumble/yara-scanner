#!/usr/bin/env python3.13
import os
import yara
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
from threading import Thread, Lock, current_thread
from queue import Queue
from multiprocessing import Pool, cpu_count
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


def rules_hash(file_list):
    rtn = {}
    to_hash = ""
    for path in sorted(file_list):
        to_hash += '%s%s' % (os.path.basename(path),str(os.path.getmtime(path)))
    return md5(to_hash.encode()).hexdigest()


# Path to a separately-built yara CLI compiled with --enable-profiling.
# yara-python 4.5.x's profiling_info() is broken against current libyara
# (issue VirusTotal/yara-python#155), so -P shells out to this binary.
# Build instructions live in the README. Falls back to a notice if missing.
PROFILED_YARA_BIN = os.path.expanduser(
    '~/tools/yara-scanner/yara-profiling/bin/yara')


def run_profile_via_cli(compiled_rules, scan_targets, threshold):
    """Run the profiled yara CLI against scan_targets and report per-rule outliers.

    compiled_rules : yara.Rules already-compiled by build_rules. Saved to a
                     temp .cyar; the CLI loads it via -C.
    scan_targets   : positional list of files/dirs from argv. -r is passed so
                     dirs traverse recursively; files pass through fine.
    threshold      : -T value. Rule is flagged if cost / mean_cost is above
                     threshold or below 1/threshold.
    """
    import subprocess
    import tempfile

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

    cyar = tempfile.NamedTemporaryFile(suffix='.cyar', delete=False).name
    is_tty = sys.stderr.isatty()
    profile_start = time()
    try:
        compiled_rules.save(cyar)
        block_re = re.compile(r'^\s*(\d+)\s+(\S+):(\S+):\s*$')
        results = {}  # accumulator: <ns>::<rule> -> summed cost
        per_file_cost = {}  # fname -> total cost summed across rules
        for i, fname in enumerate(flat_files, 1):
            try:
                proc = subprocess.run(
                    [PROFILED_YARA_BIN, '-C', cyar, fname],
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

    finally:
        try:
            os.unlink(cyar)
        except Exception:
            pass



def worker():
    global TERMINATE_EARLY
    global result_queue
    global bytes_scanned
    global files_scanned
    global match_count
    global lock

    yara.set_config(max_match_data=4096)
    #print 'worker %s started' % (current_thread())
    while True: #not scan_queue.empty():
        if TERMINATE_EARLY:
            #print 'worker %s terminating' % (current_thread())
            return
        job = scan_queue.get()
        #print 'Worker %s: processing job %s' % (current_thread(), job)
        if job is None:
            scan_queue.task_done()
            #print 'worker %s exiting' % (current_thread())
            return
        try:
            matches = compiled_rules.match(job['fname'])
            # filter out any matches that do not apply
            matches = [match for match in matches if not filter_match(match, job['fname'])]
            result_queue.put({'matches': matches, 'fname': job['fname']})
            lock.acquire()
            if matches:
                match_count += 1
            bytes_scanned += job['size']
            files_scanned += 1
            lock.release()
        except Exception as e:
            print('Exception scanning %s (%s): %s' % (job['fname'],human_size(job['size']),e))
            pass
        scan_queue.task_done()
    #print 'worker %s exiting' % (current_thread())
    #return
        
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
        



def monitor_thread(worker_threads):
    start = time()
    global scan_queue
    global bytes_scanned
    global result_queue
    global scan_size
    global scan_files
    while True:
        if TERMINATE_EARLY:
            break
        working = 0
        for t in worker_threads:
            if t.is_alive():
                working += 1
        delta = time() - start
        #print 'completed = %s working = %s' % (completed,working)
        try:
            bytes_per_sec = bytes_scanned/delta*1.0
            estimated_sec = (scan_size - bytes_scanned)/bytes_per_sec
            estimated_time = str(datetime.timedelta(seconds=int(estimated_sec)))
        except:
            estimated_time = 'N/A'
        sys.stderr.write('\r' + ' '*100)
        sys.stderr.flush()
        sys.stderr.write('\r')
        sys.stderr.flush()
        sys.stderr.write('Progress: (%s/%s)\t\tTime Remaining: %s\t\tMatches: %s' % (human_size(bytes_scanned), human_size(scan_size), estimated_time, match_count))
        sys.stderr.flush()
        if scan_queue.qsize() == 0 and working == 0:
            break
        sleep(1)
    print('\n')
    elapsed = time() - start

def compile_rule(rulefile):
    """Compile a single rule file. Returns None if compilation fails."""
    try:
        key = os.path.splitext(os.path.split(rulefile)[1])[0]
        yara.compile(filepaths={key: rulefile},
                     externals={'path': "TEMPORARY_EXT_VAR_VALUE",
                                'normalized_path': "TEMPORARY_EXT_VAR_VALUE"})
        return {'key': key, 'rulefile': rulefile}
    except Exception as e:
        print('rule %s failed to compile! Error: %s' % (rulefile, e))
    return None

def test_compile(file_list):
    """Test-compile each rule in parallel; return {namespace: path} of survivors."""
    rtn = {}
    pool = Pool(options.num_threads)
    for item in pool.map(compile_rule, file_list):
        if item:
            rtn[item['key']] = item['rulefile']
    return rtn
       
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
    global rule_filter
    file_list, rule_filter = collect_rule_files(parsed_signatures)
    _hash = rules_hash(file_list)
    path = os.path.join('/tmp/', '%s.py3.cyar' % (_hash))
    if os.path.isfile(path):
        print('[*]\tUp to date compiled rules already exist at %s. Using those' % (path))
        return yara.load(path)

    start = time()
    rulefile_paths = test_compile(file_list)
    elapsed = time() - start
    if options.performance:
        print('[*]\tTest compiled %s rules in %s seconds.' % (len(rulefile_paths), round(elapsed,2)))

    start = time()
    try:
        compiled_rules = yara.compile(filepaths=rulefile_paths,externals={'path': "TEMPORARY_EXT_VAR_VALUE", 'normalized_path': "TEMPORARY_EXT_VAR_VALUE"})
    except Exception as e:
        print('Exception compiling rules: %s' % (e))
    elapsed = time() - start
    try:
        compiled_rules.save(path)
        os.chmod(path, 0o666)
    except Exception as e:
        print('[!]\tFailed to save compiled rules %s: %s' % (path,e))
    compiled_size = os.stat(path).st_size

    if options.performance:
        print('[*]\tCompiled %s rule files in %s seconds.' % (len(rulefile_paths), round(elapsed,2)))
        print('[*]\tCompiled rule size is %s' % (human_size(compiled_size,)))
    return compiled_rules

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

def iterate_matches(matches):
    """Yield (offset, identifier, matched_data) for each match instance."""
    for matchobj in matches:
        name = matchobj.identifier
        for string in matchobj.instances:
            yield string.offset, name, string.matched_data


if __name__ == '__main__':
    global TERMINATE_EARLY
    global scan_queue
    global result_queue
    global bytes_scanned
    global match_count
    global scan_size
    global scan_files
    global lock
    global files_scanned

    lock = Lock()
    files_scanned = 0
    TERMINATE_EARLY = False
    scan_queue = Queue()
    result_queue = Queue()
    bytes_scanned = 0
    match_count = 0
    scan_size = 0
    if options.disassemble:
        import r2pipe

    if options.performance:
        print('[*]\tScanning with %s threads.' % (options.num_threads))

    scanlist = []
    for arg in args:
        scanlist += recursive_all_files(arg)


    #print 'scanning %s' % (scanlist)
    scan_size = 0
    for f in scanlist:
        size = os.stat(f).st_size
        if size != 0:
            scan_size+= size
            scan_queue.put({'fname': f, 'size': size})
    scan_files = scan_queue.qsize()

    if options.profile:
        # -P now subprocesses the profiled yara CLI (built with --enable-profiling).
        # Compile rules normally; the CLI reads the resulting .cyar and emits
        # per-rule cost attribution by <namespace>:<rule_name>. This bypasses
        # yara-python entirely for the profiling step (see github issue
        # VirusTotal/yara-python#155 -- yara-python.profiling_info() is
        # broken against current libyara API).
        compiled_rules = build_rules(options.parsed_signatures)
        run_profile_via_cli(compiled_rules, args, options.threshold)
        sys.exit(0)
    elif len(options.parsed_signatures) == 1 and os.path.isfile(options.parsed_signatures[0][0]):
        # Single precompiled .cyar fast path
        path, names = options.parsed_signatures[0]
        try:
            compiled_rules = yara.load(path)
            if names:
                rule_filter = {'*': names}
        except Exception as e:
            compiled_rules = build_rules(options.parsed_signatures)
    else:
        compiled_rules = build_rules(options.parsed_signatures)

    start = time()
    complete = 0

    worker_threads = []

    for i in range(options.num_threads):
        t = Thread(target=worker)
        t.daemon = True #Die when main thread dies
        t.start()
        worker_threads.append(t)
        scan_queue.put(None) # tells worker to exit

    if options.performance:
        monitor = Thread(target=monitor_thread,args=(worker_threads,))
        monitor.daemon = True
        monitor.start()

    if options.categorize_dir:
        os.makedirs(options.categorize_dir, exist_ok=True)

    while True:
        try:
            if scan_queue.empty():
                break
            else:
                #print scan_queue.queue
                sleep(1)
        except KeyboardInterrupt as kbe:
            TERMINATE_EARLY = True
            #wait for workers to die
            #for w in worker_threads:
            #    w.join()
            if options.performance:
                monitor.join()
            if result_queue.empty():
                # we have 0 results, just exit
                print('No results so far. Exiting')
                exit()
            else:
                print('Stopping further processing and outputting results gathered so far')
                sleep(1)
            break

    if options.performance:
        monitor.join()
    if options.json:
        results = {}
        while not result_queue.empty():
            res = result_queue.get()
            matches = {}
            for match in res['matches']:
                matches[match.rule] = match.meta
            if matches:
                results[res['fname']] = matches
        with open(options.json, 'w') as fp:
            json.dump(results, fp)
    else:
        while not result_queue.empty():
            res = result_queue.get()
            if not res['matches'] and not options.negative:
                continue
            header = False

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
                        for offset, name, data in iterate_matches(matchobj.strings):
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
