#!/usr/bin/env /usr/bin/python3
import os
import yara
import sys
import datetime
import re
import binascii
import glob
import shutil
from copy import deepcopy

import simplejson as json
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from utils import recursive_all_files
from time import sleep, time
from optparse import OptionParser
from threading import Thread, Lock, current_thread
from queue import Queue
from multiprocessing import Pool, cpu_count
from hashlib import md5
from pprint import pprint

usage = "yarascan.py [-S SIGNATURES_DIR] [-t] [FILE_OR_DIR]..." 
opt_parser = OptionParser(usage=usage)
opt_parser.add_option("-S", "--signatures", action="store",dest="signatures",
    default='/Users/jhumble/ice-53-yara-rules/', help="compiled signatures or directory to load YARA rules from")
opt_parser.add_option("-T", "--Threshold", action="store",dest="threshold",default=3.0,type=float,
   help="threshold used in profiling to determine if a rule's runtime is abnormal. Default=3, which returns any rules taking 3x longer than average or 1/3x or less of average")
opt_parser.add_option("-p", "--performance", action="store_true",dest="performance",
    default=False, help="Enable progress and performance profiling")
opt_parser.add_option("-P", "--Profile", action="store_true",dest="profile",
    default=False, help="Profile rules searching for performance issues, overlapping detection, and error 30")
opt_parser.add_option("-s", "--strings", action="store_true",dest="strings",
    default=False, help="output matching strings")
opt_parser.add_option("-C", "--categorize", action="store",dest="categorize_dir",
    default=False, help="categorize the scanned samples into directories by rule name")
opt_parser.add_option("-o", "--offset", action="store_true",dest="offset",
    default=False, help="show match string offsets")
opt_parser.add_option("-t", "--threads", type=int, action="store",dest="num_threads",
    default=None, help="number of threads/workers")
opt_parser.add_option("-c", "--context", type=int, action="store",dest="context",
    default=5, help="number of bytes of context before and after matches")
opt_parser.add_option("-l", "--line", action="store_true",dest="line",
    default=False, help="Output entire line match occurs on")
opt_parser.add_option("-j", "--json", action="store_true",dest="json",
    default=False, help="json output")
opt_parser.add_option("-n", "--negative", action="store_true",dest="negative",
    default=False, help="Output files having no matches")
opt_parser.add_option("--max-strings", action="store",dest="max_strings",type=int,
    default=5, help="Max strings to print per rule")
opt_parser.add_option("--max-offsets", action="store",dest="max_offsets",type=int,
    default=5, help="Max offsets to print per string")
opt_parser.add_option('-d', "--disassemble", action="store", choices=['64', '32'], default=None,
    help="Disassemble matching bytes using 32/64 bit mode as provided")

(options, args) = opt_parser.parse_args()
printable = re.compile(rb'^[\x20-\x7e\x0a]*$')
printable_wide = re.compile(rb'^([\x20-\x7e]\x00)*$')

def percent_printable(string):
    string = string.replace(b'\x00', b'')
    if len(string) == 0:
        return 0
    printable_count = 0
    for c in string:
        if (c <= 0x7f and c >= 20) or c == b'\n' or c == b'\r' or c == b'\t':
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


def highest_impact(match):
    highest = 0
    for entry in match:
        #print entry
        if entry.meta:
            highest = min(100, max(0, entry.meta.get('impact', 100), highest))
        else:
            highest = 100
    return highest

def worker():
    global TERMINATE_EARLY
    global result_queue
    global bytes_scanned
    global files_scanned
    global match_count
    global lock

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
            if not options.profile:
                matches = compiled_rules.match(job['fname'])
            else:
                matches = []
                for key, rule in compiled_rules.items():
                    start = time()
                    matches += rule['rule'].match(job['fname'])
                    profile_queue.put({'fname': job['fname'], 'rulefile': rule['rulefile'], 'time': time() - start})
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
    if 'file_name' in match.meta:
        passed = False         
        for search in match.meta['file_name'].lower().split(','):
            if 'sub:' in search:
                if search.replace('sub:', '') in fname.lower():
                    passed = True
            else:
                if search == fname.lower():
                    passed = True
        if not passed:
            return True

    if 'full_path' in match.meta:
        passed = False
        for search in match.meta['full_path'].lower().split(','):
            if 'sub:' in search:
                if search.replace('sub:', '') in fname.lower():
                    passed = True
            else:
                if search == fname.lower():
                    passed = True
        if not passed:
            return True

    if 'file_ext' in match.meta:
        passed = False
        for search in match.meta['file_ext'].lower().split(','):
            if fname.lower().endswith(search):
                passed = True
        if not passed:
            return True
        
    return False



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

def compile_rule(rulefile, include_compiled=False):
    try:
        key = os.path.splitext(os.path.split(rulefile)[1])[0]
        start = time()
        rule = yara.compile(filepaths={key: rulefile},externals={'path': "TEMPORARY_EXT_VAR_VALUE", 'normalized_path': "TEMPORARY_EXT_VAR_VALUE"})
        rtn = {'key': key, 'rulefile': rulefile, 'compile_time': time() - start}
        if include_compiled:
            rtn['rule'] = rule
        return rtn
    except Exception as e:
        print('rule %s failed to compile! Error: %s' % (rulefile, e))
    return None
    
def test_compile(file_list, individual_rules=False):
    rtn = {}
    # Can't use a pool since we can't pickle the compiled rule objects to send across the queue
    if individual_rules:
        for f in file_list:
            compiled = compile_rule(f, include_compiled=True)
            if compiled:
                rtn[compiled['key']] = compiled
    
    else:
        pool = Pool(options.num_threads)
        results = pool.map(compile_rule, file_list)
        for item in results:
            if item:
                rtn[item['key']] = item['rulefile']
    return rtn
       
def build_rules(signature_dir, profile_rules=False):
    file_list = recursive_all_files(signature_dir,'yar')
    _hash = rules_hash(file_list)
    if profile_rules:
        return test_compile(file_list, individual_rules=True)
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
        print('[*]\tCompiled %s rules in %s seconds.' % (len(rulefile_paths), round(elapsed,2)))
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

def score_matches(matches):
    score = 0
    for match in matches:
        score = max(score, int(match.meta.get('impact', 0)))
    return score

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
            
    if printable_wide.match(string):
        rtn = string.decode('utf-16le')
    elif percent_printable(before + string + after) > .8:
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
    return raw_bytes, hex_format, rtn
    

def preexec_function():
    # Ignore SIGINT by setting handler to SIG_IGN
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in xrange(0, len(l), n):
        yield '\x00' + l[i:i+n]

def ngrams(s, n=3, i=0):
    rtn = set()
    while len(s[i:i+n]) == n:
        rtn.add(s[i:i+n])
        i += 1
    return list(rtn)


def extract_trigrams(string):
    rtn = set()
    hex_extractor = re.compile(r'([0-9a-f]{2}){3,}', re.IGNORECASE)
    if string['type'] == 'hex':
        string['value'] = string['value'].replace(' ','')
        for match in hex_extractor.finditer(string['value']):
            data = binascii.unhexlify(match.group())
            rtn |= set(ngrams(data))
    elif string['type'] == 'string':
        rtn |= set(ngrams(string['value']))
        
    return rtn
        

def prefilter(cache_dir, rule_path):
    from rule_parsers.YaraRule import YaraRule
    import struct
    req_trigrams = {}
    with open(rule_path,'rb') as fp:
        ruletext = fp.read()

    rule = YaraRule(ruletext)
    rule.condition = '\n'.join(rule.conditions)
    if 'any of them' in rule.condition:
        strings = rule.strings
        print('Extracting trigrams from {}'.format([string['value'].rstrip('"').lstrip('"') for string in strings]))
        #supported
    elif 'cache_helper' in rule.metas:
        print(('Applying cache helper {}'.format(rule.metas['cache_helper'])))
        strings = []
        print('Extracting trigrams from {}'.format(rule.metas['cache_helper'].split(',')))
        for search in rule.metas['cache_helper'].split(','):
            strings.append({'type': 'string', 'value': search})
    else:
        print('Can only cache accelerate "any of them" rules or those with cache_helper meta')
        return recursive_all_files(cache_dir)


    for string in strings:
        req_trigrams[string['value']] = extract_trigrams(string)

    start = time()
    with open(os.path.join(cache_dir, 'cache_files.json'), 'r') as fp:
        id_to_path = json.load(fp)
    #all_files.pop('id')
    #id_to_path = {}
    #for key, val in all_files.items():
    #    id_to_path[int(val['id'])] = val['path']
    #with open(os.path.join(cache_dir, 'by_id.json'), 'w') as fp:
    #    json.dump(id_to_path, fp)
    #exit()

    matching = set([int(x) for x in id_to_path.keys()])
    match_sets = {}
    print('Parsed cache_files in {}s'.format(time() - start))
    for string, trigram_set in req_trigrams.items():
        matching_set = deepcopy(matching)
        for trigram in trigram_set:
            print('trigram = {}'.format(trigram))
            hex_trigram = binascii.hexlify(trigram)
            with open(os.path.join(cache_dir, hex_trigram[:2], hex_trigram), 'rb') as fp:
                fids = set([struct.unpack('>I', i)[0] for i in chunks(fp.read(),3)])
                print('Before filtering with trigram {}: {} files'.format(hex_trigram, len(matching_set)))
                matching_set &= fids
                print('After filtering: {} files'.format(len(matching_set)))
        match_sets[string] = matching_set
    matching = set()
    for string, matching_set in match_sets.items():
        print('Before filtering with string {}: {} files'.format(string, len(matching)))
        matching_set &= fids
        print('After filtering: {} files'.format(len(matching)))
        matching |= matching_set
    print('done')
    return [id_to_path[str(fid)] for fid in matching]


if __name__ == '__main__':
    global TERMINATE_EARLY
    global scan_queue  
    global result_queue
    global profile_queue
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
    profile_queue = Queue()
    bytes_scanned = 0
    match_count = 0
    scan_size = 0
    if options.disassemble:
        import r2pipe

    if options.performance:
        print('[*]\tScanning with %s threads.' % (options.num_threads))

    scanlist = []
    for arg in args:
        #Perform prefiltering if we're operating with a single yara rule and are targetting a cache dir
        if os.path.exists(os.path.join(arg, 'cache_files.json')) and os.path.isfile(options.signatures):
            print('Prefiltering with trigram cache')
            scanlist += prefilter(arg, options.signatures)
        else:    
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
        compiled_rules = build_rules(options.signatures, True)
        print('built profiled rules')
    else:
        try:
            compiled_rules = yara.load(options.signatures)
        except Exception as e:
            compiled_rules = build_rules(options.signatures)

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
            results[res['fname']] = matches
        print(json.dumps(results))
    else:
        while not result_queue.empty():
            res = result_queue.get()
            if not res['matches'] and not options.negative:
                continue
            header = False

            for match in res['matches']:
                if not filter_match(match, res['fname']):
                    if not header:
                        print(res['fname'])# + '\t' + str(score_matches(res['matches'])))
                        header = True
                    if options.categorize_dir:
                        d = os.path.join(options.categorize_dir, match.rule)
                        os.makedirs(d, exist_ok=True)
                        shutil.copy(res['fname'], d) 
                    strings = {}
                    if options.strings:
                        for s in match.strings:
                            offset = hex(s[0]).strip('L')
                            name = s[1]
                            raw_bytes, printable, string = format_string_output(string=s[2], offset=s[0], fname=res['fname'], context=options.context, line=options.line)
                            string = string.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                            if name not in strings:
                                strings[name] = {}
                            if string not in strings[name]:
                                strings[name][string] = {'bytes': raw_bytes, 'offsets': [], 'printable': printable}
                            if offset not in strings[name][string]['offsets']:
                                strings[name][string]['offsets'].append(offset)
                    
                    print('    %s/%s' % (match.namespace, match.rule))
                        
                    if options.strings:
                        for name, string_dict in strings.items():
                            for string in list(string_dict.keys())[:options.max_strings]:
                                offsets = string_dict[string]['offsets']
                                for offset in offsets[:options.max_offsets]:
                                    if options.offset: 
                                        try:
                                            print('        %s:%s:    %s' % (name, offset, string))
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
    
    if options.profile:
        # group by signature, looking for outliers
        profile_results = {}
        while not profile_queue.empty():
            item = profile_queue.get()
            try:
                profile_results[item['rulefile']][item['fname']] = item['time']
            except:
                profile_results[item['rulefile']] = {item['fname']: item['time']}

        for rule, results in profile_results.items():
            total = 0
            for fname, duration in results.items():
                total += duration
            results['rule_average'] = total*1.0/len(results)

        overall_average = (sum([x['rule_average'] for x in profile_results.values()]) - results['rule_average'])/(1.0*(len(profile_results)-1))
        for rule, results in profile_results.items():
            try:
                relative = results['rule_average']/overall_average
                if relative > options.threshold or relative < (1.0/options.threshold):
                    print('{0:50}\t{1:0.1f}%'.format(os.path.basename(rule), relative*100.0))
            except Exception as e:
                import traceback
                print('Failed to calculate results for {}: {}'.format(rule, traceback.format_exc()))

    if options.performance:
        elapsed = time() - start
        print('[*]\tProcessed %s files in %s seconds. %s/s' % (files_scanned,round(elapsed,2), human_size(bytes_scanned/elapsed)))
    #print max(scores)
    """
    for f in get_directory_file_list(sys.argv[1]): #recursive_all_files(sys.argv[1]):
        match = compiled_rules.match(f)
        print f + "\t" + str(highest_impact(match))# + "\t" + str(match)
        #for match in match_ret
        #    dir(match)
    """

