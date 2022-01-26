import os
import glob
import binascii

def recursive_all_files(directory, ext_filter=None):
    all_files = []
    dir_content = []
    ret = []
    
    if os.path.isfile(directory):
        dir_content = [directory]
    else:
        if '*' in directory:
            dir_content = glob.glob(directory)
        else:
            try:
                dir_content = os.listdir(directory)
            except Exception as e:
                #print 'Exception listing contents of %s. Skipping' % (directory)
                return []

    for f in dir_content:
        if os.path.isdir(directory):
            rel_path = os.path.join(directory,f)
        else:
            rel_path = f
        if os.path.isfile(rel_path):
            all_files.append(rel_path)
        elif f == '.' or f == '..':
            pass
        else:
            all_files += recursive_all_files(rel_path,ext_filter)

    for f in all_files:
        if (ext_filter is None or os.path.splitext(f)[1] == '.%s' % ext_filter):
            ret.append(f)
    return ret


def hexlify(string):
    string = binascii.hexlify(string).upper().decode('utf-8')
    return ' '.join(string[i:i+2] for i in range(0, len(string), 2))
