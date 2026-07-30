#!/usr/bin/env python3
"""
FP Analyzer - Test YARA rules against benign samples and annotate/comment out matching patterns.

Usage:
    fp_analyzer.py -r rule.yar -b benign_dir/ -o annotated_rule.yar
"""

import os
import sys
import re
import yara
from argparse import ArgumentParser
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from utils import recursive_all_files


def parse_args():
    parser = ArgumentParser(description="Test YARA rules against benign samples and annotate FP-causing patterns")
    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule file to test")
    parser.add_argument("-b", "--benign", required=True, action="append", 
                        help="Directory of benign files to test against. Can specify multiple times.")
    parser.add_argument("-o", "--output", help="Output path for annotated rule (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show which files matched each pattern")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads for scanning")
    return parser.parse_args()


def scan_benign(rule_path, benign_dirs, verbose=False):
    """
    Scan benign files and return a dict of pattern_name -> list of matching files
    """
    # Compile the rule
    try:
        rules = yara.compile(filepath=rule_path)
    except yara.SyntaxError as e:
        print(f"Error compiling rule: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Collect all benign files
    benign_files = []
    for benign_dir in benign_dirs:
        benign_files.extend(recursive_all_files(benign_dir))
    
    print(f"[*] Testing rule against {len(benign_files)} benign files...", file=sys.stderr)
    
    # Track matches: pattern_name -> [list of files that matched]
    pattern_matches = defaultdict(list)
    
    for i, fpath in enumerate(benign_files):
        if (i + 1) % 1000 == 0:
            print(f"[*] Scanned {i + 1}/{len(benign_files)} files...", file=sys.stderr)
        
        try:
            matches = rules.match(fpath)
            for match in matches:
                # Handle both old and new yara-python API
                for string_match in match.strings:
                    if hasattr(string_match, 'identifier'):
                        # New API (>= 4.3.0)
                        name = string_match.identifier
                    else:
                        # Old API
                        name = string_match[1]
                    
                    if fpath not in pattern_matches[name]:
                        pattern_matches[name].append(fpath)
        except Exception as e:
            if verbose:
                print(f"[!] Error scanning {fpath}: {e}", file=sys.stderr)
    
    print(f"[*] Scan complete. {len(pattern_matches)} patterns matched benign files.", file=sys.stderr)
    
    if verbose and pattern_matches:
        print("\n[*] FP Details:", file=sys.stderr)
        for pattern, files in sorted(pattern_matches.items(), key=lambda x: -len(x[1])):
            print(f"    {pattern}: {len(files)} matches", file=sys.stderr)
            for f in files[:3]:  # Show first 3 files
                print(f"        - {f}", file=sys.stderr)
            if len(files) > 3:
                print(f"        ... and {len(files) - 3} more", file=sys.stderr)
    
    return pattern_matches


def annotate_rule(rule_path, pattern_matches, output_path=None):
    """
    Read the rule file and:
    1. Add benign match counts to pattern comments
    2. Comment out patterns that had matches
    """
    with open(rule_path, 'r') as f:
        rule_text = f.read()
    
    lines = rule_text.split('\n')
    output_lines = []
    
    # Regex to match YARA string definitions
    # Matches: $name = "string" or $name = { hex } or $name = /regex/
    string_pattern = re.compile(
        r'^(\s*)(\$\w+)\s*=\s*(.+?)(\s*//.*)?$'
    )
    
    in_strings_section = False
    
    for line in lines:
        # Track if we're in the strings section
        if re.match(r'\s*strings\s*:', line):
            in_strings_section = True
            output_lines.append(line)
            continue
        elif re.match(r'\s*condition\s*:', line):
            in_strings_section = False
            output_lines.append(line)
            continue
        
        if not in_strings_section:
            output_lines.append(line)
            continue
        
        # Try to match a string definition
        match = string_pattern.match(line)
        if match:
            indent = match.group(1)
            pattern_name = match.group(2)
            pattern_value = match.group(3)
            existing_comment = match.group(4) or ""
            
            # Check if this pattern matched benign files
            fp_count = len(pattern_matches.get(pattern_name, []))
            
            if fp_count > 0:
                # Comment out the pattern and add FP count
                # Strip existing comment's // prefix if present
                existing_comment = existing_comment.strip()
                if existing_comment.startswith('//'):
                    existing_comment = existing_comment[2:].strip()
                
                if existing_comment:
                    new_comment = f"// BENIGN_FP:{fp_count} {existing_comment}"
                else:
                    new_comment = f"// BENIGN_FP:{fp_count}"
                
                # Comment out the entire line
                output_lines.append(f"{indent}// {pattern_name} = {pattern_value} {new_comment}")
            else:
                # No FPs - keep the line, just add BENIGN_FP:0 to comment
                existing_comment = existing_comment.strip()
                if existing_comment.startswith('//'):
                    existing_comment = existing_comment[2:].strip()
                
                if existing_comment:
                    new_comment = f"// BENIGN_FP:0 {existing_comment}"
                else:
                    new_comment = f"// BENIGN_FP:0"
                
                output_lines.append(f"{indent}{pattern_name} = {pattern_value} {new_comment}")
        else:
            # Not a string definition, keep as-is
            output_lines.append(line)
    
    result = '\n'.join(output_lines)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(result)
        print(f"[*] Annotated rule written to {output_path}", file=sys.stderr)
    else:
        print(result)
    
    # Print summary
    fp_patterns = [p for p, files in pattern_matches.items() if files]
    if fp_patterns:
        print(f"\n[!] Summary: {len(fp_patterns)} patterns commented out due to benign matches:", file=sys.stderr)
        for pattern in sorted(fp_patterns, key=lambda p: -len(pattern_matches[p])):
            print(f"    {pattern}: {len(pattern_matches[pattern])} FPs", file=sys.stderr)
    else:
        print("\n[+] No false positives found!", file=sys.stderr)


def main():
    args = parse_args()
    
    # Scan benign files
    pattern_matches = scan_benign(args.rule, args.benign, args.verbose)
    
    # Annotate and output the rule
    annotate_rule(args.rule, pattern_matches, args.output)


if __name__ == '__main__':
    main()
