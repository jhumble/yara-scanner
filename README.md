# yara-scanner

A practical wrapper around `libyara` for malware triage and rule development. Same rule language as upstream YARA, but with the ergonomics and introspection you actually want when you're iterating on rules against real sample sets and benign corpora.

## Why not just use `yara`?

Stock `yara` gives you `rules + targets -> match / no match`. It does that well, but everything *around* that loop — parallel scanning, match context, rule performance, benign testing, per-rule output — you end up building yourself. This tool is that layer, purpose-built for the rule-writer's inner loop.

Roughly, compared to `yara`:

| | `yara` | `yarascan.py` |
|---|---|---|
| Parallel scanning | `-p` threads, but no progress | threaded by default, live progress + ETA + match count |
| Combining rule sources | one `-r` at a time | `-S` repeatable, mixes `.yar` files / dirs / precompiled `.yxc` |
| Run a specific rule from a multi-rule file | no | `-S foo.yar::rule_b` (comma-separate for several) |
| Compiled rule caching | manual | automatic — compiles once to `/tmp/<content-hash>.yxc`, reused as long as no rule-source bytes changed |
| Per-rule performance profiling | no | `-P` — flags rules running N× slower/faster than average |
| Match context in output | `-s` shows bytes, no context, no color | `-s -c N` shows match bytes in red with N bytes of surrounding context; `-l` expands to the full line |
| Wide / UTF-16LE matches | shown raw | auto-decoded, optional tag with `-w` |
| Non-printable matches | shown raw | automatically rendered as hex |
| Match offsets | `-s` only | `-o` is independent of `-s` |
| Disassembly of matches | no | `-d 32` / `-d 64` disassembles match bytes via r2pipe, highlights the matching instructions |
| Sort samples by rule | no | `-C out_dir/` copies each matched file into `out_dir/<rule_name>/` for triage |
| JSON output | no | `-j results.json` |
| "Which files *didn't* match" | no | `-n` |
| Per-rule file-name / path filtering | no | rule-level `file_name` / `full_path` / `file_ext` meta fields are auto-honored (supports `!` negation and `sub:` substring) |
| FP triage loop | manual diffing | `fp_analyzer.py` — runs a rule against a benign corpus and rewrites the rule with an annotated, commented-out version of every string that fired on benign data |

## Install

```
pip install yara-x
# optional: r2pipe  (needed for -d / disassembly)
```

Python 3.13. Drop the repo anywhere and either symlink `yarascan.py` onto your `PATH` or invoke it directly.

## Usage

```
yarascan.py [-S SIG[::RULE[,RULE...]]] [options] FILE_OR_DIR...
```

`-S` is repeatable and accepts a `.yar` file, a directory of rules, or a precompiled `.yxc`. Positional arguments are scan targets (files or dirs, recursively walked). If `-S` is omitted, a hardcoded default rules dir is used.

### Quickstart

```
$ yarascan.py -S yara-rules/Classification_AsyncRat.yar \
              -S yara-rules/Classification_njRAT.yar \
              ~/RE/samples/malpedia/win.asyncrat/ \
              ~/RE/samples/malpedia/win.njrat/
[*]     Up to date compiled rules already exist at /tmp/13f8705c0ccdc43d428c834590176e63.yxc. Using those
~/RE/samples/malpedia/win.asyncrat/4541b53...a94f899_unpacked
    Classification_AsyncRat/Classification_AsyncRAT

~/RE/samples/malpedia/win.asyncrat/2020-05-10-v0.5.7b/bc820d4...c20ab775f6_unpacked
    Classification_AsyncRat/Classification_AsyncRAT

~/RE/samples/malpedia/win.njrat/v0.8d/f305ed2...7b33ba5c6_unpacked
    Classification_njRAT/Classification_njRat_Auto

~/RE/samples/malpedia/win.njrat/v0.7.2/1296a50...18369078b
    Classification_njRAT/Classification_njRat_Auto
```

Each matching file is printed once, followed by an indented `<namespace>/<rule_name>` line per rule that fired.

### Rule-source syntax

```
# all rules in one file
yarascan.py -S Classification_CastleRat.yar ./samples/

# one specific rule out of a multi-rule file
yarascan.py -S Classification_CastleRat.yar::Classification_CastleRat_Deno_JS_Loader ./samples/

# two specific rules
yarascan.py -S Classification_CastleRat.yar::rule_a,rule_b ./samples/

# mix restricted and unrestricted sources
yarascan.py -S CastleRat.yar::Deno_JS_Loader -S Technique_Deno_Runtime_Abuse.yar ./samples/

# whole directory of rules
yarascan.py -S /home/jhumble/RE/yara-rules/ ./samples/
```

### Match output with context

Flags:
- `-s` — show matching strings
- `-o` — include byte offsets
- `-p` — enable progress + performance monitor
- `-c N` — N bytes of surrounding context (match is rendered in red in a TTY)

`-l` replaces `-c N` with "show the full source line containing the match" — best when scanning text (PowerShell, JS, config files).

Printable matches render as text; binary matches fall back to hex automatically. UTF-16LE hits are detected and decoded; add `-w` to tag them explicitly.

```
$ yarascan.py -sop -c 40 -S yara-rules/Classification_AsyncRat.yar \
              ~/RE/samples/malpedia/win.asyncrat/
[*]     Scanning with 8 threads.
Progress: (4.5 MB/4.5 MB)     Time Remaining: 0:00:00     Matches: 3
~/RE/samples/malpedia/win.asyncrat/2020-05-10-v0.5.7b/bc820d4...c20ab775f6_unpacked
    Classification_AsyncRat/Classification_AsyncRAT
        $val_schtasks:0x995b:    i\x00n\x00g\x00\x00\x0fM\x00e\x00s\x00s\x00a\x00g\x00e\x00\x00\x07c\x00m\x00d\x00\x00i/c schtasks /create /f /sc onlogon /rl highest /tn \x00"\x00\x00\x11"\x00 \x00/\x00t\x00r\x00 \x00'\x00"\x00\x01\x13"\x00'\x00 \x00&\x00
        $val_pong:0x5e31:    ingField\x00<Ping>k__BackingField\x00<ActivatePong>k__BackingField\x00<Interval>k__Ba
        $aes_exc:0x9e41:    \x00\x11R\x00e\x00c\x00e\x00i\x00v\x00e\x00d\x00\x00\x0bE\x00r\x00r\x00o\x00r\x00\x00GmasterKey can not be null or empty.\x00\x00-i\x00n\x00p\x00u\x00t\x00 \x00c\x00a\x00n\x00 \x00n\x00o\x00t\x00 \x00
        $patt_aes:0x913:    06 01 00 00 01 1B 30 02 00 2D 01 00 00 02 00 00 11 28 19 00 00 0A 7E 07 00 00 04 28 1A 00 00 0A 6F 1B 00 00 0A 80 07 00 00 04 7E 07 00 00 04 73 4B 00 00 06 80 0D 00 00 04 7E 0D 00 00 04 7E 01 00 00 04 6F 4E 00 00 06 80 01 00 00 04 7E 0D 00

[*]     Processed 12 files in 1.01 seconds. 4.47 MB/s
```

The mixed rendering is automatic: `$val_schtasks` is mostly UTF-16LE surrounding ASCII and gets escaped text; `$patt_aes` is .NET IL bytecode and falls back to hex. Running this in a TTY highlights the matched bytes in red inside the surrounding context.

### Rule performance profiling

```
$ yarascan.py -P -T 3 -S yara-rules/ /tmp/unk3/
profiled 50/602 files
profiled 100/602 files
...
profiled 602/602 files
===== yarascan -P: per-rule outliers (threshold=3, mean nonzero cost=929614457, n_rules=1730, files=602, profile-wallclock=178.0s) =====
Classification_Kutaki::Classification_Kutaki_EricsVersion       308910591939   33230.0%
SlackConnect_TOAD_Email::SlackConnect_TOAD_Email                275387004255   29623.8%
fdr_defense_evasion::fdr_defense_evasion_PowerShell_Alias_Abuse 249704034096   26861.0%
Classification_Pyobfuscate::Classification_Pyobfuscate_Online   171826631955   18483.6%
Classification_DarkGate::DarkGate_Html_Dropper                   95794439142   10304.7%
...
--- top 5 files by total cost ---
   501612870571	/tmp/unk3/logs/flog.xml
   384956663963	/tmp/unk3/logs/analysis.binlog
   363203636610	/tmp/unk3/17316713.zip
    35166053131	/tmp/unk3/logs/flog.txt
    14910104038	/tmp/unk3/internal/static_analyses/sample_static_analysis_cfg.json
```

Output is keyed `<rulefile>::<rule_name>`, so multi-rule `.yar` files (Classification_AgentTesla.yar contains 7 rules; Classification_Rhadamanthys.yar contains ~15) are attributed to the specific rule that's expensive rather than lumped at the file level.

The "cost" is the engine's own per-rule cost counter (`atom_matches × match_time + exec_time`, with verification time sampled 1-in-1024 — that's why the numbers are integers in the billions, not nanoseconds). Use them as a relative ranking, not a wallclock estimate. Anything above `-T × 100%` (default 300%) of the mean nonzero rule cost is shown. Fast-side outliers are intentionally suppressed — they were dominated by rules whose atoms matched once or twice but the condition never fired, which made every interesting rule look like an "outlier" in the legacy implementation.

The "top 5 files by total cost" block below the rule outliers points at which input file made the corpus expensive — a useful pivot when one slow rule's cost is concentrated on a single artifact.

**Setup required.** `-P` shells out to a separately-built `yara` CLI compiled with `--enable-profiling`. Source rule files are passed as `[namespace:]path` positional args — the compiled-rules binary format is not portable between yara-x's `Rules` and the standalone `yara` CLI's `.cyar`. The path is hardcoded to `~/tools/yara-scanner/yara-profiling/bin/yara`; build it with:

```
git clone https://github.com/VirusTotal/yara.git ~/tools/build-yara/yara
cd ~/tools/build-yara/yara
./bootstrap.sh
./configure --enable-profiling --prefix=~/tools/yara-scanner/yara-profiling
make -j$(nproc)
make install
```

This is a separate install from your system `yara` — it lives under `~/tools/yara-scanner/yara-profiling/` and is only invoked when you pass `-P`. Your normal yarascan runs use yara-x (no profiling overhead).

If the profiled binary is missing, `yarascan -P` warns and exits cleanly with build instructions; no other modes are affected.

### Sort matches into per-rule bins

```
$ yarascan.py -S yara-rules/Classification_AsyncRat.yar \
              -S yara-rules/Classification_njRAT.yar \
              -C /tmp/triage/ \
              ~/RE/samples/malpedia/win.asyncrat/ \
              ~/RE/samples/malpedia/win.njrat/

$ tree /tmp/triage/
/tmp/triage/
├── Classification_AsyncRAT/
│   ├── 4541b53f...a94f899_unpacked
│   ├── 8ea22c9f...c5ecb2_unpacked
│   └── bc820d4b...775f6_unpacked
└── Classification_njRat_Auto/
    ├── 1296a508...9078b
    ├── 1296a508...9078b_dump_0x00400000
    ├── f305ed22...5c6_dump7_0x00400000
    └── f305ed22...5c6_unpacked
```

Samples that hit multiple rules land in multiple bins. Useful for first-pass categorization of an unknown pile.

### JSON output

```
$ yarascan.py -S yara-rules/Classification_AsyncRat.yar \
              -j results.json \
              ~/RE/samples/malpedia/win.asyncrat/

$ jq '.' results.json
{
  "~/RE/samples/malpedia/win.asyncrat/4541b53f...a94f899_unpacked": {
    "Classification_AsyncRAT": {
      "author": "-"
      "date": "2023-11-28",
      "description": "Detects on the AsyncRAT windows binary."
    }
  }
}
```

Shape is `{path: {rule_name: meta_dict}}` — suitable for downstream scripting. Matching strings are not included; use the plain-text output with `-s` if you need those.

### Disassembly of matches

```
$ yarascan.py -sop -d 32 -c 0 -S yara-rules/Shellcode_PEB_Parsing.yar \
              ~/RE/samples/malpedia/win.rhadamanthys/2024-03-21/bea1d58d...49203_unpacked
~/RE/samples/malpedia/win.rhadamanthys/2024-03-21/bea1d58d...49203_unpacked
    Shellcode_PEB_Parsing/Shellcode_PEB_Parsing
        $get_ldr_data_direct_eax_x86:0xee82:    64 A1 30 00 00 00 89 45 FC 8B 45 FC 8B 40 0C 3B C7 74 31 8D 50 14
                        0x00000000      64a130000000   mov eax, dword fs:[0x30]
                        0x00000006      8945fc         mov dword [ebp - 4], eax
                        0x00000009      8b45fc         mov eax, dword [ebp - 4]
                        0x0000000c      8b400c         mov eax, dword [eax + 0xc]
                        0x0000000f      3bc7           cmp eax, edi
                    ┌─< 0x00000011      7431           je 0x44
                    │   0x00000013      8d5014         lea edx, [eax + 0x14]
                    │   0x00000016      8b4014         mov eax, dword [eax + 0x14]
```

For each match, `-d` pipes the bytes (optionally plus context from `-c N`) through an r2pipe instance, tries the bit width from `-d` first and falls back to the other, and prints annotated disassembly. In a TTY the instructions that fall *inside* the matched bytes are drawn in red, so you can see at a glance whether your string is centered on real code or is slightly skewed off a function boundary. Requires `r2pipe` and a working `radare2`.

The `-c 0` above trims pre-match context so the disassembly starts right at the matched bytes — here, the canonical `mov eax, fs:[0x30]` PEB fetch. Bump `-c` higher when you want to see the prologue that led into the match.

## Rule-side filtering via meta fields

`yarascan.py` reads three optional `meta:` fields on each rule and uses them to suppress matches post-hoc. This lets you keep a rule narrow without polluting its `condition:` with path-shape checks.

- `file_name = "foo.exe"` — match only when the sample's basename is `foo.exe`
- `full_path = "C:\\Windows\\foo.exe"` — match only against this full path
- `file_ext = "dll"` — match only for this extension

Each supports:
- **Comma-separated alternatives**: `file_ext = "exe,dll,sys"`
- **Negation** with a leading `!`: `file_ext = "!txt,!md"`
- **Substring** with `sub:`: `file_name = "sub:loader"` matches anything with `loader` in the name

If the rule fires but the sample doesn't satisfy the filter, the match is dropped before it ever reaches output / categorization / JSON.

## FP analyzer

Companion tool for the part of rule-writing that sucks the most: finding out *which individual string* in your rule is responsible for matching benign samples.

```
fp_analyzer.py -r my_rule.yar -b /data/benign/ -o my_rule.annotated.yar
```

What you get back: a copy of `my_rule.yar` where every `$string` is annotated with `// BENIGN_FP:N`, and every string that fired on benign data is commented out. Remaining strings are the ones you can still rely on; you edit the condition to not count on the commented-out ones and re-test.

`-b` is repeatable, `-v` prints per-pattern FP files, `-t N` threads.

## Trigram prefilter (advanced)

If the scan target directory contains a `cache_files.json` trigram index (produced by a separate caching pipeline not in this repo) and you're scanning with exactly one rule file, `yarascan.py` will use the trigram index to skip any file that can't possibly match. Triggers automatically — no flag required.

Only applies to rules whose condition is `any of them` or which declare a `cache_helper` meta field naming the relevant strings.

## Files in this repo

- `yarascan.py` — the scanner
- `fp_analyzer.py` — benign-corpus FP annotator
- `utils.py` — shared helpers (recursive file walk, hex formatting)
