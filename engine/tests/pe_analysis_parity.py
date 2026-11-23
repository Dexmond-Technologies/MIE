#!/usr/bin/env python3
"""CI test: the C++ analysis of Windows executables equals the Python reference's PEAnalyzer.

Usage: pe_analysis_parity.py <path to mie-pe-analysis-probe> <repository root>

Reference side: dexmond_mie.pe_analyzer.PEAnalyzer of this checkout with pefile 2024.8.26,
calling the methods Engine.scan_file calls (core.py 145-260 and 429-442): analyze() and its
warnings, high_entropy_sections, wx_sections, tls_callbacks, tls_callback_section,
api_chains, minor_api_chains, certificate, overlay, overlay_entropy; get_suspicious_imports,
get_packer_sections, confirmed_upx_sections, scored_import_names, scored_import_name_spans,
_section_name, section_at_rva, get_resource_section, resource_slack_entropy; and
PEAnalyzer.from_data for the head-window analysis of an oversize file.
C++ side: `mie-pe-analysis-probe <dir> --packer-rule Packer_UPX`.

Inputs (all generated here, harmless, no malware and no EICAR file): the base files of
engine/tests/pe_parity.py (the executables of parity set S and the ones built there for
resources, ordinals, delay imports, overlapping sections and 64-bit), plus damaged variants of
each, built by that test's generator with the seed printed below. The number of variants and
the seed follow the same environment settings (MIE_PE_VARIANTS_PER_BASE, MIE_PE_TOTAL_VARIANTS,
MIE_PE_SEED); files are handled in batches. Only files that parse
on BOTH sides are compared here; "parses or not" is the business of pe_parity.py.

The packer rule name is given to every file on both sides (not only to the files named
"packer"): confirmation still needs the packer's real section layout, so this compares the
confirmation rule on every file.

Per field: how many files were compared and how many differ; the first 20 differences in
full. Exit code 1 on any difference, or when fewer than 2,000 variants were built.
"""
import json
import os
import random
import subprocess
import sys
import tempfile

PROBE, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pe_parity  # noqa: E402  the variant generator and the base files (its main() is not run)

PACKER_RULES = ['Packer_UPX']
FIELDS = ('section_names', 'section_permissions', 'section_entropy', 'imports', 'total_imports', 'api_chains',
          'minor_api_chains', 'suspicious_imports', 'scored_import_names', 'scored_import_name_spans',
          'packer_sections', 'confirmed_upx_sections', 'confirmed_upx_sections_without_rule', 'warnings',
          'high_entropy_sections', 'wx_sections', 'tls_callbacks', 'tls_callback_section', 'resource_section',
          'resource_slack', 'certificate', 'overlay', 'overlay_entropy', 'section_at_rva')
HEAD_FIELDS = ('imports', 'api_chains', 'minor_api_chains', 'suspicious_imports')


def probe_rvas(pe):
    """The same list of RVAs the probe uses for section_at_rva."""
    rvas = [pe.OPTIONAL_HEADER.AddressOfEntryPoint]
    for section in pe.sections[:64]:
        start = section.VirtualAddress
        span = max(section.Misc_VirtualSize, section.SizeOfRawData)
        rvas += [start, start - 1, start + span - 1, start + span]
    return rvas


def reference_view(path, data):
    """What the reference reports for the file, in the shape of the probe's JSON line.
    Returns None when the reference does not parse the file, {'raises': name} when one of the
    reference's own methods raises on it (then the file is counted and not compared)."""
    from dexmond_mie.pe_analyzer import PEAnalyzer
    analyzer = PEAnalyzer(path)
    if not analyzer.is_valid():
        return None
    pe = analyzer.pe
    try:
        info = analyzer.analyze()
        resource_section = analyzer.get_resource_section()
        resource_index = None
        slack = None
        if resource_section is not None:
            resource_index = next(i for i, s in enumerate(pe.sections) if s is resource_section)
            measured = analyzer.resource_slack_entropy(resource_section)
            slack = {'size': measured['size'], 'entropy': float(measured['entropy'])}
        cert = info['certificate']
        overlay = analyzer.get_overlay_info()
        overlay_entropy = analyzer.get_overlay_entropy()
        imports = analyzer._get_imports()
        view = {
            'section_names': [analyzer._section_name(s) for s in pe.sections],
            'section_permissions': [analyzer._get_section_permissions(s) for s in pe.sections],
            'section_entropy': [float(s.get_entropy()) for s in pe.sections],
            'imports': [[dll, names] for dll, names in imports.items()],
            'total_imports': sum(len(names) for names in imports.values()),
            'api_chains': info['api_chains'],
            'minor_api_chains': info['minor_api_chains'],
            'suspicious_imports': analyzer.get_suspicious_imports(),
            'scored_import_names': sorted(analyzer.scored_import_names()),
            'scored_import_name_spans': sorted([a, b] for a, b in analyzer.scored_import_name_spans()),
            'packer_sections': analyzer.get_packer_sections(),
            'confirmed_upx_sections': sorted(analyzer.confirmed_upx_sections(PACKER_RULES)),
            'confirmed_upx_sections_without_rule': sorted(analyzer.confirmed_upx_sections([])),
            'warnings': info['warnings'],
            'high_entropy_sections': info['high_entropy_sections'],
            'wx_sections': info['wx_sections'],
            'tls_callbacks': info['tls_callbacks'],
            'tls_callback_section': info['tls_callback_section'],
            'resource_section': resource_index,
            'resource_slack': slack,
            'certificate': {'present': cert['present'], 'valid': cert['valid'], 'problems': cert['problems']},
            'overlay': {'present': overlay['present'], 'size': overlay['size']},
            'overlay_entropy': {'size': overlay_entropy['size'], 'entropy': float(overlay_entropy['entropy']),
                                'certificate_excluded': overlay_entropy['certificate_excluded']},
            'section_at_rva': [[rva, analyzer.section_at_rva(rva)] for rva in probe_rvas(pe)],
        }
    except Exception as e:  # noqa: BLE001 - a reference method raised on a damaged file
        return {'raises': type(e).__name__}
    finally:
        try:
            pe.close()   # pefile keeps the file locked on Windows (review finding W-2)
        except Exception:  # noqa: BLE001
            pass

    head = PEAnalyzer.from_data(data, path)
    if head.is_valid():
        try:
            view['head'] = {'imports': [[dll, names] for dll, names in head._get_imports().items()],
                            'api_chains': head.get_api_chains(),
                            'minor_api_chains': head.get_minor_api_chains(),
                            'suspicious_imports': head.get_suspicious_imports()}
        except Exception as e:  # noqa: BLE001
            view['head'] = {'raises': type(e).__name__}
        finally:
            try:
                head.pe.close()
            except Exception:  # noqa: BLE001
                pass
    else:
        view['head'] = None
    return view


def normalise(got):
    """Turns the probe's exact-number strings back into numbers."""
    out = dict(got)
    out['section_entropy'] = [float(x) for x in got.get('section_entropy', [])]
    if got.get('resource_slack') is not None:
        out['resource_slack'] = {'size': got['resource_slack']['size'], 'entropy': float(got['resource_slack']['entropy'])}
    if got.get('overlay_entropy') is not None:
        out['overlay_entropy'] = dict(got['overlay_entropy'], entropy=float(got['overlay_entropy']['entropy']))
    return out


def main():
    rng = random.Random(pe_parity.SEED)
    counts = {field: [0, 0] for field in FIELDS + tuple('head.' + f for f in HEAD_FIELDS)}
    shown = 0
    tally = {'both': 0, 'reference only': 0, 'C++ only': 0, 'neither': 0, 'reference method raised': 0,
             'head compared': 0, 'head valid on one side only': 0, 'files with any difference': 0}
    confirmed_files = 0
    variants_built = 0
    lines_read = unreadable_lines = probe_failures = 0
    stopped = False
    planned = 0

    with tempfile.TemporaryDirectory(prefix='mie-pea-') as tmp:
        bases = pe_parity.base_files(tmp)
        per_base = pe_parity.variants_per_base(len(bases))
        planned = per_base * len(bases)
        print(f'seed {pe_parity.SEED}; {per_base} damaged variants per base file; {len(bases)} base files; '
              f'packer rules given to both sides: {PACKER_RULES}')
        case_dir = os.path.join(tmp, 'cases')
        os.mkdir(case_dir)
        args = [PROBE, case_dir]
        for rule in PACKER_RULES:
            args += ['--packer-rule', rule]

        for batch in pe_parity.case_batches(bases, rng, case_dir, per_base):
            if pe_parity.deadline_passed():
                stopped = True
                break
            got, unreadable, code = pe_parity.run_probe(args, timeout=800)   # line feeds only, never str.splitlines()
            lines_read += len(got)
            unreadable_lines += unreadable
            if code != 0:
                probe_failures += 1
                print(f'FAIL  the probe ended with exit code {code} on a batch starting at {batch[0][1]}')
            for kind, name, data in batch:
                variants_built += 1 if kind == 'variant' else 0
                want = reference_view(os.path.join(case_dir, name), data)
                have = got.get(name)
                cpp_parsed = bool(have and have.get('parsed'))
                if want is None or not cpp_parsed:
                    key = ('neither' if want is None and not cpp_parsed else
                           'C++ only' if want is None else 'reference only')
                    tally[key] += 1
                    continue
                if 'raises' in want:
                    tally['reference method raised'] += 1
                    continue
                tally['both'] += 1
                have = normalise(have)
                if want['confirmed_upx_sections']:
                    confirmed_files += 1
                different = False
                for field in FIELDS:
                    counts[field][0] += 1
                    if want[field] != have.get(field):
                        counts[field][1] += 1
                        different = True
                        if shown < 20:
                            shown += 1
                            print(f'DIFFERENT {name}: {field}: reference {want[field]!r}  C++ {have.get(field)!r}')
                head_want, head_have = want['head'], have.get('head')
                if head_want is None or head_have is None or 'raises' in head_want:
                    if (head_want is None) != (head_have is None):
                        tally['head valid on one side only'] += 1
                else:
                    tally['head compared'] += 1
                    for field in HEAD_FIELDS:
                        counts['head.' + field][0] += 1
                        if head_want[field] != head_have.get(field):
                            counts['head.' + field][1] += 1
                            different = True
                            if shown < 20:
                                shown += 1
                                print(f'DIFFERENT {name}: head.{field}: reference {head_want[field]!r}  '
                                      f'C++ {head_have.get(field)!r}')
                if different:
                    tally['files with any difference'] += 1

    print(f'probe: {lines_read} lines read, {unreadable_lines} unreadable')
    print(f'{len(bases)} base files, {variants_built} damaged variants; ' + '; '.join(f'{k}: {v}' for k, v in tally.items()))
    print(f'files where the packer layout is confirmed in the reference: {confirmed_files}')
    total_different = 0
    for field in sorted(counts):
        compared, different = counts[field]
        total_different += different
        print(f'{field}: {compared} compared, {different} different')
    problems = []
    if probe_failures or unreadable_lines:
        problems.append(f'the probe failed on {probe_failures} batches; {unreadable_lines} lines could not be read')
    if stopped:
        print(f'pe_analysis_parity: STOPPED AT THE DEADLINE ({pe_parity.deadline_text()}) after {variants_built} '
              f'damaged variants of {planned} planned; coverage checks NOT DONE')
    else:
        if variants_built < 2000:
            problems.append(f'only {variants_built} variants were built (at least 2,000 are required)')
        if tally['both'] == 0:
            problems.append('no file parsed on both sides: nothing was compared')
        if confirmed_files == 0:
            problems.append('no file with a confirmed packer layout: confirmed_upx_sections was never exercised')
    for problem in problems:
        print('FAIL  ' + problem)
    print(f'pe_analysis_parity: compared {variants_built} damaged variants')
    print(f'pe_analysis_parity: {total_different} differences')
    if total_different or problems:
        return 1
    return 3 if stopped else 0


if __name__ == '__main__':
    sys.exit(main())
