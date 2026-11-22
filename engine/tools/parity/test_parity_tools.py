"""Tests of the parity harness itself (pytest, run in CI).

The comparison rules tested here are r-01's pass line for A-1 (board B-3484): all four fields
compared, no verdict difference of any cause, explained differences need a named library and
field, missing files fail.
The reference runner is tested on three harmless generated files; no malware, no EICAR.
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare  # noqa: E402

RULES = {'eicar.yar': 'aa', 'packers.yar': 'bb'}


def header(rules=None):
    return {'record': 'header', 'producer': 'test', 'rules': RULES if rules is None else rules}


def rec(path, score=0, verdict='CLEAN', categories=(), sha='0' * 64, error=None):
    return {'record': 'file', 'path': path, 'sha256': sha, 'size': 1, 'score': score,
            'verdict': verdict, 'categories': list(categories), 'error': error}


def side(*records, rules=None):
    return header(rules), {r['path']: r for r in records}


def test_identical_sets_pass():
    a = side(rec('a.bin'), rec('b.bin', 35, 'SUSPICIOUS (MEDIUM)', ['api_chain']))
    b = side(rec('a.bin'), rec('b.bin', 35, 'SUSPICIOUS (MEDIUM)', ['api_chain']))
    report = compare.compare(a, b, {}, 5)
    assert report['pass'] and report['identical'] == 2


def test_score_difference_without_explanation_fails():
    a = side(rec('a.bin', 10, 'SUSPICIOUS (LOW)', ['anomaly']))
    b = side(rec('a.bin', 15, 'SUSPICIOUS (LOW)', ['anomaly']))
    report = compare.compare(a, b, {}, 5)
    assert not report['pass'] and len(report['unexplained']) == 1


def test_explained_score_difference_is_counted_and_passes_within_cap():
    a = side(rec('a.bin', 10, 'SUSPICIOUS (LOW)', ['anomaly']))
    b = side(rec('a.bin', 15, 'SUSPICIOUS (LOW)', ['anomaly']))
    note = {'a.bin': {'library': 'LIEF', 'field': 'score', 'reason': 'section size read differently'}}
    report = compare.compare(a, b, note, 5)
    assert report['pass'] and len(report['explained']) == 1


def test_explanation_must_name_library_field_and_reason():
    a = side(rec('a.bin', 10, 'SUSPICIOUS (LOW)', ['anomaly']))
    b = side(rec('a.bin', 15, 'SUSPICIOUS (LOW)', ['anomaly']))
    for bad in ({'a.bin': {'field': 'score', 'reason': 'x'}},
                {'a.bin': {'library': 'LIEF', 'reason': 'x'}},
                {'a.bin': {'library': 'LIEF', 'field': 'categories', 'reason': 'x'}},
                {'a.bin': {'library': 'LIEF', 'field': 'score'}},
                {'a.bin': 'LIEF'}):
        assert not compare.compare(a, b, bad, 5)['pass']


def test_verdict_difference_fails_even_when_explained():
    a = side(rec('a.bin', 29, 'SUSPICIOUS (LOW)', ['anomaly']))
    b = side(rec('a.bin', 30, 'SUSPICIOUS (MEDIUM)', ['anomaly']))
    note = {'a.bin': {'library': 'LIEF', 'field': 'score', 'reason': 'x'}}
    report = compare.compare(a, b, note, 5)
    assert not report['pass'] and len(report['verdict_differences']) == 1


def test_more_explained_than_the_cap_fails():
    names = [f'f{i}.bin' for i in range(6)]
    a = side(*[rec(n, 10, 'SUSPICIOUS (LOW)', ['anomaly']) for n in names])
    b = side(*[rec(n, 15, 'SUSPICIOUS (LOW)', ['anomaly']) for n in names])
    notes = {n: {'library': 'LIEF', 'field': 'score', 'reason': 'x'} for n in names}
    assert not compare.compare(a, b, notes, 5)['pass']
    assert compare.compare(a, b, notes, 6)['pass']


def test_file_missing_on_one_side_fails():
    a = side(rec('a.bin'), rec('b.bin'))
    b = side(rec('a.bin'))
    assert not compare.compare(a, b, {}, 5)['pass']
    assert not compare.compare(b, a, {}, 5)['pass']


def test_category_difference_fails():
    a = side(rec('a.bin', 10, 'SUSPICIOUS (LOW)', ['anomaly']))
    b = side(rec('a.bin', 10, 'SUSPICIOUS (LOW)', ['tls_callback', 'suspicious_string']))
    assert not compare.compare(a, b, {}, 5)['pass']


def test_sha_difference_cannot_be_explained():
    a = side(rec('a.bin', sha='1' * 64))
    b = side(rec('a.bin', sha='2' * 64))
    note = {'a.bin': {'library': 'x', 'field': 'sha256', 'reason': 'x'}}
    assert not compare.compare(a, b, note, 5)['pass']


def test_error_text_is_compared():
    a = side(rec('a.bin', None, None, [], error='File not found'))
    b = side(rec('a.bin', None, None, [], error=None))
    assert not compare.compare(a, b, {}, 5)['pass']


def test_different_rule_files_fail():
    a = side(rec('a.bin'))
    b = side(rec('a.bin'), rules={'eicar.yar': 'aa', 'packers.yar': 'CHANGED'})
    assert not compare.compare(a, b, {}, 5)['pass']


def test_load_rejects_duplicates_and_missing_header(tmp_path):
    good = tmp_path / 'good.jsonl'
    good.write_text('\n'.join(json.dumps(x) for x in (header(), rec('a.bin'))) + '\n', encoding='utf-8')
    head, files = compare.load(str(good))
    assert head['record'] == 'header' and list(files) == ['a.bin']

    twice = tmp_path / 'twice.jsonl'
    twice.write_text('\n'.join(json.dumps(x) for x in (header(), rec('a.bin'), rec('a.bin'))) + '\n', encoding='utf-8')
    with pytest.raises(ValueError):
        compare.load(str(twice))

    headless = tmp_path / 'headless.jsonl'
    headless.write_text(json.dumps(rec('a.bin')) + '\n', encoding='utf-8')
    with pytest.raises(ValueError):
        compare.load(str(headless))


def test_identical_mode_ignores_order_and_header(tmp_path):
    a = tmp_path / 'a.jsonl'
    b = tmp_path / 'b.jsonl'
    lines = [json.dumps(rec('a.bin'), sort_keys=True), json.dumps(rec('b.bin'), sort_keys=True)]
    a.write_text(json.dumps(header(), sort_keys=True) + '\n' + '\n'.join(lines) + '\n', encoding='utf-8')
    b.write_text(json.dumps({'record': 'header', 'producer': 'other'}, sort_keys=True) + '\n'
                 + '\n'.join(reversed(lines)) + '\n', encoding='utf-8')
    assert compare.identical(str(a), str(b))
    b.write_text(json.dumps(header(), sort_keys=True) + '\n' + lines[0] + '\n', encoding='utf-8')
    assert not compare.identical(str(a), str(b))


def test_reference_runner_on_harmless_files(tmp_path):
    pytest.importorskip('yara')
    pytest.importorskip('pefile')
    corpus = tmp_path / 'corpus'
    (corpus / 'sub').mkdir(parents=True)
    (corpus / 'plain.txt').write_bytes(b'This is a plain text file.\n' * 20)
    (corpus / 'zeros.bin').write_bytes(bytes(5000))
    (corpus / 'sub' / 'numbers.csv').write_bytes(b'1,2,3\n4,5,6\n' * 50)

    runner = os.path.join(HERE, 'run_reference.py')
    outs = []
    for name in ('run1.jsonl', 'run2.jsonl'):
        out = tmp_path / name
        done = subprocess.run([sys.executable, runner, '--corpus', str(corpus), '--out', str(out)],
                              capture_output=True, text=True, timeout=300)
        assert done.returncode == 0, done.stderr
        outs.append(str(out))

    head, files = compare.load(outs[0])
    assert head['producer'] == 'python-reference'
    assert head['rules'] and all(len(v) == 64 for v in head['rules'].values())
    assert head['yara_library'], 'the YARA library version must be on record (r-01 M-12)'
    assert sorted(files) == ['plain.txt', 'sub/numbers.csv', 'zeros.bin']
    for record in files.values():
        assert record['error'] is None
        assert len(record['sha256']) == 64
        assert isinstance(record['score'], int)
        assert record['verdict'] in ('CLEAN', 'SUSPICIOUS (LOW)', 'SUSPICIOUS (MEDIUM)', 'MALICIOUS')
        assert record['categories'] == sorted(record['categories'])
    # determinism: two runs of the reference give the same lines
    assert compare.identical(outs[0], outs[1])
    report = compare.compare(compare.load(outs[0]), compare.load(outs[1]), {}, 0)
    assert report['pass'] and report['identical'] == 3
