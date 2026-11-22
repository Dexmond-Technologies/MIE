# The four frozen interfaces of the stage 1 engine (version 1)

"Frozen" means: the parallel tracks build against these. A change needs a new version number
and a note here; nothing is changed silently.

Status: written in week 0. Interfaces 1 to 3 have code and tests. Interface 4 is data only:
no C++ code computes a score or a verdict yet (the synthetic parity set comes first).

## 1. Finding format

One piece of evidence. C++: `mie::Finding` in `include/mie/result.hpp`.

| field | type | meaning |
|---|---|---|
| `category` | text | a row of the scoring table, for example `high_entropy` |
| `family` | text | family the weight counts in; empty = the category's default family |
| `weight` | whole number | points |
| `description` | text | for people |
| `floor` | true/false | true: raises the score to at least `weight` instead of adding to it |

## 2. Result format (schema version 1)

What one scan says about one subject. C++: `mie::ScanResult`. JSON through `mie::to_json` /
`mie::from_json`: keys sorted, no white space, so equal results are equal bytes; the reader
refuses unknown fields, wrong types and unknown schema versions.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `subject.kind` | `file` | stage 2 adds further kinds; the other fields stay |
| `subject.sha256` | text | identity of the file |
| `subject.display_name` | text | for people; never used as a path |
| `state` | `scanned`, `not_fully_scanned`, `not_scanned` | `not_fully_scanned`: a limit, a crash or an unsupported part cut the scan; such a result is never CLEAN. `not_scanned`: refused or unreadable; no score |
| `reason` | text | why the state is not `scanned`; empty otherwise |
| `score` | whole number | 0 to 100 |
| `verdict` | text | the reference's verdict texts; empty until a scorer exists |
| `findings` | list of findings | |
| `hashes.md5`, `hashes.sha1`, `hashes.sha256` | lower-case hex | |
| `size` | whole number | bytes |

## 3. Channel messages (protocol version 1)

How the interface and the command line talk to the service. There is no network listener.

Transport:
- Windows: named pipe `\\.\pipe\DexmondMIE.<user SID>.service`, byte mode, created with the
  current user as owner and as the only entry of the access list, remote clients rejected,
  first instance exclusive (this is also the single-instance rule). A client checks that the
  pipe it opened is owned by the current user before it sends anything.
- Linux, macOS: Unix-domain socket `service.sock` in `$XDG_RUNTIME_DIR/dexmond-mie/`, or in
  `/tmp/dexmond-mie-<uid>/` when that variable is not set. The directory must be a real
  directory owned by the user with no access for anyone else: the service creates it 0700, the
  client checks it. The service checks the user id of every peer. Single instance: an exclusive
  lock on `service.sock.lock`.

Frame: 4 bytes, the length of the JSON text, big-endian; then the JSON text in UTF-8.
Length 0 and lengths above 1 MiB (1,048,576) are refused before any text is read.
Nesting deeper than 32 is refused before parsing.

JSON text: one object with exactly these fields; any other field is refused, not ignored.

| field | type | meaning |
|---|---|---|
| `v` | 1 | protocol version |
| `id` | non-negative whole number | chosen by the requester; the response carries the same |
| `type` | `request`, `response`, `event` | |
| `op` | 1 to 64 characters of `a-z 0-9 . _ -` | operation name |
| `body` | object, optional | parameters or answer; a response body carries `ok` true/false |

Operations of version 1:

| op | built in week 0 | request body | response body |
|---|---|---|---|
| `ping` | yes | none | `{"ok":true,"pong":true}` |
| `status` | yes | none | `ok`, `service`, `version`, `protocol`, `result_schema`, `pid`, `engine` (`absent` in week 0), `monitoring`, `rules` |
| `shutdown` | yes | none | `{"ok":true,"stopping":true}` |
| `scan` | no (reserved) | `{"path": text}` | a result in format 2 |
| `quarantine.list`, `quarantine.add`, `quarantine.restore`, `quarantine.delete` | no (reserved) | | |
| `trusted.list`, `trusted.add`, `trusted.remove` | no (reserved) | | |
| anything else | | | `{"ok":false,"error":"unknown_op"}` |

Events (`type` = `event`, service to client) are reserved for scan progress and alerts.

## 4. Scoring data file

`engine/data/scoring.reference.json`: the weights, families, family caps, the signature cap,
the verdict boundaries and labels, and the engine's limits, copied from the Python reference
at commit ff313e2. `engine/tools/check_scoring_data.py` compares every value with the
reference source files on every push. This is the PARITY profile's data: it reproduces the
reference, defects included, and never ships (see the design, section 7b). The stage 1
profile will be a second file with the numbered differences switched on.

## Comparison format of the parity harness

Not one of the four, but shared by the Python reference runner and the future C++ runner:
`engine/tools/parity/run_reference.py` (docstring) defines the JSON-lines format,
`engine/tools/parity/compare.py` the comparison rules (r-01's pass line for A-1).
