# X12 v2: provisioning and review (SENTINEL, 2026-11-14)

## (1) Pinned root store: `authenticode_roots.pem` → commit it as `trust/authenticode_roots.pem`
Set in signature.py: `PINNED_ROOTS_SHA256 = "59934744aa41b1432da5196f37e97bac269df7be62bb02d65b74d08d80b6d2c4"`

| root | sha256 fingerprint | valid | source |
|---|---|---|---|
| Microsoft Root Certificate Authority 2011 | 84:7D:F6:A7:84:97:94:3F:27:FC:72:EB:93:F9:A6:37:32:0A:02:B5:61:D0:A9:1B:09:E8:7A:78:07:ED:7C:61 | 2011–2036 | https://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt |
| Microsoft Root Certificate Authority 2010 | DF:54:5B:F9:19:A2:43:9C:36:98:3B:54:CD:FC:90:3D:FA:4F:37:D3:99:6D:8D:84:B4:C3:1E:EC:6F:3C:16:3E | 2010–2035 | https://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt |
| Microsoft Root Certificate Authority (2001) | 88:5D:E6:4C:34:0E:3E:A7:06:58:F0:1E:11:45:F9:57:FC:DA:27:AA:BE:EA:1A:B9:FA:A9:FD:B0:10:2D:40:77 | 2001–**2021 (expired)** | https://www.microsoft.com/pki/certs/MicrosoftRootCert.crt |

**How the roots were proven:**
- Downloaded over HTTPS only (no redirect to HTTP), with the owner's OK.
- Then I extracted all 319 certificates embedded in the 147 Sysinternals signatures of corpus v1. **All 6 distinct Microsoft intermediates verify cryptographically against these roots**: Code Signing PCA 2011 and PCA 2024 (root 2011); Code Signing PCA ×2 and Time-Stamp PCA (root 2001); Windows Production PCA 2023 (root 2010). 0 failures.
- The 2001 root is expired. It still validates **old, timestamped** signatures, because validity is checked at the countersignature time (check 5).
- **Deliberately left out:**
  - the 1997 "Microsoft Root Authority" (MD5 era): 2 files chain to it, and they will get no cap;
  - the third-party Thawte and VeriSign timestamping roots: 1–2 old files, whose timestamps then don't count.

## (2) Lock: `requirements-signify.lock` (pip `--require-hashes`)
- For CPython 3.13, x86_64 Linux, which is what I assume for tiny. Check: `python3 -V; uname -m`.
- Packages: signify 0.9.3, asn1crypto 1.5.1, certvalidator 0.11.1, oscrypto 1.3.0, mscerts 2026.10.27, typing-extensions 4.16.0. All are pure-Python wheels, downloaded from PyPI and hashed.
- **mscerts is signify's bundled Microsoft trust store.** It gets installed as a dependency, and it **must not be used**. The throwaway-root test (skipped today) has to prove that verification uses only our store.
- **Known risk:** oscrypto 1.3.0 has a libcrypto-version detection bug with some OpenSSL 3.x version strings, and its fix is only in oscrypto's git, not on PyPI. If it triggers on tiny, every check returns `unavailable`: it fails closed, so no cap. Then the choice is to pin oscrypto to a reviewed git commit, or to replace certvalidator. Report what the tiny run shows.

## (3) Code review of signature.py at 5e4b052 (4a8f6ab not received; send the bundle)
**PASS UNDER REVIEW. Must-tests are owed.**
- The precheck matches the design: nothing after the table, ≤1 MiB, revision 2.0 / PKCS#7, the DER length equals dwLength, zero alignment.
  - Note: it only accepts `30 82` DER headers, so PKCS#7 blobs over 64 KiB are refused (fail-closed). That's fine; record it.
- `pe.verify(multi_verify_mode='first', trusted_certificate_store=<pinned>, allow_fetching=False)`. A `TypeError` (API mismatch) is re-raised and becomes `unavailable`. Other errors give `invalid`. The leaf EKU must be code signing, checked separately. Validity is at the countersignature time, else now. The publisher allowlist decides only the cap.
- **Must-test added (T-TS):** a signature whose **countersignature** chains to a root that is *not* in the pinned store. The timestamp must then be ignored (validity checked now), not trusted. signify might check countersignatures against its own default store, i.e. mscerts; this test settles it.
- Timeout: the thread keeps running after 2 s (flagged). It's acceptable for a scanner, because the result is already "unavailable". Bound it later with a process pool if it shows up in time per file.
- Page hashes aren't checked separately (flagged). The image digest covers the same bytes; acceptable.

**Order:** commit the store + sha + lock → run the skipped real-binary tests on tiny, including the throwaway-root test and T-TS → send me the output → then the single final candidate run on v1 + B'.
