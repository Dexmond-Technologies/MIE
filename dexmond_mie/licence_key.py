# The licence-verification key of MIE and the constants of the release gate.
# This is the only file that holds them. It is read in two ways:
#   - dexmond_mie/licence.py imports it to check licences;
#   - scripts/check_release_key.py reads it AS TEXT before a sale build.
# So each constant below stays one plain literal on the pattern it has now.
# Only public values belong here: a public key and SHA-256 fingerprints.
# Never a secret key.
#
# A fingerprint is the SHA-256, in lower-case hex, of the raw public key bytes
# (the 1952 bytes of an ML-DSA-65 public key that LICENSE_PUBLIC_KEY_B64
# decodes to).

# Public ML-DSA-65 licence-verification key of the product "mie" (base64,
# 1952 bytes). EMPTY: no MIE key exists yet. The matching secret key is made in
# the owner's offline ceremony, lives only with the activation service's
# signer, and is never in this repository or on a build machine.
LICENSE_PUBLIC_KEY_B64 = ""

# Fingerprint of the PRODUCTION public key. Until this holds that key's
# fingerprint and LICENSE_PUBLIC_KEY_B64 holds that key, a sale build fails.
PROD_PUBKEY_SHA256 = "UNSET-PRODUCTION-KEY-NOT-YET-CREATED"

# Fingerprints of development and test keys. A build that embeds one of these
# is a test build and can never pass the release gate. Entries are only ever
# added (a retired production key goes here too).
NON_PRODUCTION_PUBKEY_SHA256 = [
    "97349bc899e85f5460ef6c69c84415e2a41830750a8b4d7c1e74d60c5e9f4d70",
]

# MIE ships as 100% Free Edition (owner decision 2026-11-20 00:54:48+01:00: "mie is free");
# if licensing is ever wired in later, non-production builds show this notice.
TEST_BUILD_NOTICE = 'TEST BUILD: licences from this build are not valid for sale'
