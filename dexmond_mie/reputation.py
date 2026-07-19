import os
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger('DEXMOND_MIE')


class ReputationDB:
    '''Local known-hash reputation list.

    Gives instant verdicts for previously classified files. SHA-256 keys map to
    either a malicious label (forces MALICIOUS) or a trusted label (forces CLEAN),
    short-circuiting the full analysis pipeline.
    '''

    def __init__(self, db_path: str = './data/reputation.json'):
        self.db_path = os.path.abspath(db_path)
        self.malicious: Dict[str, str] = {}
        self.trusted: Dict[str, str] = {}
        self._load()

    def _load(self):
        try:
            with open(self.db_path) as f:
                data = json.load(f)
            self.malicious = {k.lower(): v for k, v in data.get('malicious', {}).items()}
            self.trusted = {k.lower(): v for k, v in data.get('trusted', {}).items()}
            logger.info(f'Reputation DB: {len(self.malicious)} known-bad, '
                        f'{len(self.trusted)} known-good hashes')
        except (OSError, json.JSONDecodeError):
            logger.info('Reputation DB not found; starting empty')

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with open(self.db_path, 'w') as f:
                json.dump({'malicious': self.malicious, 'trusted': self.trusted}, f, indent=2)
        except OSError as e:
            logger.error(f'Failed to save reputation DB: {e}')

    def lookup(self, sha256: str) -> Optional[Dict]:
        '''Returns a verdict dict if the hash is known, else None.'''
        if not sha256:
            return None
        h = sha256.lower()
        if h in self.malicious:
            return {'reputation': 'malicious', 'label': self.malicious[h]}
        if h in self.trusted:
            return {'reputation': 'trusted', 'label': self.trusted[h]}
        return None

    def add_malicious(self, sha256: str, label: str = 'user-flagged'):
        self.malicious[sha256.lower()] = label
        self.trusted.pop(sha256.lower(), None)
        self._save()

    def add_trusted(self, sha256: str, label: str = 'user-trusted'):
        self.trusted[sha256.lower()] = label
        self.malicious.pop(sha256.lower(), None)
        self._save()

    @property
    def counts(self) -> Dict[str, int]:
        return {'malicious': len(self.malicious), 'trusted': len(self.trusted)}
