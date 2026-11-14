from typing import List, Dict


class Scorer:
    '''Calculates maliciousness score based on weighted signals.'''
    WEIGHTS = {
        'yara_match': 20,
        'critical_yara': 70,
        'high_entropy': 15,
        'sliding_entropy_spike': 20,
        'suspicious_import': 10,
        'api_chain': 35,
        'suspicious_string': 5,
        'obfuscated_script': 25,
        'b64_executable': 30,
        'packer_detected': 25,
        'pe_overlay': 15,
        'tls_callback': 20,
        'anomaly': 10,
        'reputation_malicious': 70}

    def __init__(self):
        self.score = 0
        self.floor = 0
        self.findings: List[Dict] = []

    def set_floor(self, floor: int):
        '''Sets a minimum score (used for a malicious reputation hit).'''
        self.floor = max(self.floor, floor)

    def add_finding(self, category: str, description: str, weight_override=None):
        '''Adds a finding and updates the score.'''
        weight = weight_override if weight_override is not None else self.WEIGHTS.get(category, 5)
        self.score += weight
        self.findings.append({
            'category': category,
            'description': description,
            'weight': weight})

    def get_score(self) -> int:
        '''Returns the final score, capped at 100.'''
        return min(max(self.score, self.floor), 100)

    def get_verdict(self) -> str:
        score = self.get_score()
        if score == 0:
            return 'CLEAN'
        if score < 30:
            return 'SUSPICIOUS (LOW)'
        if score < 70:
            return 'SUSPICIOUS (MEDIUM)'
        return 'MALICIOUS'
