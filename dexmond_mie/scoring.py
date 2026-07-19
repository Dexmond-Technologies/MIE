from typing import List, Dict


class Scorer:
    '''Calculates maliciousness score based on weighted signals.'''
    WEIGHTS = {
        'yara_match': 20,
        'critical_yara': 70,
        'high_entropy': 15,
        'suspicious_import': 10,
        'suspicious_string': 5,
        'packer_detected': 25,
        'anomaly': 10}

    def __init__(self):
        self.score = 0
        self.findings: List[Dict] = []

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
        return min(self.score, 100)

    def get_verdict(self) -> str:
        score = self.get_score()
        if score == 0:
            return 'CLEAN'
        if score < 30:
            return 'SUSPICIOUS (LOW)'
        if score < 70:
            return 'SUSPICIOUS (MEDIUM)'
        return 'MALICIOUS'
