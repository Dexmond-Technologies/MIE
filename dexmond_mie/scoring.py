from typing import List, Dict


class Scorer:
    '''Calculates maliciousness score based on weighted signals.

    Findings are grouped into families. A family with a cap contributes at
    most that much, however many findings it has, so one kind of evidence
    seen several ways is not counted several times. Floors (reputation hit,
    worst archive member) set a minimum after the caps.
    '''
    WEIGHTS = {
        'yara_match': 20,
        'critical_yara': 70,
        'high_entropy': 15,
        'sliding_entropy_spike': 10,
        'suspicious_import': 10,
        'api_chain': 35,
        'api_chain_minor': 15,
        'dynamic_resolution_chain': 15,
        'suspicious_string': 5,
        'obfuscated_script': 25,
        'b64_executable': 30,
        'packer_detected': 15,
        'pe_overlay': 15,
        'tls_callback': 5,
        'anomaly': 10,
        'wx_section': 10,
        'reputation_malicious': 70,
        'oversize_partial_scan': 5,
        'malformed_pe': 10,
        'overlay_high_entropy': 5,
        'malformed_certificate_table': 10}

    # category -> family (categories not listed form their own family)
    FAMILIES = {
        'packer_detected': 'packing',
    }
    # Packing is a property, not malice (X10). When a packer is detected,
    # the signals packing itself causes (high-entropy sections, W+X
    # sections, TLS callbacks, a stub that resolves imports at run time) are
    # the same evidence and join the packing
    # family, whose cap keeps a packer alone below MEDIUM (30).
    PACKING_CONSEQUENCES = {'high_entropy', 'wx_section', 'tls_callback',
                            'dynamic_resolution_chain'}
    FAMILY_CAPS = {
        'packing': 25,
    }

    def __init__(self):
        self.floor = 0
        self.findings: List[Dict] = []

    def set_floor(self, floor: int):
        '''Sets a minimum score (used for a malicious reputation hit).'''
        self.floor = max(self.floor, floor)

    def add_finding(self, category: str, description: str, weight_override=None, family=None):
        '''Adds a finding. `family` overrides the category's default family.'''
        weight = weight_override if weight_override is not None else self.WEIGHTS.get(category, 5)
        finding = {'category': category, 'description': description, 'weight': weight}
        if family:
            finding['family'] = family
        self.findings.append(finding)

    def add_floor_finding(self, category: str, description: str, floor: int):
        '''Records a finding that raises the score to at least `floor`
        instead of adding to it (an archive takes its worst member's score).'''
        self.set_floor(floor)
        self.findings.append({
            'category': category,
            'description': description,
            'weight': floor,
            'mode': 'floor'})

    def _family(self, finding: Dict, packer_present: bool) -> str:
        if finding.get('family'):
            return finding['family']
        category = finding['category']
        if packer_present and category in self.PACKING_CONSEQUENCES:
            return 'packing'
        return self.FAMILIES.get(category, category)

    def family_scores(self) -> Dict[str, int]:
        '''Score per family after caps (floor findings excluded).'''
        packer_present = any(self._family(f, False) == 'packing' for f in self.findings)
        totals: Dict[str, int] = {}
        for f in self.findings:
            if f.get('mode') == 'floor':
                continue
            fam = self._family(f, packer_present)
            totals[fam] = totals.get(fam, 0) + f['weight']
        return {fam: min(total, self.FAMILY_CAPS.get(fam, total)) for fam, total in totals.items()}

    @property
    def score(self) -> int:
        return sum(self.family_scores().values())

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
