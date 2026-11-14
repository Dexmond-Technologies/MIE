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
    # Packing is a property, not malice (X10). The engine puts a finding
    # in the 'packing' family (family='packing') only when the packer is
    # CONFIRMED and the finding is on the packer's own sections; the cap
    # keeps a confirmed packer alone below MEDIUM (30). A fake marker folds
    # nothing, so it cannot hide independent evidence.
    FAMILY_CAPS = {
        'packing': 25,
    }

    # Never lowered by a trusted signature: hard evidence, not heuristics
    UNCAPPABLE_FAMILIES = {'critical_yara', 'reputation_malicious'}
    # Highest score a heuristic-only file reaches under a trusted signature
    SIGNED_CAP = 29

    def __init__(self):
        self.floor = 0
        self.heuristic_cap = None
        self.findings: List[Dict] = []

    def cap_heuristics(self, cap: int = None):
        '''A valid signature from a trusted publisher (X12): the heuristic
        families together count at most `cap` (LOW). Critical YARA, the
        reputation list and floors are not affected.'''
        self.heuristic_cap = self.SIGNED_CAP if cap is None else cap

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

    def _family(self, finding: Dict) -> str:
        if finding.get('family'):
            return finding['family']
        category = finding['category']
        return self.FAMILIES.get(category, category)

    def family_scores(self) -> Dict[str, int]:
        '''Score per family after caps (floor findings excluded).'''
        totals: Dict[str, int] = {}
        for f in self.findings:
            if f.get('mode') == 'floor':
                continue
            fam = self._family(f)
            totals[fam] = totals.get(fam, 0) + f['weight']
        return {fam: min(total, self.FAMILY_CAPS.get(fam, total)) for fam, total in totals.items()}

    @property
    def score(self) -> int:
        fams = self.family_scores()
        hard = sum(v for f, v in fams.items() if f in self.UNCAPPABLE_FAMILIES)
        soft = sum(v for f, v in fams.items() if f not in self.UNCAPPABLE_FAMILIES)
        if self.heuristic_cap is not None:
            soft = min(soft, self.heuristic_cap)
        return hard + soft

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
