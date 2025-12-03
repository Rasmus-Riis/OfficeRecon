from utils.helpers import NS, log_info, log_warning, log_success, log_danger

class ProtectionAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Document Protection Analysis ---")
        self._check_document_protection()
        self._check_section_protection()

    def _check_document_protection(self):
        """Check for document-level protection."""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree:
            return

        # Check for document protection
        doc_protection = tree.xpath('//w:documentProtection', namespaces=NS)
        
        if not doc_protection:
            log_success("No document protection detected.")
            return
        
        prot = doc_protection[0]
        edit_type = prot.get(f"{{{NS['w']}}}edit", '')
        enforcement = prot.get(f"{{{NS['w']}}}enforcement", '0')
        
        # Check for password hash
        hash_value = prot.get(f"{{{NS['w']}}}hash", '')
        salt = prot.get(f"{{{NS['w']}}}salt", '')
        algo = prot.get(f"{{{NS['w']}}}algorithmName", 'legacy')
        
        if enforcement == '1' or enforcement == 'true' or enforcement == '1':
            log_warning("Document protection is ENABLED:")
            
            edit_types = {
                'none': 'Read-only',
                'comments': 'Comments only',
                'trackedChanges': 'Tracked changes only',
                'forms': 'Form fields only'
            }
            print(f"  Type: {edit_types.get(edit_type, edit_type)}")
            
            if hash_value:
                log_danger("  Password protected!")
                print(f"    Algorithm: {algo}")
                print(f"    Hash: {hash_value[:20]}...")
                if salt:
                    print(f"    Salt: {salt[:20]}...")
                print("    [FORENSIC NOTE]: Document was password-protected.")
            else:
                log_info("  No password hash found - protection may have been bypassed!")
        else:
            log_info("Document protection exists but is NOT enforced.")
            if hash_value:
                print("  [FORENSIC ALERT]: Password hash present but enforcement disabled!")
                print("  → Protection may have been removed/bypassed")

    def _check_section_protection(self):
        """Check for section-level protection."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # Check for protected sections
        sections = tree.xpath('//w:sectPr', namespaces=NS)
        protected_sections = []
        
        for i, section in enumerate(sections):
            form_prot = section.xpath('.//w:formProt', namespaces=NS)
            if form_prot:
                val = form_prot[0].get(f"{{{NS['w']}}}val", '1')
                if val == '1' or val == 'true':
                    protected_sections.append(i + 1)
        
        if protected_sections:
            log_warning(f"Found {len(protected_sections)} protected sections: {protected_sections}")
            print("  → These sections are restricted to form field editing only")
