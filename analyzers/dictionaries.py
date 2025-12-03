from utils.helpers import NS, log_info, log_warning, log_success

class DictionaryAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.custom_dictionaries = []
        self.language_settings = []

    def run(self):
        print("\n--- Custom Dictionary & Language Analysis ---")
        self._extract_dictionary_info()
        self._extract_language_settings()
        self._report_findings()

    def _extract_dictionary_info(self):
        """Extract custom dictionary references."""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree:
            return

        # Check for custom dictionaries
        proof_state = tree.xpath('//w:proofState', namespaces=NS)
        if proof_state:
            for state in proof_state:
                spelling = state.get(f"{{{NS['w']}}}spelling", '')
                grammar = state.get(f"{{{NS['w']}}}grammar", '')
                if spelling or grammar:
                    self.custom_dictionaries.append({
                        'spelling': spelling,
                        'grammar': grammar
                    })
        
        # Check active writing style
        active_writing_style = tree.xpath('//w:activeWritingStyle', namespaces=NS)
        if active_writing_style:
            for style in active_writing_style:
                lang = style.get(f"{{{NS['w']}}}lang", '')
                vendor_id = style.get(f"{{{NS['w']}}}vendorID", '')
                dll_version = style.get(f"{{{NS['w']}}}dllVersion", '')
                
                if any([lang, vendor_id, dll_version]):
                    self.language_settings.append({
                        'type': 'Writing Style',
                        'language': lang,
                        'vendor': vendor_id,
                        'version': dll_version
                    })

    def _extract_language_settings(self):
        """Extract language and proofing settings."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # Get default language
        settings_tree = self.loader.get_xml_tree('word/settings.xml')
        if settings_tree:
            # Check theme font language
            theme_font_lang = settings_tree.xpath('//w:themeFontLang', namespaces=NS)
            if theme_font_lang:
                val = theme_font_lang[0].get(f"{{{NS['w']}}}val", '')
                bidi = theme_font_lang[0].get(f"{{{NS['w']}}}bidi", '')
                east_asia = theme_font_lang[0].get(f"{{{NS['w']}}}eastAsia", '')
                
                if val:
                    self.language_settings.append({
                        'type': 'Default Language',
                        'language': val,
                        'bidi': bidi,
                        'east_asia': east_asia
                    })

        # Look for language spans in document
        lang_spans = tree.xpath('//w:lang', namespaces=NS)
        languages_used = set()
        
        for span in lang_spans:
            val = span.get(f"{{{NS['w']}}}val", '')
            if val and val != 'en-US':  # Ignore default English
                languages_used.add(val)
        
        if languages_used:
            self.language_settings.append({
                'type': 'Languages in Document',
                'languages': ', '.join(sorted(languages_used))
            })

    def _report_findings(self):
        """Report custom dictionaries and language settings."""
        if not self.custom_dictionaries and not self.language_settings:
            log_success("Standard dictionary and language settings.")
            return
        
        if self.custom_dictionaries:
            log_warning(f"Found {len(self.custom_dictionaries)} custom dictionary reference(s):")
            for dictionary in self.custom_dictionaries:
                if dictionary['spelling']:
                    print(f"  • Spelling: {dictionary['spelling']}")
                if dictionary['grammar']:
                    print(f"  • Grammar: {dictionary['grammar']}")
        
        if self.language_settings:
            log_info(f"\n[LANGUAGE SETTINGS]: {len(self.language_settings)} configuration(s)")
            for setting in self.language_settings:
                print(f"\n  {setting['type']}:")
                if 'language' in setting and setting['language']:
                    print(f"    Language: {setting['language']}")
                if 'languages' in setting:
                    print(f"    Used: {setting['languages']}")
                if 'vendor' in setting and setting['vendor']:
                    print(f"    Vendor: {setting['vendor']}")
                if 'version' in setting and setting['version']:
                    print(f"    Version: {setting['version']}")
