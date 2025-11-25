from utils.helpers import NS, log_danger, log_warning, log_success, log_info
try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

class MacroScanner:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Macro & Script Detection ---")
        self._check_content_types()
        self._deep_macro_analysis()

    def _check_content_types(self):
        """Checks internal MIME types (Basic check)."""
        tree = self.loader.get_xml_tree('[Content_Types].xml')
        if not tree: return

        ct_ns = {'ct': 'http://schemas.openxmlformats.org/package/2006/content-types'}
        overrides = tree.xpath('//ct:Override', namespaces=ct_ns)
        
        is_macro_enabled = False
        for o in overrides:
            if 'macroEnabled' in o.get('ContentType', ''):
                is_macro_enabled = True
                break

        if is_macro_enabled:
            log_warning("Internal MIME type identifies as 'Macro-Enabled' (docm).")

    def _deep_macro_analysis(self):
        """Uses OLETOOLS to scan for malicious behavior keywords."""
        if not OLETOOLS_AVAILABLE:
            print("   [!] 'oletools' library not found. Skipping deep scan.")
            return

        # OLETools can parse the zip file directly from disk
        vbaparser = VBA_Parser(self.loader.filepath)
        
        if vbaparser.detect_vba_macros():
            log_danger("VBA MACROS DETECTED! Scanning code for threats...")
            
            # Analyze the macros
            results = vbaparser.analyze_macros()
            
            suspicious_count = 0
            for kw_type, keyword, description in results:
                # Filter for interesting events
                if kw_type in ('Suspicious', 'AutoExec'):
                    print(f"   -> [THREAT] {keyword}: {description}")
                    suspicious_count += 1
            
            if suspicious_count > 0:
                log_danger(f"Found {suspicious_count} malicious indicators in VBA code.")
            else:
                log_warning("Macros present, but no standard malicious keywords found.")
        else:
            log_success("No VBA Macros found in document structure.")
            
        vbaparser.close()