from utils.helpers import NS, log_info, log_warning, log_success

class PrinterAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Printer & Page Setup Forensics ---")
        self._extract_printer_info()
        self._analyze_page_setup()

    def _extract_printer_info(self):
        """Extract printer settings which can reveal corporate environment."""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree:
            return

        # Check for printer settings
        printer_settings = tree.xpath('//w:printerSettings', namespaces=NS)
        
        if printer_settings:
            # The printer settings are usually stored as a binary blob
            log_warning("Printer settings embedded in document")
            print("  → Document contains printer configuration")
            print("  → [FORENSIC NOTE]: May reveal corporate network printer names")
        
        # Check for default printer name (if stored in custom properties)
        # This is less common but can appear
        active_printer = tree.xpath('//w:activePrinter', namespaces=NS)
        if active_printer and active_printer[0].text:
            log_info(f"Active Printer: {active_printer[0].text}")

    def _analyze_page_setup(self):
        """Analyze page setup for unusual configurations."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        sections = tree.xpath('//w:sectPr', namespaces=NS)
        
        unusual_setups = []
        
        for i, section in enumerate(sections):
            # Check page size
            pg_sz = section.xpath('.//w:pgSz', namespaces=NS)
            if pg_sz:
                width = pg_sz[0].get(f"{{{NS['w']}}}w", '')
                height = pg_sz[0].get(f"{{{NS['w']}}}h", '')
                
                # Standard A4: 11906 x 16838 (in twips)
                # Standard Letter: 12240 x 15840
                if width and height:
                    w_int = int(width)
                    h_int = int(height)
                    
                    # Check if it's not A4 or Letter
                    if not ((11800 < w_int < 12000 and 16700 < h_int < 17000) or  # A4
                           (12200 < w_int < 12300 and 15800 < h_int < 15900)):    # Letter
                        unusual_setups.append({
                            'section': i + 1,
                            'width_twips': width,
                            'height_twips': height,
                            'type': 'Custom page size'
                        })
            
            # Check margins
            pg_mar = section.xpath('.//w:pgMar', namespaces=NS)
            if pg_mar:
                margins = {
                    'top': pg_mar[0].get(f"{{{NS['w']}}}top", ''),
                    'right': pg_mar[0].get(f"{{{NS['w']}}}right", ''),
                    'bottom': pg_mar[0].get(f"{{{NS['w']}}}bottom", ''),
                    'left': pg_mar[0].get(f"{{{NS['w']}}}left", '')
                }
                
                # Check for very small margins (potential hiding space)
                if margins['top'] and int(margins['top']) < 200:
                    unusual_setups.append({
                        'section': i + 1,
                        'type': 'Very small top margin',
                        'value': margins['top']
                    })
        
        if unusual_setups:
            log_warning(f"Found {len(unusual_setups)} unusual page setup configurations:")
            for setup in unusual_setups:
                print(f"  Section {setup['section']}: {setup['type']}")
                if 'value' in setup:
                    print(f"    Value: {setup['value']}")
        else:
            log_success("Standard page setup detected.")
