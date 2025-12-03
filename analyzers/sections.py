from utils.helpers import NS, log_info, log_warning, log_success

class SectionAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.sections = []

    def run(self):
        print("\n--- Section & Document Structure Analysis ---")
        self._extract_sections()
        self._analyze_sections()

    def _extract_sections(self):
        """Extract all section properties from document."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # Sections are defined by w:sectPr elements
        sections = tree.xpath('//w:sectPr', namespaces=NS)
        
        for idx, section in enumerate(sections):
            section_info = {
                'index': idx + 1,
                'page_size': {},
                'margins': {},
                'headers_footers': {},
                'columns': 1,
                'page_numbering': {},
                'protection': {}
            }
            
            # Page size
            pg_sz = section.xpath('.//w:pgSz', namespaces=NS)
            if pg_sz:
                section_info['page_size'] = {
                    'width': pg_sz[0].get(f"{{{NS['w']}}}w", ''),
                    'height': pg_sz[0].get(f"{{{NS['w']}}}h", ''),
                    'orientation': pg_sz[0].get(f"{{{NS['w']}}}orient", 'portrait')
                }
            
            # Margins
            pg_mar = section.xpath('.//w:pgMar', namespaces=NS)
            if pg_mar:
                section_info['margins'] = {
                    'top': pg_mar[0].get(f"{{{NS['w']}}}top", ''),
                    'right': pg_mar[0].get(f"{{{NS['w']}}}right", ''),
                    'bottom': pg_mar[0].get(f"{{{NS['w']}}}bottom", ''),
                    'left': pg_mar[0].get(f"{{{NS['w']}}}left", ''),
                    'header': pg_mar[0].get(f"{{{NS['w']}}}header", ''),
                    'footer': pg_mar[0].get(f"{{{NS['w']}}}footer", '')
                }
            
            # Column count
            cols = section.xpath('.//w:cols', namespaces=NS)
            if cols:
                num_cols = cols[0].get(f"{{{NS['w']}}}num", '1')
                section_info['columns'] = int(num_cols) if num_cols else 1
            
            # Page numbering format
            pg_num_type = section.xpath('.//w:pgNumType', namespaces=NS)
            if pg_num_type:
                section_info['page_numbering'] = {
                    'format': pg_num_type[0].get(f"{{{NS['w']}}}fmt", 'decimal'),
                    'start': pg_num_type[0].get(f"{{{NS['w']}}}start", '1')
                }
            
            # Section type (continuous, nextPage, etc.)
            section_type = section.xpath('.//w:type', namespaces=NS)
            if section_type:
                section_info['type'] = section_type[0].get(f"{{{NS['w']}}}val", 'nextPage')
            
            # Header/footer references
            header_refs = section.xpath('.//w:headerReference', namespaces=NS)
            footer_refs = section.xpath('.//w:footerReference', namespaces=NS)
            
            section_info['headers_footers'] = {
                'headers': len(header_refs),
                'footers': len(footer_refs)
            }
            
            self.sections.append(section_info)

    def _analyze_sections(self):
        """Analyze sections for unusual configurations."""
        if not self.sections:
            log_success("Single section document with standard settings.")
            return
        
        log_info(f"Document has {len(self.sections)} section(s)")
        
        for section in self.sections:
            print(f"\n[SECTION {section['index']}]:")
            
            # Page size
            if section['page_size']:
                orientation = section['page_size'].get('orientation', 'portrait')
                print(f"  Orientation: {orientation.capitalize()}")
                
                # Check for custom size
                width = section['page_size'].get('width', '')
                height = section['page_size'].get('height', '')
                if width and height:
                    w_int = int(width)
                    h_int = int(height)
                    
                    # Check if not standard
                    if not ((11800 < w_int < 12000 and 16700 < h_int < 17000) or
                           (12200 < w_int < 12300 and 15800 < h_int < 15900)):
                        log_warning(f"  [CUSTOM PAGE SIZE]: {width} × {height} twips")
            
            # Columns
            if section['columns'] > 1:
                print(f"  Columns: {section['columns']}")
            
            # Page numbering
            if section['page_numbering']:
                fmt = section['page_numbering'].get('format', 'decimal')
                start = section['page_numbering'].get('start', '1')
                if fmt != 'decimal' or start != '1':
                    print(f"  Page numbering: {fmt}, starting at {start}")
            
            # Section type
            if 'type' in section and section['type'] != 'nextPage':
                print(f"  Section break: {section['type']}")
            
            # Headers/footers
            hf = section['headers_footers']
            if hf['headers'] > 0 or hf['footers'] > 0:
                print(f"  Headers: {hf['headers']}, Footers: {hf['footers']}")
            
            # Check for suspicious margins
            margins = section['margins']
            if margins:
                if any(margins.get(k) and int(margins[k]) < 200 for k in ['top', 'bottom', 'left', 'right']):
                    log_warning("  [UNUSUAL MARGINS]: Very small margins detected (potential hiding space)")
