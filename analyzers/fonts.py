from utils.helpers import NS, log_info, log_warning, log_success

class FontAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.embedded_fonts = []
        self.font_references = []

    def run(self):
        print("\n--- Font Embedding & Subsetting Analysis ---")
        self._extract_embedded_fonts()
        self._analyze_font_usage()
        self._report_findings()

    def _extract_embedded_fonts(self):
        """Extract embedded and obfuscated fonts."""
        tree = self.loader.get_xml_tree('word/fontTable.xml')
        if not tree:
            return

        fonts = tree.xpath('//w:font', namespaces=NS)
        
        for font in fonts:
            font_name = font.get(f"{{{NS['w']}}}name", '')
            
            # Check for embedded font data
            embed_regular = font.xpath('.//w:embedRegular', namespaces=NS)
            embed_bold = font.xpath('.//w:embedBold', namespaces=NS)
            embed_italic = font.xpath('.//w:embedItalic', namespaces=NS)
            embed_bold_italic = font.xpath('.//w:embedBoldItalic', namespaces=NS)
            
            embedded = []
            if embed_regular:
                font_key = embed_regular[0].get(f"{{{NS['r']}}}fontKey", '')
                embedded.append({'style': 'Regular', 'key': font_key})
            if embed_bold:
                font_key = embed_bold[0].get(f"{{{NS['r']}}}fontKey", '')
                embedded.append({'style': 'Bold', 'key': font_key})
            if embed_italic:
                font_key = embed_italic[0].get(f"{{{NS['r']}}}fontKey", '')
                embedded.append({'style': 'Italic', 'key': font_key})
            if embed_bold_italic:
                font_key = embed_bold_italic[0].get(f"{{{NS['r']}}}fontKey", '')
                embedded.append({'style': 'BoldItalic', 'key': font_key})
            
            if embedded:
                # Check if font is subsetted
                charset = font.get(f"{{{NS['w']}}}charset", '')
                
                self.embedded_fonts.append({
                    'name': font_name,
                    'embedded_styles': embedded,
                    'charset': charset,
                    'is_obfuscated': any(e['key'] for e in embedded)
                })

    def _analyze_font_usage(self):
        """Analyze font usage throughout document."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # Get all font references
        font_refs = tree.xpath('//w:rFonts', namespaces=NS)
        
        fonts_used = set()
        for ref in font_refs:
            ascii_font = ref.get(f"{{{NS['w']}}}ascii", '')
            h_ansi = ref.get(f"{{{NS['w']}}}hAnsi", '')
            east_asia = ref.get(f"{{{NS['w']}}}eastAsia", '')
            cs = ref.get(f"{{{NS['w']}}}cs", '')  # Complex script
            
            for font in [ascii_font, h_ansi, east_asia, cs]:
                if font:
                    fonts_used.add(font)
        
        self.font_references = sorted(fonts_used)

    def _report_findings(self):
        """Report font embedding and usage findings."""
        if not self.embedded_fonts and not self.font_references:
            log_success("No embedded fonts found, standard font references.")
            return
        
        if self.embedded_fonts:
            log_warning(f"Found {len(self.embedded_fonts)} embedded font(s):")
            for font in self.embedded_fonts:
                print(f"\n  • {font['name']}")
                print(f"    Embedded styles: {', '.join([e['style'] for e in font['embedded_styles']])}")
                
                if font['is_obfuscated']:
                    log_warning("    [OBFUSCATED] Font data is obfuscated")
                    print(f"    Font keys present (typical for licensed fonts)")
                
                if font['charset']:
                    print(f"    Charset: {font['charset']}")
        
        if self.font_references:
            log_info(f"\n[FONT REFERENCES]: {len(self.font_references)} unique font(s) used")
            
            # Show first 10 fonts
            for font in self.font_references[:10]:
                print(f"  • {font}")
            
            if len(self.font_references) > 10:
                print(f"  ... and {len(self.font_references) - 10} more fonts")
            
            # Check for unusual or suspicious fonts
            suspicious = []
            common_fonts = {'Calibri', 'Arial', 'Times New Roman', 'Cambria', 'Georgia', 'Verdana'}
            
            for font in self.font_references:
                if font not in common_fonts and not any(c in font for c in common_fonts):
                    suspicious.append(font)
            
            if suspicious:
                log_info(f"\n[UNUSUAL FONTS]: {len(suspicious)} non-standard font(s)")
                for font in suspicious[:5]:
                    print(f"  → {font}")
