from utils.helpers import NS, log_info, log_warning, log_danger

class StyleAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        # GENERIC: The Allowlist. Anything NOT here is suspicious/custom.
        self.STANDARD_STYLES = {
            'normal', 'heading 1', 'heading 2', 'heading 3', 'heading 4', 'heading 5', 
            'heading 6', 'heading 7', 'heading 8', 'heading 9', 'title', 'subtitle',
            'default paragraph font', 'table normal', 'no list', 'header', 'footer', 
            'hyperlink', 'followedhyperlink', 'comment reference', 'comment text', 
            'comment subject', 'list paragraph', 'balloon text', 'annotation text', 
            'annotation reference', 'page number', 'toc 1', 'toc 2', 'toc 3', 'toc 4',
            'header char', 'footer char', 'heading 1 char', 'heading 2 char', 'heading 3 char',
            'strong', 'emphasis', 'quote', 'intense quote', 'book title'
        }

    def run(self):
        print("\n--- Style & Formatting Forensics ---")
        self._analyze_styles()

    def _analyze_styles(self):
        tree = self.loader.get_xml_tree('word/styles.xml')
        if not tree:
            log_warning("styles.xml not found.")
            return

        styles = tree.xpath('//w:style', namespaces=NS)
        
        custom_styles = []
        geo_markers = []
        custom_fonts = set()
        
        # Standard Microsoft Fonts (Allowlist)
        standard_fonts = ['Calibri', 'Arial', 'Times New Roman', 'Cambria', 'Calibri Light', 'Wingdings', 'Symbol']

        print(f"{'Style Name':<30} | {'Type':<10} | {'Lang':<6} | {'Font'}")
        print("-" * 80)

        for style in styles:
            # Extract Data
            style_id = style.get(f"{{{NS['w']}}}styleId")
            name_node = style.find('w:name', namespaces=NS)
            style_name = name_node.get(f"{{{NS['w']}}}val") if name_node is not None else style_id
            style_type = style.get(f"{{{NS['w']}}}type")
            
            # Extract Lang
            lang_node = style.xpath('.//w:lang', namespaces=NS)
            lang = lang_node[0].get(f"{{{NS['w']}}}val") if lang_node else ""

            # Extract Font
            font_node = style.xpath('.//w:rFonts', namespaces=NS)
            font_name = "N/A"
            if font_node:
                font_name = (font_node[0].get(f"{{{NS['w']}}}ascii") or 
                             font_node[0].get(f"{{{NS['w']}}}hAnsi") or 
                             "N/A")

            # -- GENERIC LOGIC --
            
            is_custom = False
            is_foreign = False
            has_weird_font = False

            # Check 1: Is the style name non-standard?
            if style_name.lower() not in self.STANDARD_STYLES:
                is_custom = True
                custom_styles.append(style_name)

            # Check 2: Is the language non-standard (Not US/UK/Empty)?
            if lang and lang.lower() not in ['en-us', 'en-gb', '']:
                is_foreign = True
                geo_markers.append(f"{lang} ({style_name})")

            # Check 3: Is the font non-standard?
            if font_name != "N/A" and font_name not in standard_fonts:
                has_weird_font = True
                custom_fonts.add(font_name)

            # Only print if it triggers one of our generic anomalies
            if is_custom or is_foreign or has_weird_font:
                print(f"{style_name:<30} | {style_type:<10} | {lang:<6} | {font_name}")

        # -- SUMMARY --
        if custom_styles:
            log_info(f"Detected {len(custom_styles)} User-Defined Styles (Template Artifacts).")
        
        if geo_markers:
            log_danger(f"Non-Standard Language/Locales Found: {', '.join(set(geo_markers))}")

        if custom_fonts:
            log_info(f"Third-Party Fonts Detected: {', '.join(custom_fonts)}")