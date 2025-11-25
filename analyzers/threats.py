from utils.helpers import NS, log_danger, log_warning, log_success, log_info

class ThreatScanner:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Threat & Anomaly Detection ---")
        self._check_template_injection()
        self._check_hidden_content()

    def _check_template_injection(self):
        tree = self.loader.get_xml_tree('word/_rels/document.xml.rels')
        if not tree: return

        rels = tree.xpath(f"//rel:Relationship[@TargetMode='External']", namespaces=NS)
        threats_found = False
        
        for rel in rels:
            target = rel.get('Target')
            r_type = rel.get('Type')
            
            if "attachedTemplate" in r_type:
                log_danger(f"Remote Template Injection Detected: {target}")
                threats_found = True
            elif "http" in target:
                log_info(f"External Hyperlink: {target}")
            else:
                log_warning(f"External Reference: {target}")
        
        if not threats_found:
            log_success("No malicious remote template injections found.")

    def _check_hidden_content(self):
        """Scans for white text and extracts content, ignoring visible text."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        # 1. Vanish Property
        vanish_nodes = tree.xpath('//w:vanish', namespaces=NS)
        if vanish_nodes:
            log_warning(f"Found {len(vanish_nodes)} runs with 'Vanish' property.")

        # 2. White Text (Deep Visibility Check)
        color_nodes = tree.xpath("//w:color[@w:val='FFFFFF']", namespaces=NS)
        hidden_samples = []

        for color_node in color_nodes:
            rPr = color_node.getparent()
            if rPr is None: continue

            is_visible = False
            
            # --- LAYER 1: Run Properties (Direct Formatting) ---
            # Check for Highlight
            if rPr.find(f"{{{NS['w']}}}highlight") is not None: is_visible = True
            
            # Check for Shading (Text Background)
            shd = rPr.find(f"{{{NS['w']}}}shd")
            if shd is not None:
                fill = shd.get(f"{{{NS['w']}}}fill", "auto")
                if fill.lower() not in ['auto', 'ffffff']: is_visible = True

            # --- LAYER 2: Paragraph Properties ---
            if not is_visible:
                run = rPr.getparent()
                para = run.getparent() if run is not None else None
                
                if para is not None:
                    pPr = para.find(f"{{{NS['w']}}}pPr")
                    if pPr is not None:
                        # Check Paragraph Shading
                        p_shd = pPr.find(f"{{{NS['w']}}}shd")
                        if p_shd is not None:
                            p_fill = p_shd.get(f"{{{NS['w']}}}fill", "auto")
                            if p_fill.lower() not in ['auto', 'ffffff']: is_visible = True
                        
                        # Check Paragraph Style (e.g., "Heading 1")
                        # If a custom style is applied, we assume it handles contrast correctly
                        p_style = pPr.find(f"{{{NS['w']}}}pStyle")
                        if p_style is not None:
                            style_val = p_style.get(f"{{{NS['w']}}}val")
                            if style_val and style_val.lower() != "normal":
                                is_visible = True

            # --- LAYER 3: Table Cell Properties ---
            if not is_visible:
                # Walk up ancestors to find if we are inside a Table Cell <w:tc>
                for ancestor in rPr.iterancestors():
                    if ancestor.tag.endswith('tc'):
                        tcPr = ancestor.find(f"{{{NS['w']}}}tcPr")
                        if tcPr is not None:
                            tc_shd = tcPr.find(f"{{{NS['w']}}}shd")
                            if tc_shd is not None:
                                tc_fill = tc_shd.get(f"{{{NS['w']}}}fill", "auto")
                                if tc_fill.lower() not in ['auto', 'ffffff']:
                                    is_visible = True
                        break # Stop once we find the cell

            # --- LAYER 4: Drawings / Text Boxes ---
            if not is_visible:
                for ancestor in rPr.iterancestors():
                    # Text inside shapes/textboxes usually has a fill color
                    if ancestor.tag.endswith('drawing') or ancestor.tag.endswith('txbxContent'):
                        is_visible = True
                        break

            # --- FINAL VERDICT ---
            if not is_visible:
                run = rPr.getparent()
                text_node = run.find(f"{{{NS['w']}}}t")
                if text_node is not None and text_node.text:
                    text = text_node.text.strip()
                    if text: hidden_samples.append(text)

        if hidden_samples:
            log_danger(f"Found {len(hidden_samples)} text runs explicitly colored White on White.")
            print(f"\n[HIDDEN DATA EXTRACTED]:")
            for sample in hidden_samples:
                print(f" >> {sample}")
        else:
            log_success("No hidden white-on-white text anomalies found.")