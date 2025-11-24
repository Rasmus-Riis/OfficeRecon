from utils.helpers import NS, log_danger, log_warning, log_success, log_info

class ThreatScanner:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Threat & Anomaly Detection ---")
        self._check_template_injection()
        self._check_hidden_content()

    def _check_template_injection(self):
        """Checks for remote template injection vulnerabilities and standard hyperlinks."""
        tree = self.loader.get_xml_tree('word/_rels/document.xml.rels')
        if not tree:
            return

        # Look for External targets
        rels = tree.xpath(f"//rel:Relationship[@TargetMode='External']", namespaces=NS)
        
        threats_found = False
        
        for rel in rels:
            target = rel.get('Target')
            r_type = rel.get('Type')
            
            # 1. Template Injection (Actual Threat) -> RED
            if "attachedTemplate" in r_type:
                log_danger(f"Remote Template Injection Detected: {target}")
                threats_found = True
                
            # 2. Standard Hyperlinks (Informational) -> BLUE (User requested change)
            elif "http" in target:
                log_info(f"External Hyperlink: {target}")
            
            # 3. Other external references -> YELLOW
            else:
                log_warning(f"External Reference ({r_type.split('/')[-1]}): {target}")
        
        if not threats_found:
            log_success("No malicious remote template injections found.")

    def _check_hidden_content(self):
        """Scans for w:vanish and specific formatting used to hide text."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # 1. Explicit 'Vanish' property
        vanish_nodes = tree.xpath('//w:vanish', namespaces=NS)
        if vanish_nodes:
            log_warning(f"Found {len(vanish_nodes)} text runs marked as 'Hidden' (w:vanish).")
        
        # 2. White text check (Smart Check)
        # We look for explicit FFFFFF color.
        color_nodes = tree.xpath("//w:color[@w:val='FFFFFF']", namespaces=NS)
        hidden_white_count = 0
        hidden_samples = []

        for color_node in color_nodes:
            # The color node is inside w:rPr (Run Properties).
            rPr = color_node.getparent()
            if rPr is None: continue

            is_visible = False

            # --- Check 1: Run-level Highlight or Shading ---
            highlight = rPr.find(f"{{{NS['w']}}}highlight")
            shading = rPr.find(f"{{{NS['w']}}}shd")
            shading_fill = shading.get(f"{{{NS['w']}}}fill") if shading is not None else "auto"

            if highlight is not None:
                is_visible = True
            elif shading_fill and shading_fill.lower() not in ['auto', 'ffffff']:
                is_visible = True

            # --- Check 2: Climb up to Paragraph Level ---
            if not is_visible:
                run_node = rPr.getparent()
                if run_node is not None:
                    
                    # --- Check 3: Is it inside a Drawing / Text Box? ---
                    # White text in shapes is standard design.
                    # We check if any ancestor is a 'drawing' or 'txbxContent'
                    for ancestor in run_node.iterancestors():
                        tag_name = ancestor.tag.split('}')[-1] # Remove namespace
                        if tag_name in ['drawing', 'txbxContent', 'fallback']:
                            is_visible = True
                            break
                    
                    if is_visible: continue # Skip if found in drawing

                    para_node = run_node.getparent()
                    
                    if para_node is not None:
                        # A. Check Paragraph Shading (pPr -> shd)
                        pPr = para_node.find(f"{{{NS['w']}}}pPr")
                        if pPr is not None:
                            p_shd = pPr.find(f"{{{NS['w']}}}shd")
                            p_fill = p_shd.get(f"{{{NS['w']}}}fill") if p_shd is not None else "auto"
                            if p_fill and p_fill.lower() not in ['auto', 'ffffff']:
                                is_visible = True
                            
                            # B. Check for Named Styles 
                            # If a style is applied (e.g., "Heading 1"), we assume it handles the background.
                            p_style = pPr.find(f"{{{NS['w']}}}pStyle")
                            if p_style is not None:
                                style_val = p_style.get(f"{{{NS['w']}}}val")
                                if style_val and style_val.lower() != "normal":
                                    is_visible = True

                        # C. Check Table Cell Shading (if inside a table)
                        cell_node = para_node.getparent()
                        if cell_node is not None and cell_node.tag.endswith('tc'):
                            tcPr = cell_node.find(f"{{{NS['w']}}}tcPr")
                            if tcPr is not None:
                                tc_shd = tcPr.find(f"{{{NS['w']}}}shd")
                                tc_fill = tc_shd.get(f"{{{NS['w']}}}fill") if tc_shd is not None else "auto"
                                if tc_fill and tc_fill.lower() not in ['auto', 'ffffff']:
                                    is_visible = True

            if not is_visible:
                hidden_white_count += 1
                # Extract text for the user
                run_node = rPr.getparent()
                if run_node is not None:
                    text_node = run_node.find(f"{{{NS['w']}}}t")
                    if text_node is not None and text_node.text:
                        hidden_samples.append(text_node.text.strip())

        if hidden_white_count > 0:
            log_warning(f"Found {hidden_white_count} text runs explicitly colored White on White background (Potential hiding).")
            print("   [Content Preview - Check Deep Artifacts Tab]:")
            for i, sample in enumerate(hidden_samples[:5]):
                print(f"   {i+1}. \"{sample}\"")
            if len(hidden_samples) > 5:
                print(f"   ... ({len(hidden_samples) - 5} more)")
            
        # 3. Tiny text (Size 1 = 0.5pt)
        tiny_text = tree.xpath("//w:sz[@w:val='1']", namespaces=NS)
        if tiny_text:
            log_warning(f"Found {len(tiny_text)} text runs with 0.5pt font size.")

        if not vanish_nodes and hidden_white_count == 0 and not tiny_text:
            log_success("No standard hidden text anomalies found.")