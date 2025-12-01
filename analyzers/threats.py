from utils.helpers import NS, log_danger, log_warning, log_success, log_info

class ThreatScanner:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Threat & Anomaly Detection ---")
        try:
            self._check_template_injection()
            self._check_hidden_content()
        except Exception as e:
            print(f"[ERROR] Threat scan failed: {e}")

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
        
        if not threats_found:
            log_success("No malicious remote template injections found.")

    def _check_hidden_content(self):
        """Deep scan for White-on-White text."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        # 1. Vanish Property
        if tree.xpath('//w:vanish', namespaces=NS):
            log_warning("Found text runs with 'Vanish' property.")

        # 2. White Text (Robust Check using local-name to bypass namespace issues)
        # Find all color elements where val is FFFFFF or white
        color_nodes = tree.xpath("//*[local-name()='color'][@*[local-name()='val']='FFFFFF']")
        
        hidden_samples = []

        for color_node in color_nodes:
            rPr = color_node.getparent()
            if rPr is None: continue
            is_visible = False
            
            # Check Run Highlight/Shading
            if rPr.xpath(".//*[local-name()='highlight']"): is_visible = True
            shd = rPr.xpath(".//*[local-name()='shd']")
            if shd:
                fill = shd[0].get(f"{{{NS['w']}}}fill") or shd[0].get("fill")
                if fill and fill.lower() not in ['auto', 'ffffff']: is_visible = True

            # Check Paragraph/Style
            if not is_visible:
                run = rPr.getparent()
                para = run.getparent() if run is not None else None
                if para is not None:
                    pPr = para.xpath(".//*[local-name()='pPr']")
                    if pPr:
                        p_shd = pPr[0].xpath(".//*[local-name()='shd']")
                        if p_shd:
                            p_fill = p_shd[0].get(f"{{{NS['w']}}}fill") or p_shd[0].get("fill")
                            if p_fill and p_fill.lower() not in ['auto', 'ffffff']: is_visible = True
                        
                        # Style check (Simple heuristic)
                        if pPr[0].xpath(".//*[local-name()='pStyle']"): is_visible = True

            # Check Table/Drawings
            if not is_visible:
                for ancestor in rPr.iterancestors():
                    tag = ancestor.tag.split('}')[-1]
                    if tag in ['tc', 'drawing', 'txbxContent']:
                        is_visible = True
                        break

            # If still not visible, extract text
            if not is_visible:
                run = rPr.getparent()
                text_nodes = run.xpath(".//*[local-name()='t']")
                for t in text_nodes:
                    if t.text and t.text.strip():
                        hidden_samples.append(t.text.strip())

        if hidden_samples:
            log_danger(f"Found {len(hidden_samples)} text runs explicitly colored White on White.")
            print(f"[HIDDEN DATA EXTRACTED]:") # GUI looks for this tag
            for sample in set(hidden_samples): # Deduplicate
                print(f" >> {sample}")
        else:
            log_success("No hidden white-on-white text anomalies found.")