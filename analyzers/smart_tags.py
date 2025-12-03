from utils.helpers import NS, log_info, log_warning, log_success

class SmartTagAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.smart_tags = []
        self.content_controls = []

    def run(self):
        print("\n--- Smart Tag & Content Control Forensics ---")
        self._extract_smart_tags()
        self._extract_content_controls()
        self._report_findings()

    def _extract_smart_tags(self):
        """Extract smart tags which often contain corporate identifiers."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # Smart tags use w:smartTag element
        smart_tags = tree.xpath('//w:smartTag', namespaces=NS)
        
        for tag in smart_tags:
            uri = tag.get(f"{{{NS['w']}}}uri", '')
            element = tag.get(f"{{{NS['w']}}}element", '')
            
            # Extract text content
            text_nodes = tag.xpath('.//w:t', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            if uri or element:
                self.smart_tags.append({
                    'uri': uri,
                    'element': element,
                    'text': text.strip()
                })

    def _extract_content_controls(self):
        """Extract content controls and their bindings."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        # Content controls: w:sdt (Structured Document Tag)
        controls = tree.xpath('//w:sdt', namespaces=NS)
        
        for control in controls:
            # Get control properties
            sdt_pr = control.xpath('.//w:sdtPr', namespaces=NS)
            if not sdt_pr:
                continue
            
            sdt_pr = sdt_pr[0]
            
            # Extract tag (identifier)
            tag_node = sdt_pr.xpath('.//w:tag', namespaces=NS)
            tag = tag_node[0].get(f"{{{NS['w']}}}val", '') if tag_node else ''
            
            # Extract alias (display name)
            alias_node = sdt_pr.xpath('.//w:alias', namespaces=NS)
            alias = alias_node[0].get(f"{{{NS['w']}}}val", '') if alias_node else ''
            
            # Check for data binding
            data_binding = sdt_pr.xpath('.//w:dataBinding', namespaces=NS)
            bound_to = ''
            if data_binding:
                bound_to = data_binding[0].get(f"{{{NS['w']}}}xpath", '')
                if not bound_to:
                    bound_to = data_binding[0].get(f"{{{NS['w']}}}storeItemID", 'Custom XML')
            
            # Get content type
            control_type = 'Unknown'
            if sdt_pr.xpath('.//w:text', namespaces=NS):
                control_type = 'Text'
            elif sdt_pr.xpath('.//w:date', namespaces=NS):
                control_type = 'Date'
            elif sdt_pr.xpath('.//w:dropDownList', namespaces=NS):
                control_type = 'Dropdown'
            elif sdt_pr.xpath('.//w:comboBox', namespaces=NS):
                control_type = 'ComboBox'
            elif sdt_pr.xpath('.//w:picture', namespaces=NS):
                control_type = 'Picture'
            
            self.content_controls.append({
                'type': control_type,
                'tag': tag,
                'alias': alias,
                'binding': bound_to
            })

    def _report_findings(self):
        """Report all smart tags and content controls found."""
        if not self.smart_tags and not self.content_controls:
            log_success("No smart tags or content controls found.")
            return
        
        if self.smart_tags:
            log_warning(f"Found {len(self.smart_tags)} smart tags:")
            for tag in self.smart_tags[:10]:
                if tag['uri']:
                    print(f"  • URI: {tag['uri']}")
                if tag['element']:
                    print(f"    Element: {tag['element']}")
                if tag['text']:
                    preview = tag['text'][:50] + "..." if len(tag['text']) > 50 else tag['text']
                    print(f"    Text: \"{preview}\"")
            if len(self.smart_tags) > 10:
                print(f"  ... and {len(self.smart_tags) - 10} more smart tags")
        
        if self.content_controls:
            log_info(f"\nFound {len(self.content_controls)} content controls:")
            
            # Group by type
            by_type = {}
            for control in self.content_controls:
                ctype = control['type']
                if ctype not in by_type:
                    by_type[ctype] = []
                by_type[ctype].append(control)
            
            for ctype, controls in by_type.items():
                print(f"\n  [{ctype}]: {len(controls)} control(s)")
                for control in controls[:3]:
                    if control['alias']:
                        print(f"    • {control['alias']}")
                    elif control['tag']:
                        print(f"    • Tag: {control['tag']}")
                    if control['binding']:
                        print(f"      → Bound to: {control['binding']}")
