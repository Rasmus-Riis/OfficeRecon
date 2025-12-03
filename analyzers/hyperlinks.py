from utils.helpers import NS, log_info, log_warning, log_success

class HyperlinkAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.hyperlinks = []
        self.external_refs = []

    def run(self):
        print("\n--- Hyperlink & External Reference Forensics ---")
        self._extract_hyperlinks()
        self._extract_external_refs()
        self._analyze_links()

    def _extract_hyperlinks(self):
        """Extract all hyperlinks from the document."""
        # Check document relationships
        tree = self.loader.get_xml_tree('word/_rels/document.xml.rels')
        if tree:
            rels = tree.xpath('//rel:Relationship[@Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"]', 
                            namespaces=NS)
            for rel in rels:
                target = rel.get('Target', '')
                target_mode = rel.get('TargetMode', 'Internal')
                if target:
                    self.hyperlinks.append({
                        'url': target,
                        'external': target_mode == 'External',
                        'location': 'document'
                    })
        
        # Check headers and footers
        for part in ['header', 'footer']:
            rel_files = [f for f in self.loader.zip_ref.namelist() 
                        if f.startswith(f'word/_rels/{part}') and f.endswith('.rels')]
            for rel_file in rel_files:
                tree = self.loader.get_xml_tree(rel_file)
                if tree:
                    rels = tree.xpath('//rel:Relationship[@Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"]', 
                                    namespaces=NS)
                    for rel in rels:
                        target = rel.get('Target', '')
                        if target:
                            self.hyperlinks.append({
                                'url': target,
                                'external': True,
                                'location': part
                            })

    def _extract_external_refs(self):
        """Extract external references (images, OLE objects, etc.)."""
        tree = self.loader.get_xml_tree('word/_rels/document.xml.rels')
        if not tree:
            return

        # External images (potential tracking pixels)
        image_rels = tree.xpath('//rel:Relationship[@Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"][@TargetMode="External"]', 
                               namespaces=NS)
        for rel in image_rels:
            target = rel.get('Target', '')
            if target:
                self.external_refs.append({
                    'type': 'External Image',
                    'target': target,
                    'risk': 'High - Tracking pixel'
                })
        
        # OLE object links
        ole_rels = tree.xpath('//rel:Relationship[@Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"][@TargetMode="External"]', 
                             namespaces=NS)
        for rel in ole_rels:
            target = rel.get('Target', '')
            if target:
                self.external_refs.append({
                    'type': 'OLE Link',
                    'target': target,
                    'risk': 'Critical - External file link'
                })

    def _analyze_links(self):
        """Analyze all links for security and forensic significance."""
        total_links = len(self.hyperlinks) + len(self.external_refs)
        
        if total_links == 0:
            log_success("No external links or references found.")
            return

        log_warning(f"Found {total_links} external connections")
        
        if self.hyperlinks:
            external_hyperlinks = [h for h in self.hyperlinks if h['external']]
            if external_hyperlinks:
                print(f"\n[HYPERLINKS]: {len(external_hyperlinks)} external URLs")
                
                # Categorize by domain
                domains = {}
                for link in external_hyperlinks:
                    url = link['url']
                    if '://' in url:
                        domain = url.split('://')[1].split('/')[0]
                    else:
                        domain = url.split('/')[0]
                    
                    if domain not in domains:
                        domains[domain] = []
                    domains[domain].append(link)
                
                for domain, links in list(domains.items())[:10]:
                    print(f"  → {domain}: {len(links)} link(s)")
                    if len(links) <= 3:
                        for link in links:
                            print(f"     {link['url']}")
        
        if self.external_refs:
            log_warning(f"\n[EXTERNAL REFERENCES]: {len(self.external_refs)} remote resources")
            for ref in self.external_refs:
                print(f"  [{ref['risk']}] {ref['type']}: {ref['target']}")
