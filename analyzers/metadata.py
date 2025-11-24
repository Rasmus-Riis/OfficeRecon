from utils.helpers import log_info, log_warning, NS

class MetadataAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Deep Metadata Analysis ---")
        self._parse_core_props()
        self._parse_app_props()
        self._parse_custom_props()
        self._parse_doc_settings()

    def _parse_core_props(self):
        """Standard dublin core properties."""
        tree = self.loader.get_xml_tree('docProps/core.xml')
        if not tree: return

        ns = {
            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'dcterms': 'http://purl.org/dc/terms/'
        }
        
        print(f"{'[Core Properties]':<25}")
        fields = {
            'Creator': '//dc:creator',
            'Last Modified By': '//cp:lastModifiedBy',
            'Created': '//dcterms:created',
            'Modified': '//dcterms:modified',
            'Last Printed': '//cp:lastPrinted',
            'Revision': '//cp:revision',
            'Title': '//dc:title',
            'Subject': '//dc:subject',
            'Category': '//cp:category',
            'Keywords': '//cp:keywords',
            'Description': '//dc:description',
            'Status': '//cp:contentStatus'
        }

        for label, xpath in fields.items():
            val = self._get_text(tree, xpath, ns)
            if val != "N/A":
                print(f"  {label:<20}: {val}")

    def _parse_app_props(self):
        """Extended stats from app.xml."""
        tree = self.loader.get_xml_tree('docProps/app.xml')
        if not tree: return

        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
        
        print(f"\n{'[Extended Stats]':<25}")
        fields = {
            'Template': '//ep:Template',
            'Application': '//ep:Application',
            'App Version': '//ep:AppVersion',
            'Company': '//ep:Company',
            'Manager': '//ep:Manager',
            'Total Edit Time (min)': '//ep:TotalTime',
            'Pages': '//ep:Pages',
            'Words': '//ep:Words',
            'Characters': '//ep:Characters',
            'Paragraphs': '//ep:Paragraphs',
            'Lines': '//ep:Lines'
        }

        for label, xpath in fields.items():
            val = self._get_text(tree, xpath, ns)
            if val != "N/A":
                print(f"  {label:<20}: {val}")

    def _parse_custom_props(self):
        """User-defined or System-defined custom properties."""
        tree = self.loader.get_xml_tree('docProps/custom.xml')
        if not tree: return

        ns = {'cp': 'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties'}
        properties = tree.xpath('//cp:property', namespaces=ns)
        
        if properties:
            print(f"\n{'[Custom Properties]':<25}")
            for prop in properties:
                name = prop.get('name')
                # Value can be in various type tags (lpwstr, i4, bool, filetime)
                val_node = prop[0] if len(prop) > 0 else None
                val = val_node.text if val_node is not None else "Empty"
                print(f"  {name:<20}: {val}")

    def _parse_doc_settings(self):
        """Internal document settings (Track changes, Protection)."""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree: return

        print(f"\n{'[Internal Settings]':<25}")
        
        # Check for Track Revisions
        track_rev = tree.xpath('//w:trackRevisions', namespaces=NS)
        if track_rev:
            print(f"  {'Track Changes':<20}: ACTIVE (History may be present)")
        
        # Check for Protection
        protection = tree.xpath('//w:documentProtection', namespaces=NS)
        if protection:
            edit_type = protection[0].get(f"{{{NS['w']}}}edit")
            print(f"  {'Protection':<20}: YES (Type: {edit_type})")

    def _get_text(self, tree, xpath, ns):
        elements = tree.xpath(xpath, namespaces=ns)
        return elements[0].text if elements and elements[0].text else "N/A"