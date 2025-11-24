from lxml import etree
from utils.helpers import NS, log_info, log_warning, log_danger, log_success

class DeepScanAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Deep Artifact Extraction ---")
        self._scan_deleted_text()
        self._scan_glossary()
        self._scan_printer_settings()
        self._scan_custom_xml_namespaces()

    def _scan_deleted_text(self):
        """Generic: Flags ANY text marked as deleted (Track Changes)."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        deleted_nodes = tree.xpath('//w:delText', namespaces=NS)
        
        if deleted_nodes:
            log_warning(f"Found {len(deleted_nodes)} fragments of deleted text (Track Changes).")
            print("   [Preview of Deleted Content]:")
            for i, node in enumerate(deleted_nodes[:5]): 
                text = node.text or "[Empty]"
                print(f"   {i+1}. \"{text}\"")
            if len(deleted_nodes) > 5:
                print(f"   ... and {len(deleted_nodes)-5} more.")
        else:
            log_success("No active Track Changes deletions found.")

    def _scan_glossary(self):
        """Generic: Checks if the 'Glossary' part exists (where Quick Parts hide)."""
        tree = self.loader.get_xml_tree('word/glossary/document.xml')
        if not tree:
            return 

        log_info("Glossary Document (Quick Parts) storage detected.")
        paragraphs = tree.xpath('//w:t', namespaces=NS)
        if paragraphs:
            print(f"   -> Contains {len(paragraphs)} text fragments hidden in glossary.")

    def _scan_printer_settings(self):
        """Generic: Checks if specific printer binary blobs are linked."""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree: return

        printers = tree.xpath('//w:printerSettings', namespaces=NS)
        if printers:
            for p in printers:
                r_id = p.get(f"{{{NS['r']}}}id")
                log_warning(f"Document contains a binary link to a specific physical printer (Ref: {r_id}).")

    def _scan_custom_xml_namespaces(self):
        """Generic: Extracts specific Schema URLs from customXml to identify software."""
        # Find all customXml items in the ZIP
        custom_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('customXml/item')]
        
        if not custom_files:
            return

        found_schemas = set()

        for cf in custom_files:
            try:
                xml_content = self.loader.zip_ref.read(cf)
                root = etree.fromstring(xml_content)
                
                # Check all namespaces defined in this file
                for prefix, url in root.nsmap.items():
                    # Filter out the standard Office crap so we only see the interesting 3rd party stuff
                    if url and "schemas.openxmlformats.org" not in url and "schemas.microsoft.com" not in url:
                        found_schemas.add(url)
            except:
                continue

        if found_schemas:
            log_info(f"Found {len(found_schemas)} Third-Party Software Schemas (Custom XML):")
            for schema in found_schemas:
                print(f"   -> Schema: {schema}")
                # This will print things like 'http://schemas.adobe.com/...' or 'http://schemas.investigative.tool/...'