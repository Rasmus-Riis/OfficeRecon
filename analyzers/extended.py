import re
from utils.helpers import NS, log_info, log_warning, log_success

class ExtendedAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Extended Artifact Analysis ---")
        self._check_thumbnail()
        self._scan_custom_xml_for_corporate_data()

    def _check_thumbnail(self):
        """
        Checks for the existence of a 'Last Save' thumbnail.
        """
        # Standard location for the thumbnail
        thumb_path = 'docProps/thumbnail.jpeg'
        if thumb_path not in self.loader.zip_ref.namelist():
            # Sometimes it's an EMF or WMF file
            thumb_path = next((f for f in self.loader.zip_ref.namelist() if f.startswith('docProps/thumbnail')), None)

        if thumb_path:
            size_kb = self.loader.zip_ref.getinfo(thumb_path).file_size / 1024
            log_info(f"Visual Thumbnail Found: {thumb_path} ({size_kb:.1f} KB)")
            print("   -> This is a snapshot of the document at the moment of the last save.")
            print("   -> [FORENSIC CHECK]: Does this image match the current text content?")
        else:
            print("   -> No visual thumbnail found (Save Thumbnail option was off).")

    def _scan_custom_xml_for_corporate_data(self):
        """
        Scans customXml files for SharePoint/OneDrive metadata (GUIDs, URLs).
        """
        # Find all custom xml items
        custom_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('customXml/item')]
        
        found_corp_data = False
        
        for f in custom_files:
            try:
                tree = self.loader.get_xml_tree(f)
                if not tree: continue
                
                # Convert tree to string to regex search it (namespaces can be messy in customXml)
                raw_xml = str(tree.getroot()) # In lxml, we might need toserialize if we want full text search
                # Better: Iterate elements
                
                for elem in tree.iter():
                    tag = elem.tag.split('}')[-1] # Strip namespace
                    text = elem.text or ""
                    
                    # 1. SharePoint / Server URLs
                    if "http" in text and ("sharepoint" in text or "my.site" in text):
                        log_warning(f"Corporate Server URL Found: {text}")
                        found_corp_data = True
                        
                    # 2. Document Management GUIDs
                    if tag in ['DocId', 'DocumentId', 'dlpPolicy']:
                        log_warning(f"Enterprise ID ({tag}): {text}")
                        found_corp_data = True
                        
                    # 3. Author/Editor from Server (often different from core.xml)
                    if tag in ['editor', 'author'] and text.strip():
                        print(f"   -> Server User ({tag}): {text}")
                        found_corp_data = True

            except Exception:
                continue

        if found_corp_data:
            print("   -> [ALERT]: This file contains internal Corporate Server metadata.")
        else:
            print("   -> No specific Corporate/SharePoint metadata found in customXml.")