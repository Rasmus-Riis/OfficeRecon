from utils.helpers import NS, log_info, log_warning, log_success

class FieldAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Persistent ID & Field Code Analysis ---")
        self._check_doc_id()
        self._scan_field_codes()

    def _check_doc_id(self):
        """
        Extracts the w15:docId. This ID persists across file copies.
        Matching IDs in different files = Proof of Copying.
        """
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree: return

        # Search for the w15:docId
        # Note: We use the specific w15 namespace defined in helpers.py
        doc_id_node = tree.find('.//w15:docId', namespaces=NS)
        
        if doc_id_node is not None:
            doc_id = doc_id_node.get(f"{{{NS['w15']}}}val")
            log_info(f"Persistent Document ID found: {doc_id}")
            print("   -> This ID stays constant when a file is copied/renamed in Windows.")
            print("   -> Use this to link disparate files back to a common source.")
        else:
            print("   -> No Persistent Document ID found (Older Word version or stripped).")

    def _scan_field_codes(self):
        """
        Scans document.xml for Field Codes (w:instrText).
        These reveal dynamic data like old file paths, authors, or hyperlinks.
        """
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        # Find all instruction text nodes
        instr_nodes = tree.xpath('//w:instrText', namespaces=NS)
        
        found_fields = []
        for node in instr_nodes:
            text = node.text.strip() if node.text else ""
            if text:
                found_fields.append(text)

        if found_fields:
            log_warning(f"Found {len(found_fields)} Dynamic Field Codes:")
            
            # Filter and print interesting ones
            for field in found_fields:
                # Clean up formatting noise
                clean_field = field.replace(" MERGEFORMAT", "").strip()
                
                if "HYPERLINK" in clean_field:
                    print(f"   -> LINK: {clean_field}")
                elif "FILENAME" in clean_field:
                    print(f"   -> PATH VAR: {clean_field} (May store old path in cached view)")
                elif "AUTHOR" in clean_field or "TITLE" in clean_field:
                    print(f"   -> METADATA VAR: {clean_field}")
                else:
                    # Print generic fields if not empty
                    if len(clean_field) > 3: 
                        print(f"   -> FIELD: {clean_field}")
        else:
            log_success("No hidden Field Codes found in main text.")