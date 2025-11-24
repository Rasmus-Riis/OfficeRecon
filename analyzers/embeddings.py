import re
from utils.helpers import NS, log_info, log_warning, log_danger, log_success

class EmbeddingAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Embeddings & Linked Data Forensics ---")
        self._scan_ole_paths()
        self._scan_people_xml()

    def _scan_ole_paths(self):
        """
        Scans binary OLE objects (e.g., embedded Excel sheets) for local file paths.
        This often leaks the original Author's Username and Folder Structure.
        """
        # 1. Find embedding files
        embedding_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('word/embeddings/')]
        
        if not embedding_files:
            return

        log_info(f"Found {len(embedding_files)} embedded object(s) (OLE). Scanning for leaked paths...")
        
        # Regex for Windows Paths (e.g., C:\Users\Name\...)
        # Looks for Drive Letter + Colon + Backslash + Characters
        path_pattern = re.compile(rb'[a-zA-Z]:\\[a-zA-Z0-9_ \-\.\\]+\.[a-zA-Z0-9]{2,5}')
        
        leaked_paths = set()

        for ef in embedding_files:
            try:
                binary_data = self.loader.zip_ref.read(ef)
                matches = path_pattern.findall(binary_data)
                
                for m in matches:
                    # Decode and clean up
                    try:
                        path_str = m.decode('utf-8', errors='ignore')
                        # Filter out common system noise if necessary
                        if "Program Files" not in path_str and "System32" not in path_str:
                            leaked_paths.add(path_str)
                    except:
                        continue
            except Exception as e:
                continue

        if leaked_paths:
            log_danger(f"Leaked Local File Paths detected in OLE Objects:")
            for p in leaked_paths:
                print(f"   -> {p}")
            print("   -> This reveals the folder structure and username of the creator.")
        else:
            log_success("No leaked local paths found in embeddings.")

    def _scan_people_xml(self):
        """
        Scans word/people.xml. This file caches contact info of anyone who 
        has commented or tracked changes in modern Word versions.
        """
        # Check if file exists
        if 'word/people.xml' not in self.loader.zip_ref.namelist():
            return

        tree = self.loader.get_xml_tree('word/people.xml')
        if not tree: return

        # Namespace for people (usually w15)
        # We use local namespace map from the file to be safe, or fallback to wildcard
        
        # Iterate through persons
        # The tag is usually <w15:person>
        persons = []
        
        # Use generic xpath to find 'person' tags regardless of namespace prefix
        person_nodes = tree.xpath('//*[local-name()="person"]')
        
        for p in person_nodes:
            # Extract attributes directly
            author = p.get(f"{{{NS['w15']}}}author") or "Unknown"
            user_id = p.get(f"{{{NS['w15']}}}userId") or "N/A"
            
            # Sometimes providerId gives a clue (e.g., "Active Directory")
            provider = p.get(f"{{{NS['w15']}}}providerId") or ""
            
            persons.append(f"{author} (ID: {user_id}) {provider}")

        if persons:
            log_warning(f"Found {len(persons)} cached User Profiles (people.xml):")
            for per in persons:
                print(f"   -> {per}")
            print("   -> These users interacted with the document (Comments/Edits) in the past.")