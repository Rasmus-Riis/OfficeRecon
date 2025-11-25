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
        Scans binary OLE objects for leaked local paths and usernames.
        """
        embedding_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('word/embeddings/')]
        
        if not embedding_files:
            return

        log_info(f"Found {len(embedding_files)} embedded object(s). Scanning for leaked paths...")
        
        # Regex for Windows Paths
        path_pattern = re.compile(rb'[a-zA-Z]:\\[a-zA-Z0-9_ \-\.\\]+\.[a-zA-Z0-9]{2,5}')
        # Regex specifically for Users folder (captures the username)
        user_pattern = re.compile(rb'Users\\([^\\]+)\\')
        
        leaked_paths = set()
        leaked_users = set()

        for ef in embedding_files:
            try:
                binary_data = self.loader.zip_ref.read(ef)
                
                # Find Paths
                matches = path_pattern.findall(binary_data)
                for m in matches:
                    try:
                        path_str = m.decode('utf-8', errors='ignore')
                        if "Program Files" not in path_str and "System32" not in path_str:
                            leaked_paths.add(path_str)
                    except: continue

                # Find Users specifically
                user_matches = user_pattern.findall(binary_data)
                for u in user_matches:
                    try:
                        user_str = u.decode('utf-8', errors='ignore')
                        if user_str.lower() not in ['public', 'default', 'admin']:
                            leaked_users.add(user_str)
                    except: continue

            except: continue

        if leaked_users:
            log_danger(f"Leaked System Usernames detected in binary blobs:")
            for u in leaked_users:
                # This tag [USER LEAK] is scraped by the GUI
                print(f"   -> [USER LEAK]: {u}")

        if leaked_paths:
            log_warning(f"Leaked Local File Paths:")
            for p in leaked_paths:
                print(f"   -> {p}")
        else:
            if not leaked_users:
                log_success("No leaked local paths found in embeddings.")

    def _scan_people_xml(self):
        if 'word/people.xml' not in self.loader.zip_ref.namelist(): return
        tree = self.loader.get_xml_tree('word/people.xml')
        if not tree: return
        
        persons = []
        person_nodes = tree.xpath('//*[local-name()="person"]')
        
        for p in person_nodes:
            author = p.get(f"{{{NS['w15']}}}author") or "Unknown"
            user_id = p.get(f"{{{NS['w15']}}}userId") or "N/A"
            persons.append(f"{author} (ID: {user_id})")

        if persons:
            log_warning(f"Found {len(persons)} cached User Profiles (people.xml):")
            for per in persons:
                print(f"   -> {per}")