import os
import zipfile
from lxml import etree
from utils.helpers import NS, log_info, log_success, log_warning

class GenealogyMapper:
    def __init__(self, folder_path):
        self.folder = folder_path
        self.file_map = {} # {filename: set(rsids)}

    def run(self):
        print(f"\n--- RSID Genealogy Mapping (Recursive: {self.folder}) ---")
        self._scan_folder_recursive()
        self._analyze_and_report()

    def _scan_folder_recursive(self):
        """Scans folder AND subfolders for .docx files."""
        docx_count = 0
        
        # os.walk allows us to traverse the directory tree
        for root, dirs, files in os.walk(self.folder):
            for f in files:
                if f.lower().endswith('.docx') and not f.startswith('~$'):
                    # We need the full path to open the file
                    full_path = os.path.join(root, f)
                    
                    # Store it using the relative path or filename for readability
                    # Using just filename might cause collisions if two folders have "report.docx"
                    rel_path = os.path.relpath(full_path, self.folder)
                    
                    rsids = self._extract_rsids(full_path)
                    self.file_map[rel_path] = set(rsids)
                    docx_count += 1

        log_info(f"Recursively scanned {docx_count} documents for DNA markers (RSIDs)...")

    def _extract_rsids(self, filepath):
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                if 'word/settings.xml' not in z.namelist():
                    return []
                xml = z.read('word/settings.xml')
                root = etree.fromstring(xml)
                return [elem.get(f"{{{NS['w']}}}val") for elem in root.xpath('//w:rsid', namespaces=NS)]
        except:
            return []

    def _analyze_and_report(self):
        files = list(self.file_map.keys())
        matched_files = set()
        
        exact_matches = []   # > 90%
        partial_matches = [] # 1% - 90%

        # Compare All Pairs
        for i in range(len(files)):
            for j in range(i + 1, len(files)):
                f1 = files[i]
                f2 = files[j]
                
                rsid1 = self.file_map[f1]
                rsid2 = self.file_map[f2]
                
                shared = rsid1.intersection(rsid2)
                shared_count = len(shared)
                
                if shared_count > 0:
                    matched_files.add(f1)
                    matched_files.add(f2)
                    
                    min_len = min(len(rsid1), len(rsid2))
                    if min_len == 0: continue
                    
                    score = (shared_count / min_len) * 100
                    match_data = (f1, f2, shared_count, score)
                    
                    if score >= 90:
                        exact_matches.append(match_data)
                    else:
                        partial_matches.append(match_data)

        # REPORTING
        print(f"\n[GROUP 1: HIGH CONFIDENCE LINKS (>90% Match)]")
        print("   -> Likely direct copies, templates, or minor revisions.")
        print("-" * 75)
        if exact_matches:
            exact_matches.sort(key=lambda x: x[3], reverse=True)
            for m in exact_matches:
                print(f"   🔗 {m[3]:.0f}% | {m[0]} <--> {m[1]} ({m[2]} shared sessions)")
        else:
            print("   (None)")

        print(f"\n[GROUP 2: PARTIAL LINKS (Shared History)]")
        print("   -> Documents share a common ancestor or author but have diverged.")
        print("-" * 75)
        if partial_matches:
            partial_matches.sort(key=lambda x: x[3], reverse=True)
            for m in partial_matches:
                print(f"   ⛓  {m[3]:.0f}% | {m[0]} <--> {m[1]} ({m[2]} shared sessions)")
        else:
            print("   (None)")

        # ISOLATED FILES
        all_files_set = set(files)
        isolated = all_files_set - matched_files
        
        print(f"\n[GROUP 3: ISOLATED (No Links Found)]")
        print("   -> These files have unique history/DNA compared to the set.")
        print("-" * 75)
        if isolated:
            for iso in isolated:
                count = len(self.file_map[iso])
                print(f"   • {iso} (Unique RSIDs: {count})")
        else:
            print("   (None)")