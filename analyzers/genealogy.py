import os
import zipfile
from lxml import etree
from utils.helpers import NS, log_info, log_success

class GenealogyMapper:
    def __init__(self, folder_path):
        self.folder = folder_path
        self.file_map = {} # {filename: set(rsids)}

    def run(self):
        print(f"\n--- RSID Genealogy Mapping (Folder: {self.folder}) ---")
        self._scan_folder()
        self._find_relationships()

    def _scan_folder(self):
        files = [f for f in os.listdir(self.folder) if f.endswith('.docx')]
        log_info(f"Scanning {len(files)} documents for DNA markers (RSIDs)...")

        for f in files:
            path = os.path.join(self.folder, f)
            rsids = self._extract_rsids(path)
            if rsids:
                self.file_map[f] = set(rsids)

    def _extract_rsids(self, filepath):
        """Quick extraction without full DocLoader overhead"""
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                if 'word/settings.xml' not in z.namelist():
                    return []
                xml = z.read('word/settings.xml')
                root = etree.fromstring(xml)
                return [elem.get(f"{{{NS['w']}}}val") for elem in root.xpath('//w:rsid', namespaces=NS)]
        except:
            return []

    def _find_relationships(self):
        files = list(self.file_map.keys())
        found_matches = False
        
        # Compare every file against every other file
        for i in range(len(files)):
            for j in range(i + 1, len(files)):
                f1 = files[i]
                f2 = files[j]
                
                rsid1 = self.file_map[f1]
                rsid2 = self.file_map[f2]
                
                # Intersection: RSIDs present in BOTH files
                shared = rsid1.intersection(rsid2)
                
                if len(shared) > 0:
                    found_matches = True
                    self._print_match(f1, f2, len(shared), len(rsid1), len(rsid2))

        if not found_matches:
            log_info("No shared editing history found between documents.")

    def _print_match(self, f1, f2, shared_count, total1, total2):
        # Calculate similarity score based on the smaller document
        # (If Doc A is inside Doc B, Doc A is 100% match, even if B is huge)
        min_len = min(total1, total2)
        similarity = (shared_count / min_len) * 100
        
        print(f"🔗 MATCH: {f1} <--> {f2}")
        print(f"   Shared Sessions: {shared_count}")
        print(f"   Genealogy Score: {similarity:.1f}% likelihood of shared origin")
        print("-" * 40)