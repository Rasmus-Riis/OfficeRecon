from utils.helpers import NS, log_info, log_warning

class RSIDAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.rsid_map = {} # Stores all RSIDs from metadata
        self.paragraph_counts = {} # Maps RSID -> Count of paragraphs

    def run(self):
        print("\n--- RSID (Revision Save ID) Analysis ---")
        self._parse_settings()
        self._map_paragraphs()
        self._report()

    def _parse_settings(self):
        """Extracts the list of all RSIDs from settings.xml"""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree:
            log_info("No settings.xml found.")
            return

        rsids = tree.xpath('//w:rsid', namespaces=NS)
        log_info(f"Found {len(rsids)} distinct editing sessions (RSIDs) in metadata.")
        
        for r in rsids:
            val = r.get(f"{{{NS['w']}}}val")
            self.rsid_map[val] = 0  # Initialize count to 0

    def _map_paragraphs(self):
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        paragraphs = tree.xpath('//w:p', namespaces=NS)
        
        for p in paragraphs:
            rsid = p.get(f"{{{NS['w']}}}rsidR")
            if rsid:
                # Count it. If it wasn't in metadata (weird but possible), add it.
                self.paragraph_counts[rsid] = self.paragraph_counts.get(rsid, 0) + 1
                
                # Also update the map if it exists there
                if rsid in self.rsid_map:
                    self.rsid_map[rsid] += 1

    def _report(self):
        if not self.paragraph_counts:
            log_warning("No RSID tags found in document body.")
            return

        # Sort by most active
        sorted_sessions = sorted(self.paragraph_counts.items(), key=lambda x: x[1], reverse=True)
        
        print(f"{'RSID':<15} | {'Paragraphs':<10} | {'% of Doc':<10}")
        print("-" * 40)
        
        total_p = sum(self.paragraph_counts.values())
        
        for rsid, count in sorted_sessions:
            percentage = (count / total_p) * 100
            print(f"{rsid:<15} | {count:<10} | {percentage:.1f}%")

        # --- NEW: Identify Ghosts ---
        # Find RSIDs that are in the map (Metadata) but NOT in paragraph_counts (Text)
        ghosts = [r for r in self.rsid_map if r not in self.paragraph_counts]
        
        if ghosts:
            print("-" * 40)
            print(f"[INFO] Detected {len(ghosts)} 'Ghost' Sessions (Metadata only - No text content):")
            print(f"       -> {', '.join(ghosts)}")
            print("       -> These users saved the file but did not write any currently visible paragraphs.")