from utils.helpers import NS, log_info, log_warning

class RSIDAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.rsid_map = {} # Stores all RSIDs from metadata
        self.paragraph_counts = {} # Maps RSID -> Count of paragraphs
        self.ordered_rsids = [] # Chronological list

    def run(self):
        print("\n--- RSID (Revision Save ID) Analysis ---")
        self._parse_settings()
        self._map_paragraphs()
        self._report_statistics()
        self._report_timeline()

    def _parse_settings(self):
        """Extracts the list of all RSIDs from settings.xml"""
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree:
            log_info("No settings.xml found.")
            return

        # The order of <w:rsid> tags in settings.xml represents the save history.
        rsids = tree.xpath('//w:rsid', namespaces=NS)
        log_info(f"Found {len(rsids)} distinct editing sessions (RSIDs) in metadata.")
        
        for r in rsids:
            val = r.get(f"{{{NS['w']}}}val")
            if val:
                self.rsid_map[val] = 0  # Initialize count to 0
                self.ordered_rsids.append(val)

    def _map_paragraphs(self):
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        paragraphs = tree.xpath('//w:p', namespaces=NS)
        
        for p in paragraphs:
            rsid = p.get(f"{{{NS['w']}}}rsidR")
            if rsid:
                self.paragraph_counts[rsid] = self.paragraph_counts.get(rsid, 0) + 1
                if rsid in self.rsid_map:
                    self.rsid_map[rsid] += 1

    def _report_statistics(self):
        if not self.paragraph_counts:
            log_warning("No RSID tags found in document body.")
            return

        sorted_sessions = sorted(self.paragraph_counts.items(), key=lambda x: x[1], reverse=True)
        
        print(f"\n[Volume Analysis - Who wrote the most?]")
        print(f"{'RSID':<15} | {'Paragraphs':<10} | {'% of Doc':<10}")
        print("-" * 40)
        
        total_p = sum(self.paragraph_counts.values())
        
        for rsid, count in sorted_sessions:
            percentage = (count / total_p) * 100
            print(f"{rsid:<15} | {count:<10} | {percentage:.1f}%")

    def _report_timeline(self):
        """Reconstructs the history and links First/Last IDs to Metadata Names."""
        
        # 1. Fetch Metadata Names for context
        core = self.loader.get_xml_tree('docProps/core.xml')
        creator = "Unknown"
        modifier = "Unknown"
        
        if core:
            c_node = core.xpath('//dc:creator', namespaces=NS)
            if c_node: creator = c_node[0].text
            
            m_node = core.xpath('//cp:lastModifiedBy', namespaces=NS)
            if m_node: modifier = m_node[0].text

        print(f"\n[Timeline Reconstruction - Chronological Save History]")
        print("Note: Earlier IDs = Earlier Saves. 'Ghost' = Saved but didn't write text.")
        print("-" * 75)

        for i, rsid in enumerate(self.ordered_rsids):
            activity = self.paragraph_counts.get(rsid, 0)
            status = f"wrote {activity} paragraphs" if activity > 0 else "GHOST (Metadata only)"
            
            # 2. Tag the First and Last explicitly
            prefix = ""
            if i == 0: 
                prefix = f" <-- Created by {creator}"
            elif i == len(self.ordered_rsids) - 1: 
                prefix = f" <-- Last Saved by {modifier}"
            
            print(f"{i+1:02d}. {rsid} : {status:<25} {prefix}")