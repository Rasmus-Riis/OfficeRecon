from utils.helpers import NS, log_info, log_success, log_warning

class AuthorAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.rsid_to_user = {} 
        self.ordered_rsids = [] 

    def run(self):
        print("\n--- User & RSID Attribution ---")
        self._get_rsid_order()
        self._scan_track_changes()
        self._scan_comments()
        self._infer_metadata_attribution()
        self._report_identities()
        self._visualize_authorship()

    def _get_rsid_order(self):
        settings = self.loader.get_xml_tree('word/settings.xml')
        if not settings: return
        rsids = settings.xpath('//w:rsid', namespaces=NS)
        for r in rsids:
            val = r.get(f"{{{NS['w']}}}val")
            if val: self.ordered_rsids.append(val)

    def _scan_track_changes(self):
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return
        changes = tree.xpath('//w:ins | //w:del', namespaces=NS)
        for node in changes:
            author = node.get(f"{{{NS['w']}}}author")
            rsid = node.get(f"{{{NS['w']}}}rsidR")
            if author and rsid and rsid not in self.rsid_to_user:
                self.rsid_to_user[rsid] = {'author': author, 'source': 'Track Changes'}

    def _scan_comments(self):
        tree = self.loader.get_xml_tree('word/comments.xml')
        if not tree: return
        comments = tree.xpath('//w:comment', namespaces=NS)
        for c in comments:
            author = c.get(f"{{{NS['w']}}}author")
            paras = c.xpath('.//w:p', namespaces=NS)
            for p in paras:
                rsid = p.get(f"{{{NS['w']}}}rsidR")
                if rsid and author and rsid not in self.rsid_to_user:
                    self.rsid_to_user[rsid] = {'author': author, 'source': 'Comment'}

    def _infer_metadata_attribution(self):
        core = self.loader.get_xml_tree('docProps/core.xml')
        if not core: return
        
        c_node = core.xpath('//dc:creator', namespaces=NS)
        creator = c_node[0].text if c_node else "Unknown"
        
        m_node = core.xpath('//cp:lastModifiedBy', namespaces=NS)
        modifier = m_node[0].text if m_node else "Unknown"

        if not self.ordered_rsids: return

        # 1. Link First RSID
        first = self.ordered_rsids[0]
        if first not in self.rsid_to_user and creator != "Unknown":
            self.rsid_to_user[first] = {'author': creator, 'source': 'Meta: Creator'}

        # 2. Link Last RSID
        last = self.ordered_rsids[-1]
        if last not in self.rsid_to_user and modifier != "Unknown":
            self.rsid_to_user[last] = {'author': modifier, 'source': 'Meta: Last Save'}

    def _report_identities(self):
        if not self.rsid_to_user:
            log_info("No explicit link found between RSIDs and Usernames.")
            return

        print(f"{'RSID':<15} | {'Identified User':<25} | {'Source':<15}")
        print("-" * 65)
        for rsid, data in self.rsid_to_user.items():
            print(f"{rsid:<15} | {data['author']:<25} | {data['source']:<15}")
        print("-" * 65)

    def _visualize_authorship(self):
        print("\n[Content Attribution - Who wrote what?]")
        # Marker line for the GUI parser to find
        print(">>>START_SCRIPT_VIEW<<<") 
        
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        paragraphs = tree.xpath('//w:p', namespaces=NS)
        
        for p in paragraphs:
            rsid = p.get(f"{{{NS['w']}}}rsidR")
            if not rsid: continue

            if rsid in self.rsid_to_user:
                owner = self.rsid_to_user[rsid]['author']
            else:
                owner = f"Unknown [{rsid}]"
            
            text_nodes = p.xpath('.//w:t', namespaces=NS)
            full_text = "".join([t.text for t in text_nodes if t.text])
            
            if full_text.strip():
                # We print a specific delimiter "|||" so the GUI can split it easily
                print(f"{owner}|||{full_text}")