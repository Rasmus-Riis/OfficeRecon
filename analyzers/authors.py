from utils.helpers import NS, log_info, log_success, log_warning

class AuthorAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.rsid_to_user = {} # Maps RSID -> {author, date}

    def run(self):
        print("\n--- User & RSID Attribution ---")
        self._scan_track_changes()
        self._scan_comments()
        self._infer_from_metadata()
        self._report()

    def _scan_track_changes(self):
        """Scans for <w:ins> and <w:del> tags which link RSIDs to Authors."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return

        # Look for insertions and deletions
        changes = tree.xpath('//w:ins | //w:del', namespaces=NS)
        
        for node in changes:
            author = node.get(f"{{{NS['w']}}}author")
            date = node.get(f"{{{NS['w']}}}date")
            rsid = node.get(f"{{{NS['w']}}}rsidR")
            
            if author and rsid:
                # Store the link. We keep the earliest date found for that user/rsid combo.
                if rsid not in self.rsid_to_user:
                    self.rsid_to_user[rsid] = {'author': author, 'date': date, 'source': 'Track Changes'}

    def _scan_comments(self):
        """Scans comments.xml, which links RSIDs to Authors."""
        tree = self.loader.get_xml_tree('word/comments.xml')
        if not tree: return

        comments = tree.xpath('//w:comment', namespaces=NS)
        for c in comments:
            author = c.get(f"{{{NS['w']}}}author")
            date = c.get(f"{{{NS['w']}}}date")
            # Comments don't always have an RSID attribute on the comment node itself,
            # but paragraphs inside the comment might.
            # This is a secondary check.
            
            # Checking paragraphs inside the comment
            paras = c.xpath('.//w:p', namespaces=NS)
            for p in paras:
                rsid = p.get(f"{{{NS['w']}}}rsidR")
                if rsid and author:
                    if rsid not in self.rsid_to_user:
                        self.rsid_to_user[rsid] = {'author': author, 'date': date, 'source': 'Comment'}

    def _infer_from_metadata(self):
        """Attempts to link the Root RSID to the Creator."""
        # 1. Get Creator
        core = self.loader.get_xml_tree('docProps/core.xml')
        if not core: return
        
        creator_node = core.xpath('//dc:creator', namespaces=NS)
        creator = creator_node[0].text if creator_node else "Unknown"

        # 2. Get Root RSID
        settings = self.loader.get_xml_tree('word/settings.xml')
        if not settings: return
        
        root_node = settings.find('.//w:rsidRoot', namespaces=NS)
        root_rsid = root_node.get(f"{{{NS['w']}}}val") if root_node is not None else None

        if root_rsid and creator != "Unknown":
            # We only add this if we don't already have a hard link from Track Changes
            if root_rsid not in self.rsid_to_user:
                 self.rsid_to_user[root_rsid] = {'author': creator, 'date': 'Creation', 'source': 'Metadata Inference'}

    def _report(self):
        if not self.rsid_to_user:
            log_info("No explicit link found between RSIDs and Usernames.")
            return

        print(f"{'RSID':<15} | {'Identified User':<20} | {'Source':<15} | {'Date Detected'}")
        print("-" * 75)
        
        for rsid, data in self.rsid_to_user.items():
            print(f"{rsid:<15} | {data['author']:<20} | {data['source']:<15} | {data.get('date', 'N/A')}")
        
        log_success(f"Deanonymized {len(self.rsid_to_user)} RSID sessions.")