from utils.helpers import NS, log_info, log_warning, log_success, log_danger
from datetime import datetime

class TrackChangesAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.insertions = []
        self.deletions = []
        self.moves = []

    def run(self):
        print("\n--- Track Changes History ---")
        self._extract_changes()
        self._report_changes()

    def _extract_changes(self):
        """Extract all tracked insertions, deletions, and moves."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            log_info("No document.xml found.")
            return

        # Extract insertions
        insertions = tree.xpath('//w:ins', namespaces=NS)
        for ins in insertions:
            author = ins.get(f"{{{NS['w']}}}author", 'Unknown')
            date = ins.get(f"{{{NS['w']}}}date", '')
            rsid = ins.get(f"{{{NS['w']}}}rsidR", '')
            
            # Extract text content
            text_nodes = ins.xpath('.//w:t', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            if text.strip():
                self.insertions.append({
                    'author': author,
                    'date': date,
                    'rsid': rsid,
                    'text': text.strip()
                })

        # Extract deletions
        deletions = tree.xpath('//w:del', namespaces=NS)
        for dele in deletions:
            author = dele.get(f"{{{NS['w']}}}author", 'Unknown')
            date = dele.get(f"{{{NS['w']}}}date", '')
            rsid = dele.get(f"{{{NS['w']}}}rsidDel", '')
            
            # Extract deleted text
            text_nodes = dele.xpath('.//w:delText', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            if text.strip():
                self.deletions.append({
                    'author': author,
                    'date': date,
                    'rsid': rsid,
                    'text': text.strip()
                })

        # Extract moves
        move_from = tree.xpath('//w:moveFrom', namespaces=NS)
        move_to = tree.xpath('//w:moveTo', namespaces=NS)
        
        for move in move_from:
            author = move.get(f"{{{NS['w']}}}author", 'Unknown')
            date = move.get(f"{{{NS['w']}}}date", '')
            move_id = move.get(f"{{{NS['w']}}}id", '')
            
            text_nodes = move.xpath('.//w:t', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            if text.strip():
                self.moves.append({
                    'type': 'from',
                    'author': author,
                    'date': date,
                    'id': move_id,
                    'text': text.strip()
                })

    def _report_changes(self):
        """Report all tracked changes found."""
        total_changes = len(self.insertions) + len(self.deletions) + len(self.moves)
        
        if total_changes == 0:
            log_success("No tracked changes found in document.")
            return

        log_warning(f"Found {total_changes} tracked changes ({len(self.insertions)} insertions, {len(self.deletions)} deletions, {len(self.moves)} moves)")
        
        if self.insertions:
            print("\n[INSERTIONS]:")
            for ins in self.insertions[:10]:  # Show first 10
                print(f"  + By {ins['author']} ({ins['date']}): \"{ins['text'][:100]}...\"" if len(ins['text']) > 100 else f"  + By {ins['author']} ({ins['date']}): \"{ins['text']}\"")
            if len(self.insertions) > 10:
                print(f"  ... and {len(self.insertions) - 10} more insertions")

        if self.deletions:
            print("\n[DELETIONS - RECOVERABLE DATA]:")
            for dele in self.deletions[:10]:  # Show first 10
                print(f"  - By {dele['author']} ({dele['date']}): \"{dele['text'][:100]}...\"" if len(dele['text']) > 100 else f"  - By {dele['author']} ({dele['date']}): \"{dele['text']}\"")
            if len(self.deletions) > 10:
                print(f"  ... and {len(self.deletions) - 10} more deletions")
                
        if self.moves:
            print(f"\n[MOVES]: {len(self.moves)} content relocations detected")

