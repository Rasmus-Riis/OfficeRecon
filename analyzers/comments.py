from utils.helpers import NS, log_info, log_warning, log_success

class CommentAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.comments = []

    def run(self):
        print("\n--- Comment & Annotation Forensics ---")
        self._extract_comments()
        self._report_comments()

    def _extract_comments(self):
        """Extract all comments with full metadata."""
        tree = self.loader.get_xml_tree('word/comments.xml')
        if not tree:
            log_info("No comments.xml found.")
            return

        comments = tree.xpath('//w:comment', namespaces=NS)
        
        for comment in comments:
            comment_id = comment.get(f"{{{NS['w']}}}id", '')
            author = comment.get(f"{{{NS['w']}}}author", 'Unknown')
            date = comment.get(f"{{{NS['w']}}}date", '')
            initials = comment.get(f"{{{NS['w']}}}initials", '')
            
            # Extract comment text
            text_nodes = comment.xpath('.//w:t', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            # Check if it's a reply
            parent_id = comment.get(f"{{{NS['w']}}}parentId", '')
            
            self.comments.append({
                'id': comment_id,
                'author': author,
                'initials': initials,
                'date': date,
                'text': text.strip(),
                'parent_id': parent_id,
                'is_reply': bool(parent_id)
            })

    def _report_comments(self):
        """Report all comments found."""
        if not self.comments:
            log_success("No comments found in document.")
            return

        log_warning(f"Found {len(self.comments)} comments/annotations")
        
        # Group by author
        authors = {}
        for comment in self.comments:
            author = comment['author']
            if author not in authors:
                authors[author] = []
            authors[author].append(comment)
        
        print(f"\n[COMMENT AUTHORS]: {', '.join(authors.keys())}")
        
        # Show comment threads
        top_level = [c for c in self.comments if not c['is_reply']]
        replies = [c for c in self.comments if c['is_reply']]
        
        print(f"\n[COMMENT STRUCTURE]: {len(top_level)} original comments, {len(replies)} replies")
        
        # Show sample comments
        print("\n[COMMENT SAMPLES]:")
        for i, comment in enumerate(self.comments[:5]):
            prefix = "  └─ " if comment['is_reply'] else "  • "
            text_preview = comment['text'][:80] + "..." if len(comment['text']) > 80 else comment['text']
            print(f"{prefix}By {comment['author']} ({comment['date']}): \"{text_preview}\"")
        
        if len(self.comments) > 5:
            print(f"  ... and {len(self.comments) - 5} more comments")
