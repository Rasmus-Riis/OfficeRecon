import argparse
import os
from core.loader import DocLoader
from analyzers.rsid import RSIDAnalyzer
from analyzers.threats import ThreatScanner
from analyzers.styles import StyleAnalyzer
from analyzers.deep_scan import DeepScanAnalyzer
from analyzers.origin import OriginAnalyzer  # <--- NEW IMPORT
from analyzers.genealogy import GenealogyMapper
from analyzers.metadata import MetadataAnalyzer
from utils.helpers import banner, log_danger, log_info
from analyzers.authors import AuthorAnalyzer
from analyzers.embeddings import EmbeddingAnalyzer
from analyzers.platform import PlatformAnalyzer
from analyzers.fields import FieldAnalyzer

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="Forensic analysis of Word Documents (OOXML)")
    parser.add_argument("target", help="Path to a .docx file OR a directory of files")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        log_danger(f"Target not found: {args.target}")
        return

    # MODE 1: Genealogy Mapping (Directory)
    if os.path.isdir(args.target):
        mapper = GenealogyMapper(args.target)
        mapper.run()

    # MODE 2: Deep Analysis (Single File)
    elif os.path.isfile(args.target) and args.target.endswith('.docx'):
        log_info(f"Targeting Single File: {os.path.basename(args.target)}")
        loader = DocLoader(args.target)
        
        if loader.load():
            # 1. Origin Analysis (Is this even a real Word doc?)
            # Run this first to set the stage.
            origin = OriginAnalyzer(loader)
            origin.run()
            
            # 2. Platform/OS Analysis
            platform = PlatformAnalyzer(loader)
            platform.run()

            # 3. Metadata
            meta = MetadataAnalyzer(loader)
            meta.run()
            
            # 4. RSID Structure
            rsid = RSIDAnalyzer(loader)
            rsid.run()
            
            # 5. Author Attribution
            author_engine = AuthorAnalyzer(loader)
            author_engine.run()

            # 6. Threat Scan
            threat = ThreatScanner(loader)
            threat.run()

            # 7. Styles
            styles = StyleAnalyzer(loader)
            styles.run()
            
            # 8. Deep Artifacts
            deep = DeepScanAnalyzer(loader)
            deep.run()
            
            # 9. Embeddings & Leaks
            embed_engine = EmbeddingAnalyzer(loader)
            embed_engine.run()
            
            # 10. Field & ID Analysis
            field_engine = FieldAnalyzer(loader)
            field_engine.run()

            loader.close()
    else:
        log_danger("Invalid input. Please provide a .docx file or a directory.")

if __name__ == "__main__":
    main()