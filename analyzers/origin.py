from utils.helpers import NS, log_info, log_warning, log_danger, log_success

class OriginAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- File Origin & Integrity Forensics ---")
        
        # 1. Run the Synthetic Check (Sequential IDs)
        is_synthetic = self._check_sequential_para_ids()
        
        # 2. Run the "Washed" Check (Google Doc saved in Word)
        is_washed = self._check_washed_state()

        if is_synthetic:
            log_danger("VERDICT: SYNTHETIC / GENERATED.")
            print("   -> Paragraph IDs are sequential. File is a direct export (Google Docs/Script).")
        elif is_washed:
            log_warning("VERDICT: HYBRID / WASHED.")
            print("   -> File originated externally but was re-saved in Microsoft Word.")
            print("   -> 'Born-on' date in metadata likely contradicts internal structure.")
        else:
            log_success("VERDICT: ORGANIC.")
            print("   -> File appears to be a native, human-created Microsoft Word document.")

    def _check_sequential_para_ids(self):
        """Checks for the strict 1, 2, 3... ID sequence (Direct Google Export)."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree: return False
        
        # Using wildcard namespace for robustness
        para_ids = [p.get(f"{{{NS['w14']}}}paraId") for p in tree.xpath('//w:p', namespaces=NS)]
        valid_ids = [int(pid, 16) for pid in para_ids if pid]

        if len(valid_ids) < 5: return False

        sorted_ids = sorted(valid_ids)
        sequential_hits = 0
        for i in range(len(sorted_ids) - 1):
            if sorted_ids[i+1] - sorted_ids[i] == 1:
                sequential_hits += 1

        # If >50% are sequential, it's synthetic
        return (sequential_hits / len(valid_ids)) > 0.5

    def _check_washed_state(self):
        """
        Detects a file that was Synthetic but then saved in Word.
        Logic:
        1. It has RSIDs (Word has touched it).
        2. BUT the history is suspiciously short for a document of its age/complexity.
        3. OR it contains specific Compatibility Settings often found in conversions.
        """
        settings_tree = self.loader.get_xml_tree('word/settings.xml')
        if not settings_tree: return False

        # A. Check for the "Rebirth" (Short RSID list in a complex doc)
        rsids = settings_tree.xpath('//w:rsid', namespaces=NS)
        rsid_count = len(rsids)
        
        # If we have very few editing sessions (e.g., < 10) but the file isn't brand new
        # This implies the history was wiped recently.
        is_short_history = 0 < rsid_count < 10

        # B. Check Compatibility Mode
        # Google Docs often forces specific compat modes when saved in Word
        compat = settings_tree.find('.//w:compatSetting[@w:name="compatibilityMode"]', namespaces=NS)
        compat_val = compat.get(f"{{{NS['w']}}}val") if compat is not None else "0"
        
        # C. Check for "Foreign" Locale injection (e.g., en-DK on a US-based doc structure)
        # This is weak evidence on its own but strong in context
        lang = settings_tree.find('.//w:themeFontLang', namespaces=NS)
        lang_val = lang.get(f"{{{NS['w']}}}val") if lang is not None else ""

        if is_short_history and compat_val == "15":
            print(f"   -> Anomaly: RSID history is very short ({rsid_count} sessions) for a Compatibility Mode 15 file.")
            print("   -> This suggests the file's history was reset (e.g., downloaded and re-saved).")
            
            if lang_val:
                 print(f"   -> Locale Marker: '{lang_val}' (Likely the system that performed the re-save).")
            
            return True
            
        return False