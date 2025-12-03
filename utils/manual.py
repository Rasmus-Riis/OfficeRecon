"""
OfficeRecon Forensic Manual
Stores the help documentation for the suite.
"""

MANUAL_TEXT = """
OFFICERECON | FORENSIC SUITE
Version 3.0 (NC3 Edition)

[H1]1. INTRODUCTION
OfficeRecon is a specialized forensic tool designed to analyze Microsoft Office Open XML documents (.docx, .xlsx, .pptx) and OpenDocument formats (.odt). It bypasses the office application layer to inspect the raw XML and binary structures, revealing metadata hidden from the standard user interface.

[H1]2. BATCH TABLE COLUMNS
The main dashboard provides a high-level forensic overview. Here is what every column represents:

[H2]A. CRITICAL INDICATORS
• REMARKS (Verdict): AI-based assessment of the file's origin.
    - ORGANIC: Normal human editing patterns (high edit time, many saves).
    - SYNTHETIC: Created by software/scripts (0 edit time, perfect structure).
    - MIXED: Inconclusive data.
    - LOCKED: Password protected (Content is encrypted, but metadata may be visible).

• ATTENTION (Threats): Flags specific anomalies (MACROS, INJECTION, HIDDEN TEXT, USER LEAK).

• FORENSIC ARTIFACTS: Contains specific strings extracted during the batch scan, such as the exact content of hidden text, the name of a leaked user, or the URL of a malicious template.

• DEEP SCAN OUTPUT: If "Auto-Deep Scan" is enabled, this column contains the full ExifTool report and forensic timeline for the file.

• DUPLICATE: 
    - "X" (Red): Indicates this file's MD5 hash matches another file in the current list.
    - (Empty): Unique file in this session.

• MD5 HASH: The cryptographic fingerprint of the file.

[H2]B. IDENTITY & ORIGIN
• File Name: The name of the file on disk.
• Full Path: The absolute location of the file.
• Creator (Author): The name registered to the Office install that created it.
• Last Mod By: The name of the last user to save the file.
• Leaked User: Usernames found in binary paths (printer logs, embeddings).
• Software: The specific version of Office used (e.g., Microsoft Office 16.0000).
• OS: Platform fingerprint (Windows vs. Macintosh).

[H2]C. TIMESTAMPS (CHRONOLOGY)
• Meta Created: The internal creation date embedded in the XML.
• Meta Modified: The internal last-save date.
• Zip Date: The timestamp of the latest file inside the container.
• FS Created: File System creation date (When it arrived on THIS disk).
• FS Modified: File System modification date.
• FS Accessed: File System last access date.
• Last Printed: The internal timestamp of the last print job.

[H2]D. EDITING STATISTICS
• Edit Time: Total minutes the document was open for editing.
• Rev (Revision): Number of times the file was saved.
• RSIDs: Count of "Revision Save IDs". 
    - Low count (<5): Script generated or copy-pasted.
    - High count (>100): Heavily edited organic document.

[H2]E. CONTENT METRICS
• Pages: Number of pages (Word).
• Slides: Number of slides (PowerPoint).
• Words: Word count estimate.
• Media: Count of images/videos inside the document.
• Size: File size in KB.
• Template: The base template used (Normal.dotm or malicious remote link).
• Hidden: "Yes" if hidden text or hidden slides are detected.

[H1]3. DEEP FORENSIC SCAN
Double-clicking any row opens the Deep Scan window:

[H2]TAB 1: FORENSIC REPORT
• ExifTool Scan: Dumps raw XMP, IPTC, and obscure binary tags.
• Hidden Content: Extracts text hidden via CSS, font sizing, or color.
• Speaker Notes: (PowerPoint) Dumps presentation notes often missed.
• Embedding Scan: Looks for OLE objects (Excel sheets inside Word docs).

[H2]TAB 2: AUTHORS & TIMELINE
• RSID Timeline: Reconstructs the chronological history of the document.
• Script View: A screenplay-style readout of the editing session.

[H2]TAB 3: THUMBNAIL
• Visual Preview: Displays the internal thumbnail cached by Office. Note: This thumbnail often survives AFTER content is deleted, showing the "Ghost" of the original document.

[H1]4. KNOWN ARTIFACTS
• ZIP BOMBS: Malicious archives that expand to petabytes of data.
• METADATA STRIPPING: Tools that remove authors.
"""