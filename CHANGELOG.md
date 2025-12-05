# OfficeRecon Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2025-12-04

### Added - Major Format Support Expansion

#### New Format Support
- **XLSX (Excel) Full Support**: Comprehensive forensic analysis for Excel spreadsheets
- **PPTX (PowerPoint) Enhanced Support**: Significantly expanded PowerPoint analysis capabilities
- **OpenDocument Formats**: Complete support for ODT, ODS, and ODP files from LibreOffice/OpenOffice

#### XLSX Forensic Capabilities
- Hidden sheets detection (both hidden and very hidden states)
- Hidden rows and columns analysis across all sheets
- Comment extraction with full author information and timestamps
- Formula analysis with detection of potentially dangerous functions (HYPERLINK, WEBSERVICE, INDIRECT, etc.)
- Defined names scanning for data hiding and potential exfiltration
- External data connections and workbook links detection
- Data validation rules inspection
- VBA macro detection in XLSX/XLSM files
- Sheet and workbook protection analysis
- Custom document properties extraction
- Comprehensive metadata analysis

#### PPTX Enhanced Capabilities
- Hidden slides detection and enumeration
- Speaker notes extraction from all slides
- Comment threads with complete authorship tracking
- Editing session history with machine GUID identification
- Slide master content analysis for hidden information
- Embedded objects and OLE inspection
- Animation detection across slides
- Custom properties extraction
- Enhanced metadata analysis (creation software, total edit time, authors)
- Presentation format and settings analysis

#### OpenDocument (ODT/ODS/ODP) Capabilities
- Tracked changes detection with full author and timestamp information
- Deleted content recovery from tracked changes
- Comment and annotation extraction with threading support
- Version history detection and enumeration
- Hidden content analysis:
  - Hidden text and paragraphs (ODT)
  - Hidden sheets, rows, and columns (ODS)
  - Hidden slides (ODP)
- LibreOffice Basic macro detection
- Embedded object inspection
- Custom metadata properties
- Document protection status
- Format-specific statistics:
  - ODT: paragraphs, headings, tables, images, fields
  - ODS: sheet count, formulas, suspicious formula detection
  - ODP: slide count, notes, animations
- Edit time and editing cycles tracking

### Enhanced

#### Core Components
- **DocLoader (core/loader.py)**: 
  - Enhanced format detection for ODS and ODP using mimetype analysis
  - Added helper methods: `file_exists()`, `list_files()` for improved file introspection
  - Better error handling and format identification

- **MetadataAnalyzer (analyzers/metadata.py)**:
  - Extended to support XLSX and PPTX metadata extraction
  - Unified OpenDocument metadata parsing for all OD formats
  - Improved format detection and routing

- **BatchAnalyzer (analyzers/batch.py)**:
  - Added `_analyze_xlsx_specifics()` method for Excel-specific quick scanning
  - Added unified `_analyze_opendocument()` method for ODT/ODS/ODP
  - Enhanced threat detection for new formats
  - Improved forensic artifact reporting

- **PPTXDeepAnalyzer (analyzers/pptx_deep.py)**:
  - Complete rewrite with 10+ new analysis methods
  - Added metadata extraction from core and app properties
  - Enhanced comment extraction with better author tracking
  - Improved speaker notes extraction with slide numbering
  - Added slide master and layout analysis
  - Embedded object detection
  - Animation scanning
  - Custom properties support

#### Main Application (OfficeRecon.py)
- Updated version to 1.2.0
- Integrated XLSXDeepAnalyzer and OpenDocumentAnalyzer into deep scan workflow
- Extended file type support in ZIP processing (.ods, .odp, .xlsm)
- Updated deep scan logic to route formats to appropriate analyzers
- Improved format-specific analysis routing

### New Analyzers

#### XLSXDeepAnalyzer (analyzers/xlsx_deep.py)
Comprehensive Excel forensic analyzer with 13 analysis methods:
- Metadata analysis
- Sheet scanning (visible, hidden, very hidden)
- Hidden content detection (rows and columns)
- Comment extraction with authors and locations
- Defined names analysis
- External links and connections detection
- Data validation scanning
- Formula analysis with threat detection
- Protection status checking
- Macro detection
- Custom properties extraction

#### OpenDocumentAnalyzer (analyzers/opendocument.py)
Unified analyzer for all OpenDocument formats with 12+ analysis methods:
- Comprehensive metadata extraction
- Tracked changes detection and extraction
- Comment and annotation analysis
- Version history detection
- Hidden content scanning (format-specific)
- Macro detection (LibreOffice Basic)
- Embedded object inspection
- Custom properties extraction
- Protection status analysis
- Format-specific deep analysis (ODT/ODS/ODP)

### Dependencies
- Added `openpyxl` for Excel file processing
- Added `python-pptx` for PowerPoint analysis support
- Added `odfpy` for OpenDocument format support
- Added `oletools` for VBA macro analysis

### Documentation
- Updated README.md with comprehensive format support information
- Added detailed feature descriptions for each format
- Updated installation instructions with new dependencies
- Enhanced usage examples

### Technical Improvements
- Better XML namespace handling across all formats
- Improved error handling and graceful degradation
- Enhanced logging and debug output
- More robust file type detection
- Better memory management for large files

---

## [1.1.0] - Previous Release

### Added
- Track changes analyzer
- Comment analyzer
- Field analyzer
- Deleted content analyzer
- Protection analyzer
- Printer analyzer
- Hyperlink analyzer
- Smart tags analyzer
- Footnotes analyzer
- Dictionary analyzer
- Font analyzer
- Table analyzer
- Section analyzer
- Content types analyzer

---

## [1.0.0] - Initial Release

### Features
- Basic DOCX analysis
- Metadata extraction
- RSID analysis
- Threat scanning
- Macro detection
- Media analysis
- Author analysis
- Extended properties
- Embedding analysis
- Basic PPTX support
- ExifTool integration
- Batch processing
- ZIP archive support
- Excel export
- GUI interface with CustomTkinter
