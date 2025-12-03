# OfficeRecon

**OfficeRecon** is a comprehensive forensic analysis tool for Microsoft Office documents (Word, Excel, PowerPoint). It helps identify potentially manipulated documents by extracting and analyzing metadata, revisions, hidden content, and document history.

![OfficeRecon Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## 🔍 Features

### Core Analysis Capabilities
- **Metadata Extraction & Analysis** - Deep inspection of document properties, creation dates, modification history, and author information
- **Revision Detection** - Identifies document revisions, edit history, and RSID (Revision Session ID) patterns
- **Hidden Content Discovery** - Detects hidden text, white-on-white text, and concealed content within documents
- **Macro & Embedding Analysis** - Scans for macros, embedded objects, and potential security threats
- **Media File Extraction** - Extracts and analyzes images and media embedded in documents
- **Authorship Patterns** - Identifies multiple authors, leaked usernames, and editing patterns
- **Template Analysis** - Detects document templates and software used for creation
- **Timestamp Forensics** - Compares filesystem timestamps with internal metadata

### Advanced Features
- **Batch Processing** - Analyze entire folders of documents simultaneously
- **ZIP Archive Support** - Scan documents within archive files
- **Deep Scan Mode** - Automated comprehensive analysis with detailed reports
- **Duplicate Detection** - Identifies duplicate files using MD5 hashing
- **Excel Export** - Generate detailed forensic reports in Excel format
- **ExifTool Integration** - Extended metadata extraction using ExifTool by Phil Harvey
- **Activity Logging** - Complete audit trail of all analysis operations

### User Interface
- **Modern Dark Theme** - Built with CustomTkinter for a sleek, professional interface
- **Evidence Viewer** - Interactive panel for detailed file inspection
- **Real-time Filtering** - Quick search across all file attributes
- **Sortable Columns** - Click any column header to sort results
- **Right-click Context Menu** - Quick access to deep scan and file location features

## 📥 Installation

### Prerequisites
- Windows 10/11
- Python 3.8+ (for running from source)
- ExifTool (optional, for enhanced metadata extraction)

### Option 1: Pre-built Executable (Recommended)
1. Download the latest release from the [Releases](https://github.com/Rasmus-Riis/OfficeRecon/releases) page
2. Extract the archive to your desired location
3. (Optional) Download [ExifTool](https://exiftool.org/) and place `exiftool.exe` and `exiftool_files` folder in the same directory
4. Run `OfficeRecon.exe`

### Option 2: Run from Source
```bash
# Clone the repository
git clone https://github.com/Rasmus-Riis/OfficeRecon.git
cd OfficeRecon

# Install dependencies
pip install -r requirements.txt

# Run the application
python OfficeRecon.py
```

### ExifTool Setup (Optional but Recommended)
For enhanced metadata extraction:
1. Download ExifTool from [https://exiftool.org/](https://exiftool.org/)
2. Rename the downloaded executable to `exiftool.exe`
3. Place `exiftool.exe` and the `exiftool_files` directory in the same folder as OfficeRecon
4. OfficeRecon will automatically detect and use ExifTool

**Note:** ExifTool is distributed under the Artistic/GPL license by Phil Harvey.

## 🚀 Usage

### Basic Workflow
1. **Launch OfficeRecon** - Start the application
2. **Load Documents** - Click "LOAD FOLDER" to scan a directory, or "Load File" for individual documents
3. **Review Results** - Examine the analysis results in the main table
4. **Deep Scan** - Double-click any file or right-click → "Deep Scan" for comprehensive analysis
5. **Export Report** - Click "EXPORT XLSX" to generate a detailed Excel report

### Understanding the Results

#### Remarks Column
- **✓ OK** - No suspicious indicators detected
- **⚠ ALTERED** - Document shows signs of modification
- **⚠ CHECK** - Requires manual review
- **❌ FAIL** - Document could not be analyzed

#### Attention Column
Lists specific forensic indicators found, such as:
- Multiple authors detected
- Suspicious timestamps
- Hidden content
- Macro presence
- Template modifications
- Username leaks

#### Evidence Viewer
Select any row to view detailed forensic information in the Evidence Viewer panel at the bottom.

### Advanced Features

#### Auto-Deep Scan
Enable "Auto-Deep Scan" in the sidebar to automatically perform comprehensive analysis on all loaded files.

#### Search & Filter
Use the filter bar to quickly locate specific files, authors, or indicators across your entire dataset.

#### Activity Logs
Click "VIEW LOGS" to see a complete audit trail of all analysis operations performed during the session.

## 📊 Supported File Formats

- **Microsoft Word** - `.docx`, `.doc`
- **Microsoft Excel** - `.xlsx`, `.xls`
- **Microsoft PowerPoint** - `.pptx`, `.ppt`
- **Archives** - `.zip` files containing Office documents

## 🔐 Privacy & Security

- **Offline Operation** - All analysis is performed locally on your machine
- **No Data Collection** - OfficeRecon does not send any data externally
- **No Telemetry** - Your analysis activities remain completely private
- **Open Source** - Full source code available for audit

## 🛠️ Technical Details

### Architecture
- **Language:** Python 3.13
- **UI Framework:** CustomTkinter (modern dark theme)
- **Office Document Processing:** python-docx, openpyxl, python-pptx
- **Metadata Extraction:** oletools, ExifTool integration
- **Report Generation:** openpyxl

### Modular Design
OfficeRecon uses a modular architecture for easy maintenance and extensibility:
- **Core Loader** - Document loading and ZIP handling
- **Analyzers** - Specialized modules for different analysis types
- **GUI Components** - Forensic table and report windows
- **Utilities** - Export, manual, and helper functions

## 📝 Example Use Cases

### Digital Forensics
Investigate potentially tampered documents in legal or corporate investigations.

### Data Breach Analysis
Identify leaked usernames, modification patterns, and unauthorized edits.

### Document Authenticity
Verify the authenticity and integrity of submitted documents.

### OSINT (Open Source Intelligence)
Extract metadata and hidden information from publicly available documents.

### Quality Assurance
Ensure documents meet organizational metadata standards before distribution.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup
```bash
git clone https://github.com/Rasmus-Riis/OfficeRecon.git
cd OfficeRecon
pip install -r requirements.txt
```

### Building from Source
```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller OfficeRecon.spec --clean
```

The built executable will be in the `dist` folder.

## 📄 License

OfficeRecon is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

### Third-Party Components
- **ExifTool** by Phil Harvey - Artistic/GPL License (optional component, not bundled)
- **Python Libraries** - Various open-source licenses (see requirements.txt)

## 👨‍💻 Author

**Rasmus Riis**
- GitHub: [@Rasmus-Riis](https://github.com/Rasmus-Riis)

## ⚖️ Legal Disclaimer

OfficeRecon is provided for legitimate forensic analysis, security research, and educational purposes. Users are responsible for ensuring their use of this tool complies with applicable laws and regulations. The author assumes no liability for misuse of this software.

## 🔗 Related Projects

- **[PDFRecon](https://github.com/Rasmus-Riis/PDFRecon)** - Companion tool for PDF forensic analysis

## ⭐ Support

If you find OfficeRecon useful, please consider:
- Starring the repository ⭐
- Reporting issues or bugs
- Suggesting new features
- Contributing to the codebase

## 📜 Changelog

### Version 1.0.0 (2025-12-03)
- Initial release
- Core forensic analysis features
- Modern CustomTkinter UI
- Batch processing support
- Excel report generation
- ExifTool integration
- Auto-update checker
- Comprehensive documentation

---

**Note:** This tool is designed for forensic analysis and security research. Always ensure you have proper authorization before analyzing documents.
