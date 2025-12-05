import sys

# Namespaces for OOXML parsing (Word, Excel, PowerPoint)
NS = {
    # Core OpenXML
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'dc': 'http://purl.org/dc/elements/1.1/',
    'dcterms': 'http://purl.org/dc/terms/',
    'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'rel': 'http://schemas.openxmlformats.org/package/2006/relationships',
    'vt': 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes',
    'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
    'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
    'mc': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    
    # Microsoft Version Specifics
    'w14': 'http://schemas.microsoft.com/office/word/2010/wordml', # <--- The Missing Key
    'w15': 'http://schemas.microsoft.com/office/word/2012/wordml',
    'w16se': 'http://schemas.microsoft.com/office/word/2015/wordml/symex',
    'v': 'urn:schemas-microsoft-com:vml',
    'o': 'urn:schemas-microsoft-com:office:office',
    'm': 'http://schemas.openxmlformats.org/officeDocument/2006/math',
    'sl': 'http://schemas.openxmlformats.org/schemaLibrary/2006/main'
}

# ANSI Colors for Console Output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"

def _strip_ansi(text):
    """Strip ANSI color codes when output is redirected (not a terminal)."""
    import re
    # Check if stdout is a real terminal
    if hasattr(sys.stdout, 'isatty') and callable(sys.stdout.isatty) and sys.stdout.isatty():
        return text  # Keep colors for terminal
    else:
        # Strip ANSI codes when redirected to GUI or file
        return re.sub(r'\033\[[0-9;]+m', '', text)

def log_info(msg):
    """Prints an info message in Blue."""
    print(_strip_ansi(f"{BLUE}[INFO]{RESET} {msg}"))

def log_success(msg):
    """Prints a success message in Green."""
    print(_strip_ansi(f"{GREEN}[PASS]{RESET} {msg}"))

def log_warning(msg):
    """Prints a warning message in Yellow."""
    print(_strip_ansi(f"{YELLOW}[WARN]{RESET} {msg}"))

def log_danger(msg):
    """Prints an alert message in Red."""
    print(_strip_ansi(f"{RED}[ALERT]{RESET} {msg}"))