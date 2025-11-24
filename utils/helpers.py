from colorama import Fore, Style

# Comprehensive OOXML Namespaces
NS = {
    # Core Word
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'rel': 'http://schemas.openxmlformats.org/package/2006/relationships',
    
    # Version specific (The missing piece)
    'w14': 'http://schemas.microsoft.com/office/word/2010/wordml',  # Needed for paraId
    'w15': 'http://schemas.microsoft.com/office/word/2012/wordml',  # Needed for docId
    
    # Metadata
    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'dc': 'http://purl.org/dc/elements/1.1/',
    'dcterms': 'http://purl.org/dc/terms/',
    'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
    
    # Math & others
    'm': 'http://schemas.openxmlformats.org/officeDocument/2006/math'
}

def log_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

def log_success(msg):
    print(f"{Fore.GREEN}[PASS]{Style.RESET_ALL} {msg}")

def log_warning(msg):
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {msg}")

def log_danger(msg):
    print(f"{Fore.RED}[ALERT]{Style.RESET_ALL} {msg}")

def banner():
    print(f"""{Fore.GREEN}
    ____             ____                  
   / __ \____  _____/ __ \___  _________  ____
  / / / / __ \/ ___/ /_/ / _ \/ ___/ __ \/ __ \\
 / /_/ / /_/ / /__/ _, _/  __/ /__/ /_/ / / / /
/_____/\____/\___/_/ |_|\___/\___/\____/_/ /_/ 
   
   DocRecon v1.0 | OOXML Forensics
    {Style.RESET_ALL}""")