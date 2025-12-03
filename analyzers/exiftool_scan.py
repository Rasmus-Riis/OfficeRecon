import subprocess
import os
import sys
import json

class ExifToolScanner:
    def __init__(self, filepath):
        self.filepath = filepath
        self.exif_path = self._get_exiftool_path()

    def _get_exiftool_path(self):
        """
        Determines the path to exiftool.exe based on how the app is running.
        """
        # 1. Determine the base directory
        if getattr(sys, 'frozen', False):
            # If running as a compiled EXE, the base is where the EXE lives
            base_path = os.path.dirname(sys.executable)
        else:
            # If running as a script, the base is the project root
            # (Assuming this file is in /analyzers/, we go up one level)
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 2. Look for exiftool.exe in that base directory
        exif_exe = os.path.join(base_path, "exiftool.exe")
        
        # 3. Fallback: If not found, check system PATH (just in case)
        if not os.path.exists(exif_exe):
            return "exiftool" # Hope it's in the Windows PATH variable
            
        return exif_exe

    def run(self):
        """Runs ExifTool and prints the output to stdout (captured by OfficeRecon)."""
        if not os.path.exists(self.filepath):
            return

        try:
            # -g: Group by tag family (File, EXIF, XMP)
            # -json: Output as JSON (easier to parse if we wanted to, but we just dump text here)
            # For human readable report in the GUI, we stick to standard text output, or -S -G
            
            cmd = [self.exif_path, "-G", "-S", self.filepath]
            
            # Run hidden window to avoid popping up black boxes
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if process.stdout:
                print("\n--- ExifTool Raw Metadata Analysis ---")
                print(f"ExifTool Version : {self._get_version()}")
                print(process.stdout)
                
        except Exception as e:
            print(f"[!] ExifTool Error: {e}")
            print("    (Ensure exiftool.exe is in the same folder as OfficeRecon.exe)")

    def _get_version(self):
        try:
            cmd = [self.exif_path, "-ver"]
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            res = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, startupinfo=startupinfo)
            return res.stdout.strip()
        except:
            return "Unknown"