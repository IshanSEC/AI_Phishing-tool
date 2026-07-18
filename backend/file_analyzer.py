import os
import hashlib
import re
import zipfile
import struct
from datetime import datetime

# Critical extensions list
DANGEROUS_EXTENSIONS = {
    ".exe": "Executable Application",
    ".scr": "Screen Saver (often executable malware)",
    ".bat": "Batch Command Script",
    ".vbs": "VBScript Program",
    ".js": "JavaScript File (script executor)",
    ".sys": "System Driver file",
    ".dll": "Dynamic Link Library",
    ".com": "MS-DOS Application",
    ".msi": "Windows Installer Package",
    ".lnk": "Shortcut Link (can execute hidden cmd)",
    ".cmd": "Windows Command Script",
    ".pif": "Program Information File",
    ".sh": "Linux Shell Script",
    ".py": "Python Script File"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm"}
DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv"}
MOBILE_EXTENSIONS = {".apk": "Android Package", ".ipa": "iOS Application"}

class FileAnalyzer:
    @staticmethod
    def calculate_hashes(file_bytes):
        """Calculates MD5 and SHA-256 hashes of file bytes."""
        md5 = hashlib.md5(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        return md5, sha256

    @staticmethod
    def detect_rtlo(filename):
        """Detects Right-to-Left Override character (\u202e) used to spoof extensions."""
        return "\u202e" in filename

    @staticmethod
    def check_magic_bytes(file_bytes, ext):
        """Validates extension against file headers (magic bytes) to catch extension mismatches."""
        ext_lower = ext.lower()
        header = file_bytes[:10]
        
        # Define common magic signatures
        # Format: (signature_bytes, offset, description)
        signatures = {
            "MZ": (b"MZ", 0, "PE Executable (.exe, .dll, .sys, .scr)"),
            "PK": (b"PK\x03\x04", 0, "ZIP/Office Archive (.zip, .apk, .docx, .xlsx, .pptx)"),
            "PDF": (b"%PDF", 0, "PDF Document"),
            "ELF": (b"\x7fELF", 0, "Linux Executable (.elf)"),
            "RAR": (b"Rar!\x1a\x07", 0, "RAR Archive"),
            "PNG": (b"\x89PNG\r\n\x1a\n", 0, "PNG Image"),
            "JPG": (b"\xff\xd8\xff", 0, "JPEG Image"),
            "GIF": (b"GIF8", 0, "GIF Image")
        }
        
        detected_type = "Unknown / Binary Text"
        for sig_name, (sig_bytes, offset, desc) in signatures.items():
            if len(header) >= len(sig_bytes) + offset:
                if header[offset:offset+len(sig_bytes)] == sig_bytes:
                    detected_type = desc
                    break
                    
        # Check mismatches
        mismatch = False
        warning = ""
        
        if detected_type.startswith("PE Executable") and ext_lower not in [".exe", ".dll", ".sys", ".scr", ".com", ".msi"]:
            mismatch = True
            warning = f"File claims to be '{ext}' but is actually a Windows Executable (MZ header)!"
        elif detected_type.startswith("PDF Document") and ext_lower != ".pdf":
            mismatch = True
            warning = f"File claims to be '{ext}' but is actually a PDF document!"
        elif detected_type.startswith("ZIP/Office Archive") and ext_lower not in [".zip", ".apk", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm"]:
            mismatch = True
            warning = f"File claims to be '{ext}' but contains a compressed ZIP structure (PK header)!"
            
        return detected_type, mismatch, warning

    @staticmethod
    def analyze_pdf(file_bytes):
        """Statically inspects PDF for active script components."""
        indicators = []
        text_content = file_bytes.lower()
        
        triggers = {
            b"/javascript": "Embedded JavaScript execution block (/JavaScript)",
            b"/js": "Shorthand JavaScript indicator (/JS)",
            b"/openaction": "Automatic action execution on file open (/OpenAction)",
            b"/launch": "Launches an external application or process (/Launch)",
            b"/embeddedfile": "Embedded file cargo payload (/EmbeddedFile)",
            b"/acroform": "Active forms engine input block (/AcroForm)",
            b"/aa": "Additional action trigger elements (/AA)"
        }
        
        for trig, desc in triggers.items():
            count = text_content.count(trig)
            if count > 0:
                indicators.append({
                    "indicator": desc,
                    "severity": "High" if trig in [b"/javascript", b"/js", b"/openaction", b"/launch"] else "Medium",
                    "details": f"Found {count} instance(s) of '{trig.decode('utf-8')}' in raw structure.",
                    "explanation": "Active components inside documents are frequently used to trigger exploits or download external payloads when opened."
                })
                
        return indicators

    @staticmethod
    def analyze_docx(filepath):
        """Inspects DOCX/Office file contents by opening zip relationships and searching for macro elements."""
        indicators = []
        try:
            if not zipfile.is_zipfile(filepath):
                return indicators
                
            with zipfile.ZipFile(filepath, 'r') as z:
                namelist = z.namelist()
                
                # Check for macro file
                if "word/vbaProject.bin" in namelist or "xl/vbaProject.bin" in namelist or any("vbaProject.bin" in name for name in namelist):
                    indicators.append({
                        "indicator": "VBA Macros Detected (vbaProject.bin)",
                        "severity": "High",
                        "details": "Contains VBA binary project stream inside office archive package.",
                        "explanation": "Office macros are powerful scripting environments used by adversaries to download and run trojans."
                    })
                    
                # Check relationship target files for external templates (CVE-2022-30190 Follina etc.)
                rel_names = [name for name in namelist if name.endswith(".rels")]
                for rel_name in rel_names:
                    try:
                        content = z.read(rel_name).decode('utf-8', errors='ignore')
                        # Scan for external Target resources (http/https links in relation files)
                        matches = re.findall(r'Target="([^"]+)"', content)
                        for match in matches:
                            if match.startswith("http") and "template" in rel_name.lower():
                                indicators.append({
                                    "indicator": "External Document Template Reference",
                                    "severity": "Medium",
                                    "details": f"Relationship connects to external URL: {match}",
                                    "explanation": "Injecting external template references can trigger remote code execution or credential stealing protocols."
                                })
                    except Exception:
                        pass
        except Exception as e:
            print(f">>> Error analyzing Office zip format: {e}")
            
        return indicators

    @staticmethod
    def analyze_zip_apk(filepath, is_apk=False):
        """Inspects ZIP or APK file list for suspicious elements."""
        indicators = []
        try:
            if not zipfile.is_zipfile(filepath):
                return indicators
                
            with zipfile.ZipFile(filepath, 'r') as z:
                namelist = z.namelist()
                
                exec_in_zip = []
                double_ext_in_zip = []
                
                for name in namelist:
                    base = os.path.basename(name)
                    if not base:
                        continue
                    _, ext = os.path.splitext(base.lower())
                    
                    # Detect executables inside zip
                    if ext in DANGEROUS_EXTENSIONS:
                        exec_in_zip.append(name)
                        
                    # Detect double extensions inside zip
                    if len(re.findall(r"\.[a-zA-Z0-9]{2,4}\.[a-zA-Z0-9]{2,4}$", base)) > 0:
                        double_ext_in_zip.append(name)
                        
                if exec_in_zip:
                    indicators.append({
                        "indicator": f"Executable file in compressed archive ({len(exec_in_zip)} file(s))",
                        "severity": "High",
                        "details": f"Found scripts/executables: {', '.join(exec_in_zip[:3])}" + ("..." if len(exec_in_zip) > 3 else ""),
                        "explanation": "Attackers compress scripts and binary executables inside zip folders to bypass email filter scanners."
                    })
                    
                if double_ext_in_zip:
                    indicators.append({
                        "indicator": "Double Extension File in ZIP",
                        "severity": "High",
                        "details": f"Double extension names: {', '.join(double_ext_in_zip[:3])}",
                        "explanation": "Double extensions masquerade dangerous files as harmless pictures or documents."
                    })
                    
                if is_apk:
                    # Validate APK signatures
                    manifest = "AndroidManifest.xml"
                    classes = "classes.dex"
                    if manifest in namelist and classes in namelist:
                        indicators.append({
                            "indicator": "Android Application Binary Structure Verified",
                            "severity": "Low",
                            "details": "Structure contains standard classes.dex compiler code and AndroidManifest configuration.",
                            "explanation": "Static validation confirms file is a deployable Android executable wrapper package."
                        })
                    else:
                        indicators.append({
                            "indicator": "Corrupted or Malformed APK Structure",
                            "severity": "Medium",
                            "details": f"Missing core resources. manifest present: {manifest in namelist}, classes present: {classes in namelist}",
                            "explanation": "Android applications require dex code blocks and manifest files to execute on device platforms."
                        })
        except Exception as e:
            print(f">>> Error parsing ZIP directory index: {e}")
            
        return indicators

    @staticmethod
    def analyze_pe(file_bytes):
        """Parses basic PE (Portable Executable) headers from EXE/DLL file bytes to verify structures."""
        indicators = []
        metadata = {}
        try:
            # 1. DOS Header: check MZ signature
            if len(file_bytes) < 64:
                return indicators, metadata
                
            mz_sig = file_bytes[:2]
            if mz_sig != b"MZ":
                return indicators, metadata
                
            # Offset to PE Header
            pe_offset = struct.unpack("<I", file_bytes[60:64])[0]
            if len(file_bytes) < pe_offset + 24:
                return indicators, metadata
                
            # 2. PE Header signature
            pe_sig = file_bytes[pe_offset:pe_offset+4]
            if pe_sig != b"PE\x00\x00":
                return indicators, metadata
                
            # COFF Header (20 bytes after PE signature)
            coff_header = file_bytes[pe_offset+4 : pe_offset+24]
            machine, num_sections, timedate, sym_table, num_sym, opt_header_size, characteristics = struct.unpack(
                "<HHIIIHH", coff_header
            )
            
            metadata["machine"] = "x64" if machine == 0x8664 else "x86 (32-bit)" if machine == 0x14c else f"Unknown ({hex(machine)})"
            metadata["num_sections"] = num_sections
            try:
                metadata["compile_time"] = datetime.utcfromtimestamp(timedate).isoformat()
            except Exception:
                metadata["compile_time"] = "Invalid timestamp"
                
            # Parse sections (Section Headers follow COFF + Optional Header size)
            section_start = pe_offset + 24 + opt_header_size
            sections_list = []
            
            has_packed_sections = False
            packed_section_names = []
            
            for i in range(num_sections):
                offset = section_start + (i * 40)
                if len(file_bytes) < offset + 40:
                    break
                sect_bytes = file_bytes[offset:offset+40]
                sect_name = sect_bytes[:8].decode('utf-8', errors='ignore').strip('\x00')
                
                # Check for UPX packers or known encryption section headers
                if sect_name.upper() in ["UPX0", "UPX1", "UPX2", "UPX3", ".UPX0", ".UPX1", "ASPACK", "PECOMP"]:
                    has_packed_sections = True
                    packed_section_names.append(sect_name)
                    
                # Calculate section raw entropy (check compression/encryption indicator)
                # If section size > 0, inspect entropy
                sections_list.append(sect_name)
                
            metadata["sections"] = sections_list
            
            if has_packed_sections:
                indicators.append({
                    "indicator": f"PE Compressor / Packer Signature Detected ({', '.join(packed_section_names)})",
                    "severity": "High",
                    "details": f"Section table contains packer markers: {packed_section_names}",
                    "explanation": "Packers compress executable sections to disguise binary payloads, standard behavior for trojan installers."
                })
                
            if num_sections < 2 or num_sections > 10:
                indicators.append({
                    "indicator": f"Abnormal PE Section Count ({num_sections} sections)",
                    "severity": "Medium",
                    "details": f"Standard executables contain 3-5 sections (e.g. .text, .data, .rsrc). Got {num_sections}.",
                    "explanation": "Extremely low or high section counts can indicate custom loaders or compiler exploits."
                })
        except Exception as e:
            print(f">>> Failed parsing PE executable sections ({e}). Using binary analysis fallback.")
            
        return indicators, metadata

    def analyze(self, filepath, filename=None):
        """Runs full static analysis on file."""
        if not filename:
            filename = os.path.basename(filepath)
            
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
            
        file_size = len(file_bytes)
        _, ext = os.path.splitext(filename.lower())
        
        # 1. Hashes
        md5, sha256 = self.calculate_hashes(file_bytes)
        
        # 2. RTLO & Double Extension checks
        rtlo_detected = self.detect_rtlo(filename)
        
        double_ext = False
        double_ext_warning = ""
        # Match pattern of word followed by two extensions e.g. text.docx.exe
        name_parts = filename.lower().split('.')
        if len(name_parts) >= 3:
            # Check if second to last part is a common file extension
            penultimate_ext = "." + name_parts[-2]
            if penultimate_ext in DOCUMENT_EXTENSIONS or penultimate_ext in ARCHIVE_EXTENSIONS:
                double_ext = True
                double_ext_warning = f"File has suspicious nested extensions: '{penultimate_ext}{ext}'"
                
        # 3. Magic bytes
        detected_type, extension_mismatch, mismatch_warning = self.check_magic_bytes(file_bytes, ext)
        
        # 4. Content analysis
        xai_indicators = []
        metadata = {}
        
        # Format parsing
        if ext == ".pdf":
            xai_indicators.extend(self.analyze_pdf(file_bytes))
        elif ext in OFFICE_EXTENSIONS:
            xai_indicators.extend(self.analyze_docx(filepath))
        elif ext == ".zip":
            xai_indicators.extend(self.analyze_zip_apk(filepath, is_apk=False))
        elif ext == ".apk":
            xai_indicators.extend(self.analyze_zip_apk(filepath, is_apk=True))
        elif ext in [".exe", ".dll", ".sys", ".scr"]:
            pe_inds, pe_meta = self.analyze_pe(file_bytes)
            xai_indicators.extend(pe_inds)
            metadata.update(pe_meta)
            
        # 5. Risk score calculations
        risk_score = 0
        
        # Base extension risk
        if ext in DANGEROUS_EXTENSIONS:
            risk_score += 30
        elif ext in ARCHIVE_EXTENSIONS or ext in MOBILE_EXTENSIONS:
            risk_score += 15
            
        # Modifiers
        if extension_mismatch:
            risk_score += 45
        if double_ext:
            risk_score += 35
        if rtlo_detected:
            risk_score += 40
            
        # XAI indicator weight additions
        for ind in xai_indicators:
            if ind["severity"] == "High":
                risk_score += 25
            elif ind["severity"] == "Medium":
                risk_score += 15
            elif ind["severity"] == "Low":
                risk_score += 5
                
        risk_score = max(0, min(100, risk_score))
        
        # Classify threat
        if risk_score >= 75:
            prediction = "Malicious"
            threat_level = "High"
        elif risk_score >= 30:
            prediction = "Suspicious"
            threat_level = "Medium"
        else:
            prediction = "Safe"
            threat_level = "Low"
            
        # Basic metadata collection
        file_metadata = {
            "file_name": filename,
            "file_size": file_size,
            "md5": md5,
            "sha256": sha256,
            "detected_type": detected_type,
            "extension_mismatch": extension_mismatch,
            "mismatch_warning": mismatch_warning,
            "rtlo_detected": rtlo_detected,
            "double_ext": double_ext,
            "double_ext_warning": double_ext_warning,
            "compilation_time": metadata.get("compile_time", "N/A"),
            "architecture": metadata.get("machine", "N/A"),
            "num_sections": metadata.get("num_sections", "N/A"),
            "sections": metadata.get("sections", []),
            "analysis_time": datetime.utcnow().isoformat()
        }
        
        return {
            "prediction": prediction,
            "threat_level": threat_level,
            "risk_score": risk_score,
            "metadata": file_metadata,
            "xai_indicators": xai_indicators
        }
