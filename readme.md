# CVE-2025-54313 IOC Scanner

A PowerShell-based scanner for detecting Indicators of Compromise (IOCs) related to the eslint-config-prettier supply chain attack (CVE-2025-54313).

## 🚨 About CVE-2025-54313

On July 18, 2025, several popular npm packages were compromised through a phishing attack. The attacker gained access to the maintainer's npm tokens and published malicious versions containing Windows-specific malware.

### Affected Packages and Versions

| Package | Compromised Versions |
|---------|---------------------|
| eslint-config-prettier | 8.10.1, 9.1.1, 10.1.6, 10.1.7 |
| eslint-plugin-prettier | 4.2.2, 4.2.3 |
| synckit | 0.11.9 |
| @pkgr/core | 0.2.8 |
| napi-postinstall | 0.3.1 |
| is | 3.3.1, 5.0.0 |

## 🔍 What Does This Scanner Do?

The scanner searches Windows systems for known IOCs of the CVE-2025-54313 supply chain attack:

- ✅ **Package Scanning**: Identifies compromised npm package versions
- ✅ **File Analysis**: Searches for malicious install.js and DLL files
- ✅ **Hash Verification**: Compares files with known malware signatures
- ✅ **Timeline Analysis**: Identifies suspicious activities after July 18, 2025
- ✅ **Token Security**: Finds .npmrc files for token verification
- ✅ **Automatic Cleanup**: Option to remove compromised packages

## 📋 Prerequisites

- Windows PowerShell 5.1 or higher
- Administrator privileges (recommended for full system scan)
- .NET Framework 4.5 or higher

## 🚀 Installation

1. Download the script:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/[your-repo]/CVE-2025-54313-Scanner.ps1" -OutFile "CVE-2025-54313-Scanner.ps1"
```

2. Unblock the script:
```powershell
Unblock-File -Path ".\CVE-2025-54313-Scanner.ps1"
```

3. Set execution policy (if needed):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 💻 Usage

### Quick Scan (current directory)
```powershell
.\CVE-2025-54313-Scanner.ps1 -QuickScan
```

### Full System Scan
```powershell
.\CVE-2025-54313-Scanner.ps1
```

### Scan Specific Directory
```powershell
.\CVE-2025-54313-Scanner.ps1 -ScanPath "D:\Projects"
```

### With Detailed Output
```powershell
.\CVE-2025-54313-Scanner.ps1 -DetailedOutput
```

### With Custom Report Path
```powershell
.\CVE-2025-54313-Scanner.ps1 -ReportPath "C:\Security\CVE-Report.txt"
```

## 📊 What Gets Scanned?

### Known IOCs

1. **Malware Files**
   - `node-gyp.dll` (SHA256: c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441)
   - `install.js` with suspicious code patterns
   - Additional DLLs: `loader.dll`, `version.dll`, `umpdc.dll`, `profapi.dll`

2. **Code Patterns**
   - Function `logDiskSpace()`
   - Platform check for Windows
   - Obfuscated strings
   - rundll32 calls

3. **Network Indicators**
   - C2 communication patterns
   - XOR key "FuckOff"

4. **Behavioral IOCs**
   - Post-install scripts in package.json
   - Temporary files in %TEMP% directory
   - .npmrc files (for token exfiltration)

## 📄 Report Output

The scanner generates a detailed report containing:
- Summary of all findings
- List of compromised packages
- Suspicious files with hashes
- Timeline of events
- Recommendations for countermeasures

## 🛡️ Recommended Actions After Positive Detection

1. **Immediate Actions**
   - Remove all compromised package versions
   - Delete entire `node_modules` folder
   - Run `npm install` with safe versions

2. **Security Measures**
   - Rotate all npm access tokens
   - Enable 2FA for npm accounts
   - Check .npmrc files for unknown tokens

3. **System Cleanup**
   - Run full antivirus scan
   - Search for Scavenger malware
   - Check network connections

4. **Install Safe Versions**
   ```json
   {
     "eslint-config-prettier": ">=8.10.2 || >=9.1.2 || >=10.1.8",
     "eslint-plugin-prettier": "latest"
   }
   ```

## ⚠️ Important Notes

- **Windows Only**: The malware only affects Windows systems
- **False Positives**: Not all detected DLLs are necessarily malicious
- **Backup**: Create a backup before cleanup
- **Updates**: Keep the script updated as new IOCs may be discovered

## 🤝 Contributing

Found new IOCs or have suggestions for improvement?
1. Fork this repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📚 Further Reading

- [Endor Labs Blog Post](https://www.endorlabs.com/learn/cve-2025-54313-eslint-config-prettier-compromise----high-severity-but-windows-only)
- [GitHub Issue #339](https://github.com/prettier/eslint-config-prettier/issues/339)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2025-54313)
- [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-JS-ESLINTCONFIGPRETTIER-10873299)

## ⚖️ Disclaimer

This tool is provided "as-is" without any warranty. The authors assume no liability for damages that may result from using this tool. Use at your own risk and test in a safe environment first.

---

**Last Updated**: 27 July 2025  
**Version**: 1.0  


🛡️ **Stay Safe!**
