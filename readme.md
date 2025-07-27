# CVE-2025-54313 IOC Scanner

Cross-platform scanners for detecting Indicators of Compromise (IOCs) related to the eslint-config-prettier supply chain attack (CVE-2025-54313).

## 🚨 About CVE-2025-54313

On July 18, 2025, several popular npm packages were compromised through a phishing attack. The attacker gained access to the maintainer's npm tokens and published malicious versions containing platform-specific malware.

### Affected Packages and Versions

| Package | Compromised Versions |
|---------|---------------------|
| eslint-config-prettier | 8.10.1, 9.1.1, 10.1.6, 10.1.7 |
| eslint-plugin-prettier | 4.2.2, 4.2.3 |
| synckit | 0.11.9 |
| @pkgr/core | 0.2.8 |
| napi-postinstall | 0.3.1 |
| is | 3.3.1, 5.0.0 |

## 🔍 What Do These Scanners Do?

Both scanners search systems for known IOCs of the CVE-2025-54313 supply chain attack:

- ✅ **Package Scanning**: Identifies compromised npm package versions
- ✅ **File Analysis**: Searches for malicious install.js and binary files
- ✅ **Hash Verification**: Compares files with known malware signatures
- ✅ **Timeline Analysis**: Identifies suspicious activities after July 18, 2025
- ✅ **Token Security**: Finds .npmrc files for token verification
- ✅ **Automatic Cleanup**: Option to remove compromised packages

## 📋 Prerequisites

### Windows (PowerShell Version)
- Windows PowerShell 5.1 or higher
- Administrator privileges (recommended for full system scan)
- .NET Framework 4.5 or higher

### Linux/Unix (Bash Version)
- Bash 4.0 or higher
- Standard Unix tools: `find`, `grep`, `sha256sum`, `stat`
- `jq` (recommended but not required - fallback parsing included)
- Root privileges recommended for full system scan

## 🚀 Installation

### Windows Version

1. Download the PowerShell script:
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

### Linux Version

1. Download the bash script:
```bash
curl -O https://raw.githubusercontent.com/[your-repo]/CVE-2025-54313-Scanner.sh
```

2. Make it executable:
```bash
chmod +x CVE-2025-54313-Scanner.sh
```

3. Install optional dependencies for better performance:
```bash
# Debian/Ubuntu
sudo apt-get install jq

# RHEL/CentOS/Fedora
sudo yum install jq

# macOS
brew install jq
```

## 💻 Usage

### Windows (PowerShell)

#### Quick Scan (current directory)
```powershell
.\CVE-2025-54313-Scanner.ps1 -QuickScan
```

#### Full System Scan
```powershell
.\CVE-2025-54313-Scanner.ps1
```

#### Scan Specific Directory
```powershell
.\CVE-2025-54313-Scanner.ps1 -ScanPath "D:\Projects"
```

#### With Detailed Output
```powershell
.\CVE-2025-54313-Scanner.ps1 -DetailedOutput
```

#### With Custom Report Path
```powershell
.\CVE-2025-54313-Scanner.ps1 -ReportPath "C:\Security\CVE-Report.txt"
```

### Linux/Unix (Bash)

#### Quick Scan (current directory)
```bash
./CVE-2025-54313-Scanner.sh -q
```

#### Full System Scan
```bash
sudo ./CVE-2025-54313-Scanner.sh
```

#### Scan Specific Directory
```bash
./CVE-2025-54313-Scanner.sh --path /home/user/projects
```

#### With Detailed Output
```bash
./CVE-2025-54313-Scanner.sh -q -d
```

#### With Custom Report Path
```bash
./CVE-2025-54313-Scanner.sh --report /tmp/cve-report.txt
```

#### Show Help
```bash
./CVE-2025-54313-Scanner.sh --help
```

## 📊 What Gets Scanned?

### Known IOCs

1. **Malware Files**
   - **Windows**: `node-gyp.dll`, `loader.dll`, `version.dll`, `umpdc.dll`, `profapi.dll`
   - **Linux**: `node-gyp.so`, `loader.so`, `version.so`, `libumpdc.so`, `libprofapi.so`
   - `install.js` files with suspicious code patterns
   - Known SHA256 hashes:
     - `c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441` (node-gyp.dll/1st stage)
     - `5bed39728e404838ecd679df65048abcb443f8c7a9484702a2ded60104b8c4a9` (2nd stage Scavenger)
     - `32d0dbdfef0e5520ba96a2673244267e204b94a49716ea13bf635fa9af6f66bf` (install.js)

2. **Code Patterns**
   - Function `logDiskSpace()`
   - Platform checks for Windows/Linux
   - Child process spawning
   - Obfuscated command execution
   - rundll32/exec calls

3. **Network Indicators**
   - C2 URLs: `firebase.su`, `dieorsuffer.com`, `smartscreen-api.com`
   - XOR key "FuckOff"
   - Communication patterns

4. **Behavioral IOCs**
   - Post-install scripts in package.json
   - Temporary files in system temp directories
   - .npmrc files (for token exfiltration)

### Platform-Specific Locations

#### Windows
- **Temp Directory**: `%TEMP%`
- **NPM Config**: `%USERPROFILE%\.npmrc`, `%APPDATA%\npm\.npmrc`
- **Scan Path Default**: `C:\`

#### Linux
- **Temp Directories**: `/tmp`, `/var/tmp`, `$TMPDIR`
- **NPM Config**: `~/.npmrc`, `~/.config/npm/.npmrc`, `/usr/local/etc/npmrc`, `/etc/npmrc`
- **Scan Path Default**: `/`

## 📄 Report Output

Both scanners generate detailed reports containing:
- Summary of all findings
- List of compromised packages with paths and timestamps
- Suspicious files with SHA256 hashes
- Timeline of events after July 18, 2025
- Recommendations for countermeasures
- Safe package versions

## 🛡️ Recommended Actions After Positive Detection

1. **Immediate Actions**
   - Remove all compromised package versions
   - Delete entire `node_modules` folder
   - Run `npm install` with safe versions

2. **Security Measures**
   - Rotate all npm access tokens
   - Enable 2FA for npm accounts
   - Check .npmrc files for unknown tokens
   - Review system logs for unauthorized access

3. **System Cleanup**
   - Run full antivirus/malware scan
   - Search for Scavenger malware or other trojans
   - Check network connections and firewall logs
   - Verify system integrity

4. **Install Safe Versions**
   ```json
   {
     "eslint-config-prettier": ">=8.10.2 || >=9.1.2 || >=10.1.8",
     "eslint-plugin-prettier": "latest"
   }
   ```

## 🔧 Technical Differences Between Versions

| Feature | Windows (PowerShell) | Linux (Bash) |
|---------|---------------------|--------------|
| **Binary Files** | .dll files | .so files |
| **JSON Parsing** | ConvertFrom-Json | jq + fallback grep/sed |
| **File Hashing** | Get-FileHash | sha256sum |
| **Colors** | Write-Host -ForegroundColor | ANSI escape codes |
| **Privileges** | Run as Administrator | sudo for full scan |
| **Dependencies** | Built-in PowerShell | Standard Unix tools |

## ⚠️ Important Notes

- **Cross-Platform**: While the original malware targeted Windows, the Linux scanner helps detect compromised packages on development servers
- **Performance**: `jq` installation recommended on Linux for faster JSON parsing
- **Permissions**: Root/Administrator privileges recommended for complete system scans
- **False Positives**: Not all detected files are necessarily malicious - review findings carefully
- **Backup**: Create system backups before running cleanup operations
- **Updates**: Keep scripts updated as new IOCs may be discovered

## 🤝 Contributing

Found new IOCs or have suggestions for improvement?
1. Fork this repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

### Reporting New IOCs
Please include:
- File hashes (SHA256)
- File paths and names
- Suspicious code patterns
- Platform information (Windows/Linux)

## 📚 Further Reading

- [Endor Labs Blog Post](https://www.endorlabs.com/learn/cve-2025-54313-eslint-config-prettier-compromise----high-severity-but-windows-only)
- [GitHub Issue #339](https://github.com/prettier/eslint-config-prettier/issues/339)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2025-54313)
- [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-JS-ESLINTCONFIGPRETTIER-10873299)

## 🔍 Quick Command Reference

### Windows PowerShell
```powershell
# Quick scan current directory
.\CVE-2025-54313-Scanner.ps1 -QuickScan

# Full system scan with detailed output
.\CVE-2025-54313-Scanner.ps1 -DetailedOutput

# Scan specific path
.\CVE-2025-54313-Scanner.ps1 -ScanPath "C:\Users\John\Projects"
```

### Linux Bash
```bash
# Quick scan current directory
./CVE-2025-54313-Scanner.sh -q

# Full system scan with detailed output  
sudo ./CVE-2025-54313-Scanner.sh -d

# Scan specific path
./CVE-2025-54313-Scanner.sh -p /home/john/projects

# Show all options
./CVE-2025-54313-Scanner.sh --help
```

## ⚖️ Disclaimer

These tools are provided "as-is" without any warranty. The authors assume no liability for damages that may result from using these tools. Use at your own risk and test in a safe environment first.

---

**Last Updated**: 27 July 2025  
**Version**: 1.0  
**Platforms**: Windows (PowerShell), Linux/Unix (Bash)

🛡️ **Stay Safe Across All Platforms!**