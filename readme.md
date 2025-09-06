# 🔍 Agentic Digital Forensics Toolkit

**Professional-grade Linux digital forensics made accessible through intelligent automation**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Bash](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)

## 🎯 **Why Agentic Forensics?**

Digital forensics investigations require deep expertise, methodical approaches, and extensive knowledge of Linux systems. **Agentic Forensics** democratizes this expertise by providing:

### **🚀 For Novice Users:**
- **Guided Investigation**: AI agent walks you through professional forensics methodology
- **No Prior Experience Required**: Automated evidence collection with expert explanations
- **Learn While Investigating**: Educational prompts explain why each step matters
- **Mistake Prevention**: Built-in safety controls prevent evidence contamination
- **Professional Results**: Generate court-ready forensics reports automatically

### **⚡ For Experienced Users:**
- **Rapid Response**: Complete forensics collection in minutes, not hours
- **Comprehensive Coverage**: 15-phase investigation covering all critical areas
- **Automated Documentation**: Chain of custody and evidence manifests generated automatically
- **Consistent Methodology**: Standardized approach ensures nothing is missed
- **Scalable Analysis**: Handle multiple incidents with repeatable processes

---

## 📁 **Project Components**

### **1. 🤖 Intelligent Forensics Agent** (`forensics_agent/`)
An AI-powered investigation assistant that provides expert guidance and automated analysis.

**Key Features:**
- **Professional Methodology**: 10-phase investigation protocol
- **50+ Forensics Commands**: Comprehensive tool support with safety validation
- **Intelligent Analysis**: Automated suspicious file detection, network mapping, and process analysis
- **Educational Guidance**: Explains investigation steps and findings in plain language
- **Safe Execution**: Read-only operations with comprehensive command validation

### **2. 🔧 Automated Collection Script** (`forensics_automation.sh`)
A comprehensive bash script that performs complete forensics evidence collection.

**Capabilities:**
- **Full System Analysis**: 13 investigation phases covering all critical areas
- **Cross-Platform Support**: Debian, RHEL, Fedora, and Arch Linux compatibility
- **Automated Dependencies**: Installs required forensics tools automatically
- **Evidence Packaging**: Creates tamper-evident evidence archives with chain of custody
- **Progress Tracking**: Detailed logging and phase-by-phase status updates

### **3. 📖 Forensics Methodology Guide** (`forensics_process.md`)
Professional-grade documentation covering complete Linux forensics procedures.

**Contents:**
- **15 Investigation Phases**: From initial assessment to advanced analysis
- **Command References**: Complete toolkit with syntax and usage examples
- **Best Practices**: Industry-standard procedures and legal considerations
- **Tool Recommendations**: Curated list of professional forensics software
- **Quick Reference**: Emergency response procedures and one-liner commands

---

## 🎓 **Why This Approach Works for Novices**

### **Traditional Forensics Challenges:**
❌ **Steep Learning Curve**: Years of training required for competency  
❌ **Complex Toolchains**: Dozens of specialized tools with different syntaxes  
❌ **Easy to Miss Evidence**: Critical artifacts overlooked without experience  
❌ **Evidence Contamination**: Risk of modifying the system under investigation  
❌ **Inconsistent Methods**: Ad-hoc approaches lead to incomplete investigations  

### **Agentic Forensics Solutions:**
✅ **Guided Learning**: AI explains each step and its forensics significance  
✅ **Automated Expertise**: Professional methodology applied automatically  
✅ **Comprehensive Coverage**: Nothing missed with systematic 15-phase approach  
✅ **Built-in Safety**: Read-only operations prevent evidence contamination  
✅ **Consistent Results**: Standardized procedures ensure repeatable investigations  

---

## 🚀 **Quick Start Guide**

### **Option 1: AI-Guided Investigation (Recommended for Beginners)**

```python
from forensics_agent import root_agent

# Start an interactive forensics investigation
agent = root_agent
response = agent.chat("I need to investigate a potential security breach on this Linux system. Please guide me through a comprehensive forensics analysis.")

# The agent will:
# 1. Explain the investigation methodology
# 2. Guide you through each phase step-by-step
# 3. Execute commands safely and explain findings
# 4. Generate a professional forensics report
```

### **Option 2: Automated Full Investigation**

```bash
# Run complete automated forensics collection
sudo ./forensics_automation.sh /mnt/evidence

# This will:
# - Install required forensics tools
# - Collect evidence across 13 phases
# - Generate comprehensive reports
# - Create tamper-evident evidence packages
```

### **Option 3: Manual Investigation with Guide**

```bash
# Follow the step-by-step methodology
cat forensics_process.md

# Execute commands from each phase as needed
# Perfect for learning and custom investigations
```

---

## 🔍 **Investigation Phases Covered**

| Phase | Focus Area | Automated | AI-Guided |
|-------|------------|-----------|-----------|
| **1** | Initial System Assessment | ✅ | ✅ |
| **2** | Memory Analysis (Critical) | ✅ | ✅ |
| **3** | Process Analysis | ✅ | ✅ |
| **4** | Network Analysis | ✅ | ✅ |
| **5** | File System Analysis | ✅ | ✅ |
| **6** | Hash Computation & Integrity | ✅ | ✅ |
| **7** | YARA Malware Scanning | ✅ | ✅ |
| **8** | Log Analysis | ✅ | ✅ |
| **9** | User & Account Analysis | ✅ | ✅ |
| **10** | System Configuration Analysis | ✅ | ✅ |
| **11** | Artifact Collection | ✅ | ✅ |
| **12** | String Analysis | ✅ | ✅ |
| **13** | Timeline Analysis | ✅ | ✅ |
| **14** | Documentation & Reporting | ✅ | ✅ |
| **15** | Advanced Analysis | ✅ | ✅ |

---

## 💡 **Use Cases**

### **🏢 Enterprise Security Teams**
- **Incident Response**: Rapid evidence collection during active breaches
- **Compliance Audits**: Standardized forensics procedures for regulatory requirements
- **Training Programs**: Educational tool for developing forensics skills
- **Documentation**: Automated report generation for management and legal teams

### **🎓 Educational Institutions**
- **Cybersecurity Courses**: Hands-on forensics training with safety guardrails
- **Research Projects**: Consistent methodology for academic investigations
- **Skill Development**: Learn professional forensics through guided practice
- **Certification Prep**: Practice for GCFA, CCE, and other forensics certifications

### **🚨 First Responders**
- **Law Enforcement**: Rapid evidence collection with proper chain of custody
- **Incident Response Teams**: Standardized procedures for consistent results
- **Forensics Consultants**: Professional toolkit for client investigations
- **Legal Professionals**: Court-ready evidence collection and documentation

### **🔒 Individual Practitioners**
- **Personal Security**: Investigate potential compromises on personal systems
- **Skill Building**: Learn forensics methodology through practical application
- **Home Labs**: Practice forensics techniques in safe environments
- **Career Development**: Build professional forensics capabilities

---

## 🛠 **Technical Requirements**

### **System Requirements:**
- **Operating System**: Linux (Ubuntu/Debian, RHEL/CentOS/Fedora, Arch)
- **Privileges**: Root access required for complete forensics collection
- **Storage**: Minimum 10GB free space for evidence collection
- **Memory**: 4GB RAM recommended for large investigations

### **Dependencies:**
**Automatically Installed:**
- YARA malware scanning engine
- Network analysis tools (ss, netstat, lsof)
- File system utilities (find, strings, hexdump)
- Hash computation tools (sha256sum, md5sum)
- Process analysis tools (ps, pstree, lsof)

**Optional Enhancements:**
- Volatility Framework (advanced memory analysis)
- The Sleuth Kit (file system forensics)
- Autopsy (GUI forensics platform)
- Wireshark (network packet analysis)

---

## 📊 **Sample Investigation Output**

```
=== LINUX FORENSIC INVESTIGATION SUMMARY ===
Generated by: Linux Forensics Investigation Script v2.0
Investigation Date: 2025-09-06 04:47:17 UTC
Case ID: case-ip-172-31-27-195-20250906T044653Z
System: ip-172-31-27-195
OS: Ubuntu 24.04.3 LTS
Kernel: Linux 6.14.0-1011-aws
Architecture: x86-64

=== KEY FINDINGS ===
Active processes: 156
Network listeners: 8
Active connections: 12
Files modified in last 7 days: 1,247
SUID/SGID files found: 89
YARA rule matches: 0
Failed login attempts: 0

=== EVIDENCE SUMMARY ===
Total files collected: 2,847
Total evidence size: 145MB
Evidence package: case-ip-172-31-27-195-20250906T044653Z.tar.gz
Package hash: sha256:a1b2c3d4e5f6...

=== RECOMMENDED ACTIONS ===
1. Review timeline for suspicious file modifications
2. Investigate network connections for unauthorized access
3. Verify integrity of system binaries against known good hashes
4. Analyze memory dump with Volatility for advanced threats
5. Cross-reference findings with threat intelligence
```

---

## 🔐 **Security & Safety**

### **Evidence Integrity:**
- **Read-Only Operations**: Never modifies the system under investigation
- **Hash Verification**: SHA-256 checksums for all collected evidence
- **Chain of Custody**: Detailed documentation of all actions taken
- **Tamper Evidence**: Cryptographically signed evidence packages

### **Command Safety:**
- **Whitelist Approach**: Only approved forensics commands allowed
- **Input Validation**: All commands validated before execution
- **Timeout Protection**: Prevents hanging or runaway processes
- **Permission Checks**: Validates required privileges before execution

### **Privacy Protection:**
- **Local Processing**: All analysis performed locally, no data transmitted
- **Selective Collection**: Choose specific evidence types to collect
- **Anonymization Options**: Remove personally identifiable information
- **Secure Deletion**: Secure cleanup of temporary files

---

## 🤝 **Contributing**

We welcome contributions from the forensics and security community!

### **How to Contribute:**
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-forensics-tool`)
3. **Commit** your changes (`git commit -m 'Add amazing forensics capability'`)
4. **Push** to the branch (`git push origin feature/amazing-forensics-tool`)
5. **Open** a Pull Request

### **Contribution Areas:**
- **New Forensics Tools**: Add support for additional analysis tools
- **Platform Support**: Extend compatibility to new Linux distributions
- **Analysis Techniques**: Implement advanced forensics methodologies
- **Documentation**: Improve guides and educational content
- **Testing**: Add test cases and validation procedures

---

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **Digital Forensics Community**: For establishing professional methodologies
- **SANS Institute**: For forensics training and certification programs
- **Open Source Security Tools**: YARA, Volatility, The Sleuth Kit, and others
- **Linux Community**: For creating the transparent, analyzable systems we investigate

---

## 📞 **Support & Contact**

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Complete guides available in `/docs`
- **Community**: Join discussions in GitHub Discussions
- **Security**: Report security vulnerabilities privately via GitHub Security

---

**🔍 Start your forensics investigation journey today - from novice to expert, we've got you covered!**

*"Making professional digital forensics accessible to everyone, one investigation at a time."*
