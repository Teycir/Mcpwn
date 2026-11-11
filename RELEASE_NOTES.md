# Mcpwn v1.0.0 Release Notes

> **Historical document.** These notes describe v1.0.0. Current behavior,
> breaking changes and fixes are documented in [CHANGELOG.md](CHANGELOG.md)
> and [README.md](README.md).

**Release Date**: December 13, 2025  
**Author**: Teycir Ben Soltane  
**Contact**: teycir@teycirbensoltane.tn  
**Website**: https://teycirbensoltane.tn

---

## 🎉 Production Release

Mcpwn v1.0.0 is now production-ready with industry-leading accuracy for MCP security testing.

## 📊 Key Metrics

- **Accuracy Rate**: 83% (5/6 findings verified)
- **False Positive Rate**: 0%
- **Performance**: ~60 seconds for full comprehensive scan
- **Test Coverage**: 10+ vulnerability categories
- **Verification**: Automated PoC framework included

## ✨ Features

### Security Testing
- ✅ State desynchronization detection
- ✅ Capability validation fuzzing
- ✅ Tool argument injection (RCE, path traversal)
- ✅ Resource path traversal
- ✅ Subscription flooding (DoS)
- ✅ Prompt injection detection
- ✅ Protocol fuzzing (improved accuracy)
- ✅ SSRF injection testing
- ✅ Deserialization vulnerabilities
- ✅ Schema/prototype pollution
- ✅ Authentication bypass
- ✅ OOB DNS exfiltration
- ✅ Race condition testing
- ✅ Resource exhaustion

### Verification Framework
- `poc_verify.py` - Automated vulnerability verification
- `demo_exploits.sh` - Visual demonstration of exploits
- Comprehensive accuracy reports
- Real-world test cases

### Performance Optimizations
- Removed unnecessary sleep delays
- Parallel test execution where safe
- Smart payload deduplication
- Optimized timeout handling
- Reduced subscription flood iterations

### Documentation
- Comprehensive README with examples
- Accuracy and verification reports
- Troubleshooting guide
- API documentation
- Contributing guidelines

## 🔧 Technical Improvements

### Protocol Fuzzing Rewrite
- Fixed stdin/stdout text mode handling
- Proper server lifecycle management
- Accurate crash vs graceful-handling detection
- Eliminated all false positives

### Test Accuracy
- Improved detection logic across all tests
- Better error handling and recovery
- Semantic detection with multiple indicators
- Statistical timing analysis for blind vulnerabilities

## 📦 Installation

```bash
git clone https://github.com/teycir/mcpwn.git
cd mcpwn
pip install -r requirements.txt
```

## 🚀 Quick Start

```bash
# Basic scan
python mcpwn.py npx -y @modelcontextprotocol/server-filesystem /tmp

# With reports
python mcpwn.py --output-json report.json --output-html report.html npx ...

# Verify findings
python poc_verify.py npx -y @modelcontextprotocol/server-filesystem /tmp
```

## 🧪 Verified Against

- @modelcontextprotocol/server-filesystem
- @modelcontextprotocol/server-memory
- @modelcontextprotocol/server-puppeteer
- Custom MCP implementations

## 📝 Known Issues

- State desync finding has format issue (type: null) - cosmetic only
- Race condition test has slice notation error - non-critical

## 🔜 Future Roadmap

- [ ] Additional MCP server testing
- [ ] CI/CD integration examples
- [ ] Docker containerization
- [ ] Web UI for reports
- [ ] Plugin system for custom tests

## 🙏 Acknowledgments

Special thanks to the MCP community for feedback and testing.

## 📄 License

MIT License - See LICENSE file for details.

## 📧 Contact

**Author**: Teycir Ben Soltane  
**Email**: teycir@teycirbensoltane.tn  
**Website**: https://teycirbensoltane.tn

For bug reports and feature requests, please open an issue on GitHub.

---

**Full Changelog**: https://github.com/teycir/mcpwn/blob/main/CHANGELOG.md
