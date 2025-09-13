# VirusTotal MCP Server

A Model Context Protocol (MCP) server that integrates with VirusTotal's API to provide file scanning and analysis capabilities.

## Features

- **File Scanning**: Submit files to VirusTotal for analysis
- **Report Retrieval**: Get detailed analysis reports for files using their hash or analysis ID
- **Environment Variable Support**: Configure VirusTotal API key through environment variables or MCP settings
- **Debug Endpoints**: Optional debug endpoints to verify configuration

## Setup

1. **Prerequisites**
   - Node.js and npm installed
   - A VirusTotal API key (get one from [VirusTotal](https://www.virustotal.com/))

2. **Installation**
   ```bash
   npm install
   ```

3. **Configuration**
   Configure your VirusTotal API key in one of these ways:
   - Set `VT_API_KEY` environment variable
   - Add to VS Code's `mcp.json`:
     ```json
     {
       "servers": {
         "vt-server": {
           "command": "node",
           "args": ["path/to/dist/index.js"],
           "env": {
             "VT_API_KEY": "your-api-key-here"
           }
         }
       }
     }
     ```

## Tools

### VTscanFile
Scans a file using VirusTotal's API.
- Input: `filePath` (string) - Path to the file to scan
- Output: Analysis ID and links to check the status

### VTgetFileReport
Gets a report for a file from VirusTotal.
- Input: `fileHash` (string) - MD5/SHA-1/SHA-256 hash or analysis ID
- Output: Detailed analysis report including antivirus detections

### Example Output

When scanning a file, you'll receive a detailed analysis report. Here's an example output:

```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 70,
        "timeout": 0,
        "type-unsupported": 6
      },
      "magic": "PE32+ executable (console) x86-64, for MS Windows",
      "size": 85268464,
      "type_description": "Win32 EXE",
      "type_tags": [
        "executable",
        "windows",
        "win32",
        "pe",
        "peexe"
      ],
      "signature_info": {
        "product": "Node.js",
        "verified": "Signed",
        "description": "Node.js JavaScript Runtime",
        "file version": "22.19.0",
        "signing date": "07:54 AM 08/28/2025",
        "original name": "node.exe",
        "signers": "OpenJS Foundation; Microsoft ID Verified CS AOC CA 01"
      },
      "first_submission_date": 1756417347,
      "last_analysis_date": 1757069321,
      "times_submitted": 21,
      "total_votes": {
        "harmless": 0,
        "malicious": 0
      }
    }
  }
}
```

The report includes:
- Security scan results from multiple antivirus engines
- File metadata (type, size, signatures)
- Analysis history and community feedback
- Digital signature verification (for signed files)
- File characteristics and classification

## Debug Features

### Environment Variable Verification
Enable debug endpoint by setting `DEBUG_VT_ENV=1`:
- Endpoint: `http://localhost:3010/_env`
- Shows API key status (masked for security)

### Request Debugging
Enable request debugging by setting `DEBUG_VT_REQ=1`:
- Shows API request details in console
- Masks sensitive information

## Error Handling

- Handles missing API keys with informative messages
- Provides feedback for analysis in progress
- Supports both file hash and analysis ID lookups

## Development

1. **Build**
   ```bash
   npx tsc
   ```

2. **Run**
   ```bash
   node dist/index.js
   ```

3. **Debug Mode**
   ```bash
   DEBUG_VT_ENV=1 DEBUG_VT_REQ=1 node dist/index.js
   ```

## Security Notes

- API keys are masked in debug output
- Support for loading API keys from secure configuration
- File scanning uses streams for efficient memory usage
