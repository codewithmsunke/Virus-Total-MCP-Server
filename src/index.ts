import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as http from 'http';
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import FormData = require("form-data");

async function main() {
  if (!process.env.VT_API_KEY) {
    console.error("WARNING: VT_API_KEY environment variable is not set. Attempting to read from VS Code user mcp.json...");
    try {
      const loaded = tryLoadVtKeyFromUserMcp();
      if (loaded) {
        console.log('VT_API_KEY loaded from user mcp.json');
      } else {
        console.error('VT_API_KEY not found in user mcp.json');
      }
    } catch (e) {
      console.error('Error reading user mcp.json for VT_API_KEY:', e);
    }
  } else {
    console.log("VT_API_KEY is set.");
  }

  function tryLoadVtKeyFromUserMcp(): boolean {
    const appData = process.env.APPDATA || process.env.HOME || '';
    if (!appData) return false;
    const userMcpPath = path.join(appData, 'Code', 'User', 'mcp.json');
    if (!fs.existsSync(userMcpPath)) {
      console.error('DEBUG: mcp.json not found at:', userMcpPath);
      return false;
    }
    console.error('DEBUG: Found mcp.json at:', userMcpPath);
    const raw = fs.readFileSync(userMcpPath, 'utf-8');
    const parsed = JSON.parse(raw);
    const servers = parsed.servers;
    if (!servers || typeof servers !== 'object') {
      console.error('DEBUG: No servers object in mcp.json');
      return false;
    }
    // check vt-server first
    const vt = servers['vt-server'];
    if (vt?.env?.VT_API_KEY) {
      process.env.VT_API_KEY = vt.env.VT_API_KEY;
      console.error('DEBUG: Found VT_API_KEY in vt-server config, length:', vt.env.VT_API_KEY.length);
      return true;
    }
    // search all servers
    for (const key of Object.keys(servers)) {
      const s = servers[key];
      if (s?.env?.VT_API_KEY) {
        process.env.VT_API_KEY = s.env.VT_API_KEY;
        console.error('DEBUG: Found VT_API_KEY in', key, 'config, length:', s.env.VT_API_KEY.length);
        return true;
      }
    }
    console.error('DEBUG: No VT_API_KEY found in any server config');
    return false;
  }

  function maskKey(key: string | undefined) {
    if (!key) return null;
    if (key.length <= 12) return key.replace(/.(?=.{4})/g, '*');
    return `${key.slice(0,6)}...${key.slice(-6)}`;
  }
  const server = new McpServer({
    name: "virustotal-mcp",
    version: "0.1.0",
  });

  // Tool: Scan a file
  server.registerTool(
    "VTscanFile",
    {
      title: "VirusTotal File Scan",
      description: "Scan a file using VirusTotal API",
      inputSchema: {
        filePath: z.string(),
      },
    },
    async ({ filePath }) => {
      if (!process.env.VT_API_KEY) {
        return {
          content: [
            {
              type: "text",
              text: "ERROR: VT_API_KEY environment variable is not set. Please configure it in your MCP server settings.",
            },
          ],
        };
      }
      const absPath = path.isAbsolute(filePath)
        ? filePath
        : path.join(process.cwd(), filePath);

      const form = new FormData();
      form.append("file", fs.createReadStream(absPath));

      if (process.env.DEBUG_VT_REQ === '1' || process.env.DEBUG_VT_REQ === 'true') {
        console.error('DEBUG: Sending VirusTotal POST to /files with headers:', {
          ...form.getHeaders(),
          'x-apikey': maskKey(process.env.VT_API_KEY),
        });
      }
      // Validate API key before making request
      if (!process.env.VT_API_KEY) {
        console.error('DEBUG: VT_API_KEY is undefined at request time!');
        throw new Error('VT_API_KEY is missing at request time');
      }
      console.error('DEBUG: Making request with API key length:', process.env.VT_API_KEY.length);
      
      const headers = {
        ...form.getHeaders(),
        "x-apikey": process.env.VT_API_KEY,
      };
      console.error('DEBUG: Request headers:', Object.keys(headers));
      
      const response = await axios.post(
        "https://www.virustotal.com/api/v3/files",
        form,
        { headers }
      );

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    }
  );

  // Tool: Get analysis status and results
  server.registerTool(
    "VTgetFileReport",
    {
      title: "VirusTotal File Report",
      description: "Get a report for a file hash or analysis ID from VirusTotal",
      inputSchema: {
        fileHash: z.string(),
      },
    },
    async ({ fileHash }) => {
      if (!process.env.VT_API_KEY) {
        return {
          content: [
            {
              type: "text",
              text: "ERROR: VT_API_KEY environment variable is not set. Please configure it in your MCP server settings.",
            },
          ],
        };
      }
      if (process.env.DEBUG_VT_REQ === '1' || process.env.DEBUG_VT_REQ === 'true') {
        console.error('DEBUG: Sending VirusTotal GET to /files/:id with headers:', {
          'x-apikey': maskKey(process.env.VT_API_KEY),
        });
      }
      // Check if input looks like a scan ID (base64 string with multiple segments)
      const isAnalysisId = fileHash.includes('/') || fileHash.includes('+') || fileHash.includes('=');
      
      if (!isAnalysisId) {
        try {
          // Try to get file report first if it's not an analysis ID
          const response = await axios.get(
            `https://www.virustotal.com/api/v3/files/${fileHash}`,
            {
              headers: {
                "x-apikey": process.env.VT_API_KEY,
              },
            }
          );

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(response.data, null, 2),
              },
            ],
          };
        } catch (error) {
          if (!axios.isAxiosError(error) || error.response?.status !== 404) {
            throw error;
          }
          // Fall through to analysis check if file not found
        }
      }

      // If it's an analysis ID or file not found, try to get analysis status
      try {
        // Properly encode analysis ID for URL
        const encodedId = encodeURIComponent(fileHash);
        const analysisResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${encodedId}`,
          {
            headers: {
              "x-apikey": process.env.VT_API_KEY,
            },
          }
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(analysisResponse.data, null, 2),
            },
          ],
        };
      } catch (analysisError) {
        if (axios.isAxiosError(analysisError)) {
          return {
            content: [
              {
                type: "text",
                text: `Analysis not found (${analysisError.response?.status || 'unknown error'}). For new scans, please wait a few minutes and try again.`,
              },
            ],
          };
        }
        throw analysisError;
      }
    }
  );

  // Use stdio transport for MCP client
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("VirusTotal MCP server started (stdio transport)");

  // Optional debug HTTP endpoint to verify VT_API_KEY in the running process.
  // Enable by setting DEBUG_VT_ENV=1 (or 'true') in the server environment.
  if (process.env.DEBUG_VT_ENV === '1' || process.env.DEBUG_VT_ENV === 'true') {
    const debugPort = Number(process.env.DEBUG_VT_PORT || 3010);
    const debugServer = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/_env') {
        const present = !!process.env.VT_API_KEY;
        const masked = process.env.VT_API_KEY
          ? `${process.env.VT_API_KEY.slice(0, 6)}...${process.env.VT_API_KEY.slice(-6)}`
          : null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ vt_api_key_set: present, vt_api_key_masked: masked }));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    });
    debugServer.listen(debugPort, () => {
      console.error(`Debug env endpoint listening on http://localhost:${debugPort}/_env`);
    });
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
