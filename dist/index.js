"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const http = __importStar(require("http"));
const axios_1 = __importDefault(require("axios"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const FormData = require("form-data");
async function main() {
    if (!process.env.VT_API_KEY) {
        console.error("WARNING: VT_API_KEY environment variable is not set. Attempting to read from VS Code user mcp.json...");
        try {
            const loaded = tryLoadVtKeyFromUserMcp();
            if (loaded) {
                console.log('VT_API_KEY loaded from user mcp.json');
            }
            else {
                console.error('VT_API_KEY not found in user mcp.json');
            }
        }
        catch (e) {
            console.error('Error reading user mcp.json for VT_API_KEY:', e);
        }
    }
    else {
        console.log("VT_API_KEY is set.");
    }
    function tryLoadVtKeyFromUserMcp() {
        const appData = process.env.APPDATA || process.env.HOME || '';
        if (!appData)
            return false;
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
    function maskKey(key) {
        if (!key)
            return null;
        if (key.length <= 12)
            return key.replace(/.(?=.{4})/g, '*');
        return `${key.slice(0, 6)}...${key.slice(-6)}`;
    }
    const server = new mcp_js_1.McpServer({
        name: "virustotal-mcp",
        version: "0.1.0",
    });
    // Tool: Scan a file
    server.registerTool("VTscanFile", {
        title: "VirusTotal File Scan",
        description: "Scan a file using VirusTotal API",
        inputSchema: {
            filePath: zod_1.z.string(),
        },
    }, async ({ filePath }) => {
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
        const response = await axios_1.default.post("https://www.virustotal.com/api/v3/files", form, { headers });
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
        };
    });
    // Tool: Get analysis status and results
    server.registerTool("VTgetFileReport", {
        title: "VirusTotal File Report",
        description: "Get a report for a file hash or analysis ID from VirusTotal",
        inputSchema: {
            fileHash: zod_1.z.string(),
        },
    }, async ({ fileHash }) => {
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
                const response = await axios_1.default.get(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
                    headers: {
                        "x-apikey": process.env.VT_API_KEY,
                    },
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(response.data, null, 2),
                        },
                    ],
                };
            }
            catch (error) {
                if (!axios_1.default.isAxiosError(error) || error.response?.status !== 404) {
                    throw error;
                }
                // Fall through to analysis check if file not found
            }
        }
        // If it's an analysis ID or file not found, try to get analysis status
        try {
            // Properly encode analysis ID for URL
            const encodedId = encodeURIComponent(fileHash);
            const analysisResponse = await axios_1.default.get(`https://www.virustotal.com/api/v3/analyses/${encodedId}`, {
                headers: {
                    "x-apikey": process.env.VT_API_KEY,
                },
            });
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(analysisResponse.data, null, 2),
                    },
                ],
            };
        }
        catch (analysisError) {
            if (axios_1.default.isAxiosError(analysisError)) {
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
    });
    // Use stdio transport for MCP client
    const transport = new stdio_js_1.StdioServerTransport();
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
