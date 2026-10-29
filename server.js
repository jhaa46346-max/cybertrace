// server.ts
import express from "express";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";
dotenv.config();
var app = express();
var PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3e3;
app.use(express.json({ limit: "10mb" }));
var apiKey = process.env.GEMINI_API_KEY;
var ai = apiKey ? new GoogleGenAI({
  apiKey,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build"
    }
  }
}) : null;
app.get("/api/ai/status", (_req, res) => {
  res.json({
    available: !!ai,
    model: "gemini-3.8-flash"
  });
});
app.post("/api/ai/investigate", async (req, res) => {
  try {
    if (!ai) {
      return res.status(503).json({
        error: "Gemini API not configured on server (GEMINI_API_KEY missing). Falling back to local heuristic engine.",
        available: false
      });
    }
    const { events, rules, caseInfo } = req.body;
    if (!Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: "No timeline events provided." });
    }
    const sampleEvents = events.slice(0, 80).map((e) => ({
      utc: e.normalized_utc,
      host: e.host,
      service: e.service,
      user: e.user || null,
      src_ip: e.src_ip || null,
      type: e.event_type,
      msg: e.message,
      confidence: e.confidence
    }));
    const systemInstruction = `You are a digital forensics and incident response (DFIR) analyst for small IT teams.
Analyze the provided chronological log events. Identify intrusion vectors, brute force attempts, unauthorized logins, and privilege escalations.
Map findings to MITRE ATT&CK techniques. Provide actionable containment steps.
Return strict JSON matching the schema.`;
    const prompt = `Investigate this unified timeline for Case: "${caseInfo?.title || "Forensic Case"}" (${caseInfo?.caseNumber || "N/A"}).
Examiner notes: ${caseInfo?.description || "N/A"}.
Timeline Events (${sampleEvents.length} events):
${JSON.stringify(sampleEvents, null, 2)}`;
    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: { type: Type.STRING },
            threatLevel: {
              type: Type.STRING,
              description: "CRITICAL, HIGH, MEDIUM, or LOW"
            },
            attackTimeline: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  timestamp: { type: Type.STRING },
                  phase: { type: Type.STRING },
                  description: { type: Type.STRING },
                  evidenceIds: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING }
                  }
                },
                required: ["timestamp", "phase", "description"]
              }
            },
            affectedEntities: {
              type: Type.OBJECT,
              properties: {
                hosts: { type: Type.ARRAY, items: { type: Type.STRING } },
                users: { type: Type.ARRAY, items: { type: Type.STRING } },
                ips: { type: Type.ARRAY, items: { type: Type.STRING } }
              },
              required: ["hosts", "users", "ips"]
            },
            mitreMappings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  technique: { type: Type.STRING },
                  tactic: { type: Type.STRING },
                  evidence: { type: Type.STRING }
                },
                required: ["id", "technique", "tactic", "evidence"]
              }
            },
            recommendedActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING }
            }
          },
          required: [
            "summary",
            "threatLevel",
            "attackTimeline",
            "affectedEntities",
            "mitreMappings",
            "recommendedActions"
          ]
        }
      }
    });
    const parsedJson = JSON.parse(response.text || "{}");
    parsedJson.generatedBy = "gemini-3.8-flash";
    return res.json(parsedJson);
  } catch (error) {
    console.error("Gemini investigation error:", error);
    return res.status(500).json({
      error: error.message || "Error executing AI forensic investigation"
    });
  }
});
app.post("/api/ai/train-rule", async (req, res) => {
  try {
    if (!ai) {
      return res.status(503).json({
        error: "Gemini API not available. Cannot use cloud rule trainer."
      });
    }
    const { description, targetEvents } = req.body;
    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: `Generate a detection rule for: "${description}". Sample matching logs: ${JSON.stringify(
        targetEvents || []
      )}`,
      config: {
        systemInstruction: `You are a SIEM / SOC detection engineer. Generate a regex or heuristic triage rule for incident logs.`,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            name: { type: Type.STRING },
            description: { type: Type.STRING },
            patternType: { type: Type.STRING, description: "regex or heuristic" },
            matchField: {
              type: Type.STRING,
              description: "message, service, user, src_ip, or event_type"
            },
            patternValue: {
              type: Type.STRING,
              description: "Regular expression or keyword"
            },
            severity: {
              type: Type.STRING,
              description: "CRITICAL, HIGH, MEDIUM, LOW, or INFO"
            },
            mitreTechnique: { type: Type.STRING },
            recommendation: { type: Type.STRING }
          },
          required: [
            "name",
            "description",
            "patternType",
            "matchField",
            "patternValue",
            "severity",
            "mitreTechnique",
            "recommendation"
          ]
        }
      }
    });
    const ruleData = JSON.parse(response.text || "{}");
    return res.json(ruleData);
  } catch (error) {
    console.error("Gemini train-rule error:", error);
    return res.status(500).json({ error: error.message });
  }
});
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
    app.get("*", (_req, res) => {
      res.sendFile("dist/index.html", { root: "." });
    });
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`TimelineForge server running on http://0.0.0.0:${PORT}`);
  });
}
startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
