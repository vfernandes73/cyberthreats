import { GoogleGenAI, Type } from "@google/genai";
import { Threat, IOC, Severity } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });

export async function searchThreats(query: string, region?: string, vertical?: string, domain?: string): Promise<Partial<Threat>[]> {
  const prompt = `Search for recent cyber threat news with the following criteria:
  - Keyword: ${query || 'recent cyber attacks'}
  - Region: ${region || 'Global'}
  - Vertical: ${vertical || 'All'}
  - Specific Domain: ${domain || 'None'}
  
  Provide a list of recent threats found in public sources. For each threat, provide:
  - title
  - summary (detailed)
  - sourceUrl
  - region
  - vertical
  - actors (if known)
  - severity (low, medium, high, critical)
  - keywords
  - potential IoCs (IPs, domains, hashes) if mentioned.`;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }],
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING },
              summary: { type: Type.STRING },
              sourceUrl: { type: Type.STRING },
              region: { type: Type.STRING },
              vertical: { type: Type.STRING },
              actors: { type: Type.ARRAY, items: { type: Type.STRING } },
              severity: { type: Type.STRING },
              keywords: { type: Type.ARRAY, items: { type: Type.STRING } },
              iocs: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    value: { type: Type.STRING },
                    actor: { type: Type.STRING }
                  }
                }
              }
            },
            required: ["title", "summary", "sourceUrl", "region", "vertical", "severity"]
          }
        }
      }
    });

    return JSON.parse(response.text || '[]');
  } catch (error) {
    console.error("Error searching threats:", error);
    return [];
  }
}

export async function getActorProfile(actorName: string): Promise<{ description: string; techniques: string[] }> {
  const prompt = `Provide a detailed profile for the threat actor: ${actorName}.
  Include a description of their goals, history, and common techniques (TTPs).`;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            description: { type: Type.STRING },
            techniques: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["description", "techniques"]
        }
      }
    });

    return JSON.parse(response.text || '{"description": "", "techniques": []}');
  } catch (error) {
    console.error("Error getting actor profile:", error);
    return { description: "Information not available.", techniques: [] };
  }
}

export async function generateThreatIoCs(title: string, summary: string): Promise<IOC[]> {
  const prompt = `Generate potential Indicators of Compromise (IoCs) for the following threat:
  Title: ${title}
  Summary: ${summary}
  
  Provide a list of IoCs (type: 'IP', 'Domain', 'Hash', 'URL'; value: string) most relevant to this threat.`;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              type: { type: Type.STRING },
              value: { type: Type.STRING },
              actor: { type: Type.STRING }
            },
            required: ["type", "value"]
          }
        }
      }
    });

    return JSON.parse(response.text || '[]');
  } catch (error) {
    console.error("Error generating IoCs:", error);
    return [];
  }
}
