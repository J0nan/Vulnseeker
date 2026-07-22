import { CVE } from '../types';

export type AIProvider = 'gemini' | 'chatgpt' | 'claude' | 'custom';

// Use the existing proxy from the app
const getProxiedUrl = (url: string) => {
  // Don't proxy localhost/127.0.0.1
  if (url.includes('localhost') || url.includes('127.0.0.1')) {
    return url;
  }
  return `https://cors.ja1712.workers.dev/?url=${encodeURIComponent(url)}`;
};

const extractJsonFromText = (textContent: string): any => {
  try {
    const parsed = JSON.parse(textContent);
    return parsed;
  } catch (parseError) {
    const match = textContent.match(/```(?:json)?\n([\s\S]*?)\n```/);
    if (match && match[1]) {
      const parsed = JSON.parse(match[1]);
      return parsed;
    }
    throw new Error('AI returned malformed JSON');
  }
};

export const fetchAvailableModels = async (
  provider: AIProvider,
  apiKey: string,
  customBaseUrl?: string
): Promise<string[]> => {
  if (!apiKey && provider !== 'custom') return [];

  let url = '';
  let headers: Record<string, string> = {};

  if (provider === 'gemini') {
    url = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;
  } else if (provider === 'chatgpt') {
    url = getProxiedUrl('https://api.openai.com/v1/models');
    headers['Authorization'] = `Bearer ${apiKey}`;
  } else if (provider === 'claude') {
    url = getProxiedUrl('https://api.anthropic.com/v1/models');
    headers['x-api-key'] = apiKey;
    headers['anthropic-version'] = '2023-06-01';
  } else if (provider === 'custom') {
    const baseUrl = customBaseUrl?.trim() || 'http://localhost:11434/v1';
    const endpoint = baseUrl.endsWith('/') ? `${baseUrl}models` : `${baseUrl}/models`;
    url = getProxiedUrl(endpoint);
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
  }

  try {
    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(`Failed to fetch models from ${provider}`);
    }
    const data = await response.json();
    
    if (provider === 'gemini') {
      return (data.models || [])
        .filter((m: any) => 
          m.supportedGenerationMethods?.includes('generateContent') && 
          (m.name.startsWith('models/gemini-') || m.name.startsWith('models/gemma-'))
        )
        .map((m: any) => m.name.replace('models/', ''));
    } else if (provider === 'chatgpt' || provider === 'custom') {
      return (data.data || []).map((m: any) => m.id);
    } else if (provider === 'claude') {
      return (data.data || []).map((m: any) => m.id);
    }
    return [];
  } catch (error) {
    console.error(`Error fetching models for ${provider}:`, error);
    throw error;
  }
};

export const filterCVEsWithAI = async (
  provider: AIProvider,
  apiKey: string,
  modelName: string,
  cves: CVE[],
  product: string,
  version: string,
  customBaseUrl?: string
): Promise<CVE[]> => {
  // Optimize prompt to only return an array of CVE IDs to save tokens
  const simplifiedCves = cves.map(c => ({ id: c.id, configurations: c.vulnerable_configuration, summary: c.summary }));
  const prompt = `For the following JSON array of vulnerabilities, identify which ones affect ${product} version ${version}. Return ONLY a JSON array of strings containing the 'id' of the affected CVEs. Do not return anything else. JSON: ${JSON.stringify(simplifiedCves)}`;

  let url = '';
  let headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };
  let body: any = {};
  
  if (provider === 'gemini') {
    url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
    body = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: "application/json" }
    };
  } else if (provider === 'chatgpt') {
    url = getProxiedUrl('https://api.openai.com/v1/chat/completions');
    headers['Authorization'] = `Bearer ${apiKey}`;
    body = {
      model: modelName,
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: "json_object" }
    };
  } else if (provider === 'claude') {
    url = getProxiedUrl('https://api.anthropic.com/v1/messages');
    headers['x-api-key'] = apiKey;
    headers['anthropic-version'] = '2023-06-01';
    body = {
      model: modelName,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    };
  } else if (provider === 'custom') {
    const baseUrl = customBaseUrl?.trim() || 'http://localhost:11434/v1';
    const endpoint = baseUrl.endsWith('/') ? `${baseUrl}chat/completions` : `${baseUrl}/chat/completions`;
    url = getProxiedUrl(endpoint);
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
    body = {
      model: modelName,
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: "json_object" }
    };
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error?.message || errorData.error || `Failed to generate content: ${response.statusText}`);
    }

    const data = await response.json();
    let textContent = '';

    if (provider === 'gemini') {
      const candidate = data.candidates?.[0];
      if (candidate?.finishReason && candidate.finishReason !== 'STOP') {
        throw new Error(`Gemini API stopped early. Reason: ${candidate.finishReason}`);
      }
      textContent = candidate?.content?.parts?.[0]?.text;
    } else if (provider === 'chatgpt' || provider === 'custom') {
      textContent = data.choices?.[0]?.message?.content;
    } else if (provider === 'claude') {
      textContent = data.content?.[0]?.text;
    }

    if (!textContent) {
      throw new Error('No content returned from AI');
    }

    let parsedIds: any = null;
    
    // Sometimes OpenAI format wrapped inside object { "cves": [...] } instead of raw array
    try {
        const parsed = JSON.parse(textContent);
        if (parsed && !Array.isArray(parsed) && Object.keys(parsed).length === 1) {
             const key = Object.keys(parsed)[0];
             if (Array.isArray(parsed[key])) {
                 parsedIds = parsed[key];
             }
        }
    } catch(e) {}

    if (!parsedIds) {
       parsedIds = extractJsonFromText(textContent);
    }
    
    if (!Array.isArray(parsedIds)) {
        throw new Error('AI did not return a valid array of IDs');
    }
    
    // Ensure it's an array of strings
    const validIds = parsedIds.filter(id => typeof id === 'string');
    
    // Filter the original cves list using the AI's returned IDs
    return cves.filter(cve => validIds.includes(cve.id));

  } catch (error) {
    console.error(`Error filtering CVEs with ${provider}:`, error);
    throw error;
  }
};
