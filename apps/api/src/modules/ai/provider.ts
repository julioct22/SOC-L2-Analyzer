import Anthropic from '@anthropic-ai/sdk';
import { env } from '../../config/env.js';
import { AI_TOOL_INPUT_SCHEMA } from './schema.js';

/**
 * Proveedor de IA. El resto del sistema solo depende de esta interfaz.
 * Se elige con AI_PROVIDER en el .env (auto | anthropic | gemini | none).
 * Para agregar otro (OpenAI, Ollama...) implementa la interfaz y agrégalo en getProvider().
 */
export interface NarrativeProvider {
  name: 'anthropic' | 'gemini';
  model: string;
  /** Devuelve el objeto JSON (sin validar) generado por el modelo */
  generate(system: string, user: string): Promise<unknown>;
}

// ───────────────────────────── Claude (Anthropic) ─────────────────────────────
class AnthropicProvider implements NarrativeProvider {
  name = 'anthropic' as const;
  private client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY, timeout: 240_000, maxRetries: 2 });
  model = env.ANTHROPIC_MODEL;

  async generate(system: string, user: string): Promise<unknown> {
    const msg = await this.client.messages.create({
      model: this.model,
      max_tokens: env.AI_MAX_TOKENS,
      system,
      tools: [
        {
          name: 'submit_report',
          description: 'Entrega la redacción del informe técnico de seguridad.',
          input_schema: AI_TOOL_INPUT_SCHEMA as unknown as Anthropic.Messages.Tool.InputSchema,
        },
      ],
      tool_choice: { type: 'tool', name: 'submit_report' },
      messages: [{ role: 'user', content: user }],
    });
    const block = msg.content.find((b) => b.type === 'tool_use');
    if (!block || block.type !== 'tool_use') throw new Error(`La IA no devolvió el formato esperado (stop_reason=${msg.stop_reason})`);
    if (msg.stop_reason === 'max_tokens') throw new Error('La respuesta de la IA se cortó por límite de tokens (aumente AI_MAX_TOKENS)');
    return block.input;
  }
}

// ───────────────────────────── Gemini (Google AI Studio) ─────────────────────────────
interface GeminiResponse {
  candidates?: { content?: { parts?: { text?: string; thought?: boolean }[] }; finishReason?: string }[];
  promptFeedback?: { blockReason?: string };
  error?: { code?: number; message?: string; status?: string };
}

/**
 * Gemini vía REST (sin SDK adicional). Usa salida JSON estructurada con el mismo esquema que Claude.
 * Plan gratuito: https://aistudio.google.com/apikey (tiene límites de peticiones por minuto/día).
 */
export class GeminiProvider implements NarrativeProvider {
  name = 'gemini' as const;
  model = env.GEMINI_MODEL;
  private endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(env.GEMINI_MODEL)}:generateContent`;

  constructor(private fetchFn: typeof fetch = fetch) {}

  async generate(system: string, user: string): Promise<unknown> {
    const body = {
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: 'user', parts: [{ text: user }] }],
      generationConfig: {
        responseMimeType: 'application/json',
        responseJsonSchema: AI_TOOL_INPUT_SCHEMA,
        maxOutputTokens: env.AI_MAX_TOKENS,
        temperature: 0.2,
      },
    };

    // Reintentos ante límite de cuota (429) o saturación (500/503), habituales en el plan gratuito
    const delays = [0, 8_000, 20_000];
    let last: Error | null = null;
    for (const delay of delays) {
      if (delay) await new Promise((r) => setTimeout(r, delay));
      const res = await this.fetchFn(this.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(240_000),
      });
      const data = (await res.json().catch(() => ({}))) as GeminiResponse;
      if (!res.ok) {
        const msg = data.error?.message ?? `HTTP ${res.status}`;
        last =
          res.status === 429
            ? new Error(`Gemini: límite del plan gratuito alcanzado, intente en unos minutos (${msg})`)
            : res.status === 400 || res.status === 403 || res.status === 404
              ? new Error(`Gemini rechazó la petición: ${msg}. Revise GEMINI_API_KEY y GEMINI_MODEL.`)
              : new Error(`Gemini respondió ${res.status}: ${msg}`);
        if ([429, 500, 503].includes(res.status)) continue;
        throw last;
      }
      if (data.promptFeedback?.blockReason) throw new Error(`Gemini bloqueó la petición (${data.promptFeedback.blockReason})`);
      const cand = data.candidates?.[0];
      if (cand?.finishReason === 'MAX_TOKENS') throw new Error('La respuesta de Gemini se cortó por límite de tokens (aumente AI_MAX_TOKENS)');
      const text = (cand?.content?.parts ?? [])
        .filter((p) => !p.thought && typeof p.text === 'string')
        .map((p) => p.text)
        .join('')
        .trim();
      if (!text) throw new Error(`Gemini no devolvió contenido (finishReason=${cand?.finishReason ?? 'desconocido'})`);
      try {
        return JSON.parse(text.replace(/^```(?:json)?\s*|\s*```$/g, ''));
      } catch {
        throw new Error('Gemini devolvió un JSON inválido');
      }
    }
    throw last ?? new Error('Gemini no respondió');
  }
}

let provider: NarrativeProvider | null = null;
export function getProvider(): NarrativeProvider | null {
  if (!env.aiProvider) return null;
  provider ??= env.aiProvider === 'gemini' ? new GeminiProvider() : new AnthropicProvider();
  return provider;
}
