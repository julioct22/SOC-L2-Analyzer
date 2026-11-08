/**
 * Prueba del proveedor Gemini con un fetch simulado (no requiere clave ni red).
 */
import { describe, expect, it } from 'vitest';
import { GeminiProvider } from '../src/modules/ai/provider.js';

const okResponse = (payload: unknown) =>
  (async () =>
    new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(payload) }] }, finishReason: 'STOP' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;

describe('GeminiProvider', () => {
  it('envía el esquema JSON y devuelve el objeto parseado', async () => {
    let sentBody: Record<string, any> = {};
    const fetchFn = (async (_url: string, init: RequestInit) => {
      sentBody = JSON.parse(String(init.body));
      return (okResponse({ executive_summary: 'ok' }) as any)();
    }) as unknown as typeof fetch;
    const out = await new GeminiProvider(fetchFn).generate('sistema', 'usuario');
    expect(out).toEqual({ executive_summary: 'ok' });
    expect(sentBody.generationConfig.responseMimeType).toBe('application/json');
    expect(sentBody.generationConfig.responseJsonSchema.required).toContain('findings');
    expect(sentBody.systemInstruction.parts[0].text).toBe('sistema');
  });

  it('informa claramente una clave inválida', async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ error: { code: 400, message: 'API key not valid' } }), { status: 400 })) as unknown as typeof fetch;
    await expect(new GeminiProvider(fetchFn).generate('s', 'u')).rejects.toThrow(/GEMINI_API_KEY/);
  });

  it('detecta respuestas cortadas por límite de tokens', async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: '{"a":' }] }, finishReason: 'MAX_TOKENS' }] }), {
        status: 200,
      })) as unknown as typeof fetch;
    await expect(new GeminiProvider(fetchFn).generate('s', 'u')).rejects.toThrow(/AI_MAX_TOKENS/);
  });
});
