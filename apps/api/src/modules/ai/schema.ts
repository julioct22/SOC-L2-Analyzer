import { z } from 'zod';
import { L1_VERDICTS } from '@soc/shared';

/** Estructura que la IA debe devolver (se fuerza mediante tool use + validación Zod) */
export const AiOutputSchema = z.object({
  executive_summary: z.string().min(50),
  general_recommendations: z.array(z.string().min(10)).min(3).max(12),
  findings: z.array(
    z.object({
      ref: z.string(),
      technical_explanation: z.string().min(40),
      impact: z.string().min(20),
      l1_verdict: z.enum(L1_VERDICTS),
      l1_rationale: z.string().min(10),
      cited_log_ids: z.array(z.string()).min(1),
    }),
  ),
});
export type AiOutput = z.infer<typeof AiOutputSchema>;

/** JSON Schema equivalente para la definición de la herramienta en la API de Anthropic */
export const AI_TOOL_INPUT_SCHEMA = {
  type: 'object',
  properties: {
    executive_summary: {
      type: 'string',
      description: 'Resumen ejecutivo en español (3-6 párrafos) para gerencia: qué pasó, gravedad, impacto y acciones prioritarias.',
    },
    general_recommendations: {
      type: 'array',
      items: { type: 'string' },
      description: 'Entre 5 y 10 recomendaciones generales de seguridad, priorizadas, derivadas de los hallazgos.',
    },
    findings: {
      type: 'array',
      description: 'Un elemento por cada hallazgo recibido (mismo ref). No agregues hallazgos nuevos.',
      items: {
        type: 'object',
        properties: {
          ref: { type: 'string', description: 'Identificador del hallazgo recibido (p. ej. H01)' },
          technical_explanation: { type: 'string', description: 'Explicación técnica detallada basada SOLO en la evidencia del hallazgo, citando Log_ID.' },
          impact: { type: 'string', description: 'Posible impacto en la organización.' },
          l1_verdict: { type: 'string', enum: [...L1_VERDICTS] },
          l1_rationale: { type: 'string', description: 'Por qué propones ese veredicto de triaje al analista L2.' },
          cited_log_ids: { type: 'array', items: { type: 'string' }, description: 'Log_ID de la evidencia de ESTE hallazgo que sustentan tu explicación.' },
        },
        required: ['ref', 'technical_explanation', 'impact', 'l1_verdict', 'l1_rationale', 'cited_log_ids'],
      },
    },
  },
  required: ['executive_summary', 'general_recommendations', 'findings'],
} as const;
