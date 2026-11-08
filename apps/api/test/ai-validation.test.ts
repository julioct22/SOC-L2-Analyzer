/**
 * Pruebas de la validación anti-alucinación aplicada a los textos de la IA.
 */
import { describe, expect, it } from 'vitest';
import { _internal } from '../src/modules/ai/narrative.service.js';

const facts = {
  allLogIds: new Set(['EVT-00057', 'EVT-00058', 'EVT-00123']),
  allIps: new Set(['203.0.113.74', '10.10.1.22']),
  allTechniques: new Set(['T1110.003', 'T1110', 'T1078']),
};
const findingTechniques = new Set(['T1110.003', 'T1110']);
const findingEvidence = new Set(['EVT-00057', 'EVT-00058']);

describe('validación de textos de IA', () => {
  it('acepta un texto que solo usa datos de la evidencia', () => {
    const text = 'La IP 203.0.113.74 generó fallos (EVT-00057, EVT-00058), patrón de T1110.003.';
    expect(_internal.checkText(text, facts, findingTechniques, findingEvidence)).toBeNull();
  });

  it('rechaza un Log_ID inexistente', () => {
    expect(_internal.checkText('Ver EVT-99999', facts, findingTechniques, findingEvidence)).toMatch(/no existe/);
  });

  it('rechaza un Log_ID real que no pertenece a la evidencia del hallazgo', () => {
    expect(_internal.checkText('Ver EVT-00123', facts, findingTechniques, findingEvidence)).toMatch(/no es evidencia/);
  });

  it('rechaza una IP inventada', () => {
    expect(_internal.checkText('Conexión desde 8.8.8.8', facts, findingTechniques, findingEvidence)).toMatch(/8\.8\.8\.8/);
  });

  it('rechaza técnicas MITRE no asignadas al hallazgo', () => {
    expect(_internal.checkText('Uso de T1486 (ransomware)', facts, findingTechniques, findingEvidence)).toMatch(/T1486/);
  });
});
