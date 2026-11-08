import { z } from 'zod';

/**
 * Todas las variables de entorno se validan aquí al arrancar.
 * Si falta una obligatoria, la API no inicia y muestra qué falta.
 */
const bool = z
  .string()
  .optional()
  .transform((v) => v === 'true' || v === '1');

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL es obligatoria'),
  DATA_DIR: z.string().default('./data'),
  APP_TIMEZONE: z.string().default('America/Panama'),
  ORG_NAME: z.string().default('Organización'),
  MAX_UPLOAD_MB: z.coerce.number().default(20),

  JWT_SECRET: z.string().min(32, 'JWT_SECRET debe tener al menos 32 caracteres'),
  SESSION_HOURS: z.coerce.number().default(8),
  COOKIE_SECURE: bool,

  ADMIN_USERNAME: z.string().default('admin'),
  ADMIN_PASSWORD: z.string().min(8, 'ADMIN_PASSWORD debe tener al menos 8 caracteres'),
  ADMIN_FULL_NAME: z.string().default('Administrador del Sistema'),

  /** auto = usa Anthropic si hay clave, si no Gemini si hay clave, si no ninguna */
  AI_PROVIDER: z.enum(['auto', 'anthropic', 'gemini', 'none']).default('auto'),
  ANTHROPIC_API_KEY: z.string().optional().default(''),
  ANTHROPIC_MODEL: z.string().default('claude-sonnet-5-5'),
  GEMINI_API_KEY: z.string().optional().default(''),
  GEMINI_MODEL: z.string().default('gemini-flash-latest'),
  AI_MAX_TOKENS: z.coerce.number().default(8000),

  CHROMIUM_PATH: z.string().optional(),
});

const parsed = EnvSchema.safeParse(process.env);
if (!parsed.success) {
  console.error('❌ Variables de entorno inválidas:');
  for (const issue of parsed.error.issues) console.error(`   - ${issue.path.join('.')}: ${issue.message}`);
  process.exit(1);
}

function resolveProvider(d: z.infer<typeof EnvSchema>): 'anthropic' | 'gemini' | null {
  const hasAnthropic = d.ANTHROPIC_API_KEY.trim().length > 0;
  const hasGemini = d.GEMINI_API_KEY.trim().length > 0;
  if (d.AI_PROVIDER === 'none') return null;
  if (d.AI_PROVIDER === 'anthropic') return hasAnthropic ? 'anthropic' : null;
  if (d.AI_PROVIDER === 'gemini') return hasGemini ? 'gemini' : null;
  return hasAnthropic ? 'anthropic' : hasGemini ? 'gemini' : null;
}

const aiProvider = resolveProvider(parsed.data);

export const env = {
  ...parsed.data,
  aiProvider,
  aiEnabled: aiProvider !== null,
  aiModel: aiProvider === 'anthropic' ? parsed.data.ANTHROPIC_MODEL : aiProvider === 'gemini' ? parsed.data.GEMINI_MODEL : null,
};
export type Env = typeof env;
