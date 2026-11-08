import { hash, verify } from '@node-rs/argon2';

// Argon2id con parámetros recomendados por OWASP (m=19 MiB, t=2, p=1)
const OPTIONS = { memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

export function hashPassword(plain: string): Promise<string> {
  return hash(plain, OPTIONS);
}

export async function verifyPassword(hashed: string, plain: string): Promise<boolean> {
  try {
    return await verify(hashed, plain);
  } catch {
    return false;
  }
}

/** Política mínima de contraseñas */
export function passwordPolicyError(pw: string): string | null {
  if (pw.length < 10) return 'La contraseña debe tener al menos 10 caracteres';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) return 'Debe incluir mayúsculas y minúsculas';
  if (!/\d/.test(pw)) return 'Debe incluir al menos un número';
  if (!/[^A-Za-z0-9]/.test(pw)) return 'Debe incluir al menos un símbolo';
  return null;
}
