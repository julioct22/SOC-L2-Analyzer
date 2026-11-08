import type { UserDTO } from '@soc/shared';
import type { users } from '../../db/schema.js';

export function toUserDTO(u: typeof users.$inferSelect): UserDTO {
  return {
    id: u.id,
    username: u.username,
    fullName: u.fullName,
    role: u.role,
    isActive: u.isActive,
    mustChangePassword: u.mustChangePassword,
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
  };
}
