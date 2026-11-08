/**
 * Reglas de detección (el "analista L1" automático).
 *
 * Principio de rigor: cada regla SOLO afirma lo que está en los eventos que adjunta como evidencia.
 * Las reglas son genéricas (no dependen de IPs/usuarios concretos del archivo de ejemplo) y sus umbrales
 * están en THRESHOLDS para poder ajustarlos.
 *
 * Para agregar una regla: crea un objeto `Rule` y añádelo a RULES (el orden importa: las reglas más
 * específicas van primero y "reclaman" sus eventos para que reglas genéricas no los dupliquen).
 */
import type { Ev, RawFinding, Rule, RuleContext } from './types.js';
import {
  MIN,
  SENSITIVE_DATA,
  SUSPICIOUS_PATH,
  bursts,
  byTime,
  bytesOut,
  fmtList,
  groupBy,
  hhmm,
  ipOf,
  isFailedLogon,
  isPrivilegedLogon,
  isPublicIp,
  isSuccessLogon,
  logIds,
  logonType,
  mb,
  nonEmpty,
  span,
  uniq,
} from './helpers.js';

export const THRESHOLDS = {
  /** Password spraying / fuerza bruta por IP de origen */
  sprayWindowMin: 15,
  sprayMinFailures: 10,
  sprayMinDistinctUsers: 5,
  /** Ventana para buscar un login exitoso después del ataque de credenciales */
  compromiseLookaheadMin: 60,
  /** Fuerza bruta dirigida (misma IP + mismo usuario) seguida de éxito */
  guessMinFailures: 3,
  guessWindowMin: 10,
  /** Acceso masivo a archivos */
  massAccessMinFiles: 10,
  massAccessWindowMin: 10,
  /** Exfiltración por volumen */
  exfilWindowMin: 30,
  exfilMinBytes: 50 * 1024 * 1024,
  exfilMinRequests: 10,
  /** Escaneo / ataque web */
  webScanMinRequests: 8,
  webScanWindowMin: 15,
};

const claim = (ctx: RuleContext, evs: Ev[]) => evs.forEach((e) => ctx.claimed.add(e.id));
const unclaimed = (ctx: RuleContext, evs: Ev[]) => evs.filter((e) => !ctx.claimed.has(e.id));

// ─────────────────────────────────────────────────────────────────────────────
// 1. Password spraying / fuerza bruta desde una misma IP (+ compromiso posterior)
// ─────────────────────────────────────────────────────────────────────────────
const credentialAttack: Rule = {
  id: 'CRED-SPRAY',
  name: 'Ataque de credenciales desde una IP',
  run(ctx) {
    const out: RawFinding[] = [];
    const fails = ctx.events.filter((e) => isFailedLogon(e) && e.srcIp);
    for (const [ip, evs] of groupBy(fails, (e) => e.srcIp)) {
      for (const burst of bursts(evs, THRESHOLDS.sprayWindowMin * MIN)) {
        if (burst.length < THRESHOLDS.sprayMinFailures) continue;
        const targets = nonEmpty(burst.map((e) => e.user));
        const isSpray = targets.length >= THRESHOLDS.sprayMinDistinctUsers;
        const hosts = nonEmpty(burst.map((e) => e.host));
        const external = isPublicIp(ip);
        claim(ctx, burst);
        out.push({
          ruleId: isSpray ? 'CRED-SPRAY' : 'CRED-BRUTEFORCE',
          title: isSpray ? `Password spraying desde ${ip}` : `Fuerza bruta de contraseñas desde ${ip}`,
          techniques: [isSpray ? 'T1110.003' : 'T1110.001'],
          baseScore: 55,
          baseLabel: isSpray ? 'Password spraying' : 'Fuerza bruta de contraseñas',
          extraFactors: [{ label: `${burst.length} intentos fallidos en ${Math.round((burst[burst.length - 1].t - burst[0].t) / MIN) + 1} min`, points: burst.length >= 30 ? 5 : 0 }],
          events: burst,
          correlationKeys: [`ip:${ip}`],
          targetUsers: targets,
          summary: `${burst.length} inicios de sesión fallidos desde ${ip}${external ? ' (IP externa)' : ''} contra ${targets.length} cuentas distintas en ${fmtList(hosts)} entre ${span(burst)}.`,
          technicalExplanation:
            (isSpray
              ? `El patrón corresponde a password spraying (MITRE T1110.003): una misma IP prueba pocas contraseñas contra muchas cuentas para evitar bloqueos por cuenta. `
              : `El patrón corresponde a adivinación de contraseñas (MITRE T1110.001) contra un número reducido de cuentas. `) +
            `Los eventos ${burst[0].eventId === '4625' ? '4625 (An account failed to log on)' : 'de inicio de sesión fallido'} muestran ${burst.length} fallos desde ${ip} en ${fmtList(hosts)}, rotando entre las cuentas ${fmtList(targets, 10)}. Evidencia: ${logIds(burst)}.`,
          impact: `Si alguna contraseña es débil o reutilizada, el atacante obtiene una cuenta válida del dominio${hosts.some((h) => /^DC/i.test(h)) ? ' (los intentos se registran en el controlador de dominio)' : ''}, lo que permite acceso inicial y movimiento dentro de la red. También puede provocar bloqueos masivos de cuentas (denegación de servicio a usuarios).`,
          actionPlan: {
            investigate: [
              `Revisar si existen inicios de sesión exitosos (4624) desde ${ip} en cualquier sistema después de ${hhmm(burst[0])}.`,
              `Consultar reputación y geolocalización de ${ip} y buscarla en firewall/VPN/proxy.`,
              `Verificar con los dueños de las cuentas ${fmtList(targets, 4)} si reconocen actividad.`,
            ],
            contain: [`Bloquear ${ip} en el perímetro (firewall/WAF/VPN).`, 'Forzar MFA y revisar el bloqueo de cuentas por intentos fallidos.'],
            remediate: ['Restablecer contraseñas de las cuentas afectadas que tengan inicios exitosos sospechosos.', 'Aplicar política de contraseñas robustas y deshabilitar autenticación heredada (NTLM) donde sea posible.'],
          },
        });

        // ¿Hubo éxito desde la misma IP después del ataque?
        const end = burst[burst.length - 1].t;
        const successes = ctx.events.filter(
          (e) => e.srcIp === ip && isSuccessLogon(e) && e.t >= burst[0].t && e.t <= end + THRESHOLDS.compromiseLookaheadMin * MIN,
        );
        for (const [userKey, succ] of groupBy(successes, (e) => e.userKey)) {
          const user = succ[0].user;
          const priv = ctx.events.filter(
            (e) => e.userKey === userKey && e.srcIp === ip && isPrivilegedLogon(e) && e.t >= succ[0].t && e.t <= succ[0].t + THRESHOLDS.compromiseLookaheadMin * MIN,
          );
          const evidence = [...succ, ...priv].sort(byTime);
          claim(ctx, evidence);
          const wasTarget = targets.some((t) => t.toLowerCase() === userKey);
          out.push({
            ruleId: 'CRED-COMPROMISE',
            title: `Cuenta probablemente comprometida: ${user}`,
            techniques: ['T1078', ...(external ? ['T1133'] : [])],
            baseScore: 75,
            baseLabel: 'Inicio de sesión exitoso tras ataque de credenciales',
            extraFactors: [
              ...(wasTarget ? [{ label: 'La cuenta estaba entre las atacadas', points: 5 }] : []),
              ...(priv.length ? [{ label: 'Se asignaron privilegios especiales (4672) a la sesión', points: 10 }] : []),
            ],
            events: evidence,
            correlationKeys: [`ip:${ip}`, `user:${userKey}`, ...nonEmpty(evidence.map((e) => `host:${e.hostKey}`))],
            summary: `Inicio de sesión exitoso de ${user} desde ${ip} a las ${hhmm(succ[0])}, ${Math.max(0, Math.round((succ[0].t - end) / MIN))} min después del último intento fallido del ataque${priv.length ? `, seguido de asignación de privilegios especiales en ${fmtList(nonEmpty(priv.map((e) => e.host)))}` : ''}.`,
            technicalExplanation: `Un 4624 (logon exitoso) desde la misma IP que acaba de realizar ${burst.length} intentos fallidos indica que el atacante probablemente acertó la contraseña de ${user} (MITRE T1078 Valid Accounts)${priv.length ? `. El evento 4672 (Special privileges assigned to new logon) muestra que la sesión obtuvo privilegios elevados` : ''}. Evidencia: ${logIds(evidence)}.`,
            impact: `Un atacante externo con credenciales válidas de ${user} puede acceder a recursos internos con los permisos de esa cuenta${priv.length ? ' (incluyendo privilegios administrativos)' : ''}, desplegar persistencia o robar información.`,
            actionPlan: {
              investigate: [
                `Reconstruir toda la actividad de ${user} posterior a ${hhmm(succ[0])} (procesos 4688, accesos a recursos, nuevos logons).`,
                `Identificar desde qué equipos se usó la cuenta y si hubo movimiento lateral.`,
              ],
              contain: [`Deshabilitar temporalmente la cuenta ${user} y cerrar sus sesiones activas.`, `Bloquear ${ip} y aislar los equipos donde la cuenta inició sesión.`],
              remediate: [`Restablecer la contraseña de ${user} (y revocar tickets Kerberos/tokens).`, 'Habilitar MFA obligatorio para accesos remotos y cuentas privilegiadas.'],
            },
          });
        }
      }
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 2. Fuerza bruta dirigida (misma IP + usuario) seguida de éxito; RDP externo
// ─────────────────────────────────────────────────────────────────────────────
const targetedBruteForce: Rule = {
  id: 'CRED-GUESS-SUCCESS',
  name: 'Fuerza bruta dirigida exitosa',
  run(ctx) {
    const out: RawFinding[] = [];
    const fails = unclaimed(ctx, ctx.events.filter((e) => isFailedLogon(e) && e.srcIp));
    for (const [, evs] of groupBy(fails, (e) => `${e.srcIp}|${e.userKey}`)) {
      for (const burst of bursts(evs, THRESHOLDS.guessWindowMin * MIN)) {
        if (burst.length < THRESHOLDS.guessMinFailures) continue;
        const last = burst[burst.length - 1];
        const ip = last.srcIp;
        const success = ctx.events.find(
          (e) => isSuccessLogon(e) && e.srcIp === ip && e.userKey === last.userKey && e.t >= last.t && e.t <= last.t + THRESHOLDS.guessWindowMin * MIN,
        );
        if (!success) continue;
        const priv = ctx.events.filter(
          (e) => isPrivilegedLogon(e) && e.userKey === last.userKey && e.host === success.host && e.t >= success.t && e.t <= success.t + 30 * MIN,
        );
        const evidence = [...burst, success, ...priv].sort(byTime);
        claim(ctx, evidence);
        const rdp = [...burst, success].some((e) => logonType(e) === 10 || /rdp/i.test(e.desc));
        const external = isPublicIp(ip);
        out.push({
          ruleId: rdp ? 'CRED-RDP-BRUTEFORCE' : 'CRED-GUESS-SUCCESS',
          title: rdp ? `Acceso RDP${external ? ' externo' : ''} por fuerza bruta a ${success.host} (${success.user})` : `Fuerza bruta exitosa contra ${success.user} desde ${ip}`,
          techniques: ['T1110.001', 'T1078', ...(rdp ? ['T1021.001'] : []), ...(rdp && external ? ['T1133'] : [])],
          baseScore: 75,
          baseLabel: 'Contraseña adivinada: fallos seguidos de éxito',
          extraFactors: priv.length ? [{ label: 'Se asignaron privilegios especiales (4672) a la sesión', points: 10 }] : [],
          events: evidence,
          summary: `${burst.length} intentos fallidos${rdp ? ' por RDP (LogonType=10)' : ''} de ${success.user} desde ${ip} y luego un inicio de sesión exitoso en ${success.host} a las ${hhmm(success)}${priv.length ? ', con privilegios especiales asignados' : ''}.`,
          technicalExplanation: `La secuencia ${burst[0].eventId}×${burst.length} → 4624 desde la misma IP y para la misma cuenta en pocos minutos es la firma de una contraseña adivinada (MITRE T1110.001) y uso de una cuenta válida (T1078).${rdp ? ` El tipo de logon 10 indica Escritorio Remoto (T1021.001)${external ? ' expuesto a Internet (T1133 External Remote Services)' : ''}.` : ''} Evidencia: ${logIds(evidence)}.`,
          impact: `El atacante tiene una sesión interactiva en ${success.host} con la cuenta ${success.user}${priv.length ? ' con privilegios elevados' : ''}: puede ejecutar comandos, instalar herramientas, moverse a otros servidores y extraer información.`,
          actionPlan: {
            investigate: [
              `Revisar todos los procesos (4688) y conexiones originados en ${success.host} por ${success.user} desde ${hhmm(success)}.`,
              rdp ? `Confirmar por qué ${success.host} acepta RDP desde ${external ? 'Internet' : ip}.` : `Verificar si ${ip} es un equipo autorizado.`,
            ],
            contain: [`Aislar ${success.host} de la red.`, `Deshabilitar ${success.user} y cerrar sus sesiones.`, `Bloquear ${ip}.`],
            remediate: [
              rdp ? 'Cerrar RDP a Internet; publicarlo solo detrás de VPN/Gateway con MFA.' : 'Habilitar MFA y bloqueo por intentos fallidos.',
              `Restablecer la contraseña de ${success.user} y revisar si se reutiliza en otros sistemas.`,
            ],
          },
        });
      }
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 3. Web shell / explotación de aplicación pública
// ─────────────────────────────────────────────────────────────────────────────
const WEB_SHELL_URI = /\/(uploads?|files|images|tmp|temp)\/[^?\s]*\.(aspx?|php\d?|jsp|jspx|cfm|ashx)\b.*[?&](cmd|exec|command|c|q)=/i;
const WEB_WORKER_USER = /^(iis apppool\\|nt authority\\iusr|www-data|apache|nginx)/i;

const webShell: Rule = {
  id: 'WEB-SHELL',
  name: 'Web shell en servidor web',
  run(ctx) {
    const out: RawFinding[] = [];
    const requests = ctx.events.filter((e) => WEB_SHELL_URI.test(e.cmd) || WEB_SHELL_URI.test(e.desc));
    const spawned = ctx.events.filter((e) => WEB_WORKER_USER.test(e.user) && /(cmd|powershell|pwsh|whoami|net)(\.exe)?\b/i.test(`${e.cmd} ${e.desc}`));
    for (const [host, evs] of groupBy([...requests, ...spawned], (e) => e.hostKey)) {
      const evidence = uniq(evs).sort(byTime);
      claim(ctx, evidence);
      const hostName = evidence[0].host;
      const ips = nonEmpty(evidence.map((e) => e.srcIp));
      const exec = evidence.filter((e) => WEB_WORKER_USER.test(e.user));
      const uris = nonEmpty(evidence.filter((e) => !WEB_WORKER_USER.test(e.user)).map((e) => e.cmd));
      out.push({
        ruleId: 'WEB-SHELL',
        title: exec.length ? `Web shell con ejecución de comandos en ${hostName}` : `Posible web shell en ${hostName}`,
        techniques: ['T1190', 'T1505.003', ...(exec.length ? ['T1059.003'] : [])],
        baseScore: exec.length ? 80 : 60,
        baseLabel: exec.length ? 'Web shell con ejecución confirmada en el servidor' : 'Peticiones a script sospechoso en carpeta de subidas',
        events: evidence,
        correlationKeys: [...ips.filter(isPublicIp).map((i) => `ip:${i}`), `host:${host}`],
        summary: `Peticiones HTTP a ${fmtList(uris, 3)} desde ${fmtList(ips)}${exec.length ? ` y ejecución de "${exec[0].cmd}" bajo la identidad ${exec[0].user} a las ${hhmm(exec[0])}` : ''}.`,
        technicalExplanation: `Un script de servidor (${uris[0] ?? 'script'}) ubicado en una carpeta de subidas y que recibe un parámetro de comando es el patrón típico de una web shell (MITRE T1505.003), normalmente colocada explotando la aplicación web (T1190).${exec.length ? ` El proceso ejecutado por la cuenta del pool de aplicaciones (${exec[0].user}) confirma que el servidor ejecutó comandos del sistema (T1059.003).` : ' No hay evidencia en los logs de ejecución de procesos asociada.'} Evidencia: ${logIds(evidence)}.`,
        impact: `Control remoto del servidor web ${hostName} con los permisos del servicio web; punto de entrada para robar datos de la aplicación, pivotar a la red interna o desplegar malware.`,
        actionPlan: {
          investigate: [`Localizar el archivo en ${hostName} (${uris[0] ?? 'carpeta de subidas'}), calcular su hash y revisar fecha de creación.`, `Revisar todos los logs IIS de ${fmtList(ips)} y procesos hijos de w3wp.exe.`],
          contain: [`Retirar ${hostName} de publicación o bloquear la ruta en el WAF.`, `Bloquear ${fmtList(ips)}.`],
          remediate: ['Eliminar la web shell y restaurar la aplicación desde una fuente confiable.', 'Impedir la ejecución de scripts en carpetas de subida y validar tipos de archivo en la aplicación.'],
        },
      });
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 4. Escaneo / ataque contra aplicación web (rutas administrativas, login)
// ─────────────────────────────────────────────────────────────────────────────
const WEB_SENSITIVE_PATH = /^\/(admin|administrator|wp-admin|wp-login|phpmyadmin|manager|login|signin|\.env|\.git|api\/[^\s]*export|backup|config)/i;
const webScan: Rule = {
  id: 'WEB-SCAN',
  name: 'Escaneo / ataque a aplicación web',
  run(ctx) {
    const out: RawFinding[] = [];
    const web = unclaimed(
      ctx,
      ctx.events.filter((e) => /^(iis|http|web|apache|nginx|waf)/i.test(e.logSource) || /^HTTP_/i.test(e.eventId)),
    ).filter((e) => WEB_SENSITIVE_PATH.test(e.cmd));
    for (const [ip, evs] of groupBy(web, (e) => e.srcIp)) {
      for (const burst of bursts(evs, THRESHOLDS.webScanWindowMin * MIN)) {
        if (burst.length < THRESHOLDS.webScanMinRequests) continue;
        claim(ctx, burst);
        const byPath = groupBy(burst, (e) => e.cmd.split('?')[0] + (e.cmd.includes('user=') ? '?user=…' : ''));
        const codes = groupBy(burst, (e) => e.result);
        const pathSummary = [...byPath].map(([p, l]) => `${p} (${l.length})`).join(', ');
        const codeSummary = [...codes].map(([c, l]) => `${c}: ${l.length}`).join(', ');
        const loginAttempts = burst.filter((e) => /login|signin/i.test(e.cmd));
        out.push({
          ruleId: 'WEB-SCAN',
          title: `Sondeo de rutas sensibles en aplicación web desde ${ip}`,
          techniques: ['T1595.003', ...(loginAttempts.length >= 3 ? ['T1110.001'] : [])],
          baseScore: 45,
          baseLabel: 'Peticiones repetidas a rutas administrativas/login',
          events: burst,
          correlationKeys: [`ip:${ip}`],
          summary: `${burst.length} peticiones HTTP desde ${ip} a ${fmtList(nonEmpty(burst.map((e) => e.host)))} entre ${span(burst)}: ${pathSummary}. Códigos de respuesta: ${codeSummary}.`,
          technicalExplanation: `Peticiones automatizadas y repetidas a rutas administrativas, de autenticación o exportación de datos son típicas de reconocimiento por diccionario (MITRE T1595.003)${loginAttempts.length >= 3 ? ` y de intentos de acceso a la cuenta "admin" de la aplicación (T1110.001, ${loginAttempts.length} peticiones a login)` : ''}. Las respuestas 500 pueden indicar errores provocados por entradas maliciosas. Los logs no permiten confirmar si alguna autenticación fue exitosa. Evidencia: ${logIds(burst)}.`,
          impact: 'Exposición de la superficie administrativa de la aplicación; si las respuestas 200 a rutas de exportación devolvieron datos, podría haber fuga de información de la aplicación.',
          actionPlan: {
            investigate: [`Revisar el contenido/tamaño de las respuestas 200 a ${ip}, en especial en endpoints de exportación.`, 'Revisar logs de la aplicación (autenticación) en el mismo intervalo.'],
            contain: [`Bloquear ${ip} en el WAF/firewall.`, 'Restringir rutas administrativas a redes internas.'],
            remediate: ['Implementar WAF con limitación de tasa y MFA para el panel administrativo.', 'Corregir los errores 500 (validación de entradas).'],
          },
        });
      }
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 5. PowerShell ofuscado / codificado
// ─────────────────────────────────────────────────────────────────────────────
const ENCODED_PS = /(powershell|pwsh)(\.exe)?\b.*(\s-(e|ec|en|enc|enco|encodedcommand)\b|frombase64string)/i;
const encodedPowershell: Rule = {
  id: 'EXEC-ENCODED-PS',
  name: 'PowerShell codificado',
  run(ctx) {
    const out: RawFinding[] = [];
    const hits = unclaimed(ctx, ctx.events.filter((e) => ENCODED_PS.test(e.cmd)));
    for (const [, evs] of groupBy(hits, (e) => `${e.hostKey}|${e.userKey}`)) {
      claim(ctx, evs);
      const e0 = evs[0];
      const parent = /parent=([\w.]+)/i.exec(e0.desc)?.[1];
      out.push({
        ruleId: 'EXEC-ENCODED-PS',
        title: `PowerShell con comando codificado en ${e0.host} (${e0.user})`,
        techniques: ['T1059.001', 'T1027.010'],
        baseScore: 60,
        baseLabel: 'Ejecución de PowerShell con -EncodedCommand',
        events: evs,
        summary: `${e0.user} ejecutó PowerShell con -NoProfile -EncodedCommand en ${e0.host} a las ${hhmm(e0)}${parent ? ` (proceso padre: ${parent})` : ''}.`,
        technicalExplanation: `El parámetro -EncodedCommand ejecuta un script en Base64, técnica usada para ocultar el contenido real del comando (MITRE T1027.010) dentro de PowerShell (T1059.001); -NoProfile evita cargar configuraciones del usuario. El contenido codificado no está disponible en el log (aparece redactado), por lo que no se puede determinar qué ejecutó. Evidencia: ${logIds(evs)}.`,
        impact: 'Ejecución de código arbitrario no visible para el analista; suele ser descarga de herramientas, reconocimiento o establecimiento de persistencia.',
        actionPlan: {
          investigate: [`Recuperar el script decodificado (logs 4104 Script Block, EDR o memoria) de ${e0.host}.`, `Revisar procesos hijos y conexiones de red de PowerShell en ${e0.host} alrededor de ${hhmm(e0)}.`],
          contain: [`Aislar ${e0.host} si el contenido no corresponde a una tarea administrativa documentada.`],
          remediate: ['Habilitar Script Block Logging y Constrained Language Mode / AMSI.', 'Restringir PowerShell a administradores mediante AppLocker/WDAC.'],
        },
      });
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 6. Descubrimiento (reconocimiento interno)
// ─────────────────────────────────────────────────────────────────────────────
const DISCOVERY: { re: RegExp; tech: string; label: string }[] = [
  { re: /\bwhoami\b/i, tech: 'T1033', label: 'whoami' },
  { re: /get-localgroupmember|net1?(\.exe)?\s+localgroup/i, tech: 'T1069.001', label: 'enumeración de grupos locales' },
  { re: /net1?(\.exe)?\s+view|get-smbshare|net1?(\.exe)?\s+share/i, tech: 'T1135', label: 'enumeración de recursos compartidos' },
];
const discovery: Rule = {
  id: 'DISC-RECON',
  name: 'Comandos de descubrimiento',
  run(ctx) {
    const out: RawFinding[] = [];
    const hits = unclaimed(ctx, ctx.events.filter((e) => DISCOVERY.some((d) => d.re.test(`${e.cmd} ${e.desc}`))));
    for (const [, evs] of groupBy(hits, (e) => `${e.hostKey}|${e.userKey}`)) {
      for (const burst of bursts(evs, 30 * MIN)) {
        claim(ctx, burst);
        const text = burst.map((e) => `${e.cmd} ${e.desc}`).join(' ');
        const matched = DISCOVERY.filter((d) => d.re.test(text));
        const e0 = burst[0];
        out.push({
          ruleId: 'DISC-RECON',
          title: `Reconocimiento interno en ${e0.host} (${e0.user})`,
          techniques: uniq(matched.map((m) => m.tech)),
          baseScore: 40,
          baseLabel: 'Comandos de descubrimiento',
          extraFactors: matched.length >= 2 ? [{ label: `${matched.length} técnicas de descubrimiento distintas`, points: 10 }] : [],
          events: burst,
          summary: `${e0.user} ejecutó en ${e0.host} (${span(burst)}): ${burst.map((e) => (e.cmd && !/^powershell\.exe$/i.test(e.cmd) ? e.cmd : e.desc)).join(' | ')}.`,
          technicalExplanation: `Los comandos (${matched.map((m) => m.label).join(', ')}) sirven para conocer privilegios, administradores y recursos compartidos del entorno; son pasos habituales tras obtener acceso (táctica Discovery: ${uniq(matched.map((m) => m.tech)).join(', ')}). Por sí solos pueden ser administrativos; su relevancia aumenta si ocurren junto a otros hallazgos. Evidencia: ${logIds(burst)}.`,
          impact: 'El atacante identifica cuentas privilegiadas y servidores con información (p. ej. servidores de archivos) para su siguiente movimiento.',
          actionPlan: {
            investigate: [`Confirmar si ${e0.user} tenía una tarea administrativa que justifique los comandos en ${e0.host}.`],
            contain: ['Si no está justificado, tratar la sesión como comprometida (aislar equipo y deshabilitar cuenta).'],
            remediate: ['Restringir herramientas de administración a cuentas y equipos de administración dedicados (tiering).'],
          },
        });
      }
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 7. Movimiento lateral por SMB (logon de red desde otro equipo + acceso a share)
// ─────────────────────────────────────────────────────────────────────────────
const lateralSmb: Rule = {
  id: 'LAT-SMB',
  name: 'Movimiento lateral por SMB',
  run(ctx) {
    const out: RawFinding[] = [];
    const netLogons = ctx.events.filter((e) => isSuccessLogon(e) && logonType(e) === 3 && /source=/i.test(e.desc));
    for (const logon of netLogons) {
      const from = /source=([\w.-]+)/i.exec(logon.desc)?.[1] ?? logon.srcIp;
      const priorFails = ctx.events.filter(
        (e) => isFailedLogon(e) && e.userKey === logon.userKey && e.hostKey === logon.hostKey && e.t <= logon.t && e.t >= logon.t - 15 * MIN,
      );
      const access = ctx.events.filter(
        (e) => ['5140', '5145', '4663'].includes(e.eventId) && e.userKey === logon.userKey && e.hostKey === logon.hostKey && e.t >= logon.t && e.t <= logon.t + 15 * MIN,
      );
      if (!access.length) continue;
      const evidence = [...priorFails, logon, ...access].sort(byTime);
      claim(ctx, evidence);
      const sensitive = access.filter((e) => SENSITIVE_DATA.test(`${e.dest} ${e.desc} ${e.cmd}`));
      out.push({
        ruleId: 'LAT-SMB',
        title: `Movimiento lateral SMB de ${from} a ${logon.host} (${logon.user})`,
        techniques: ['T1021.002', 'T1078', ...(sensitive.length ? ['T1039'] : [])],
        baseScore: 60,
        baseLabel: 'Logon de red entre equipos seguido de acceso a recursos compartidos',
        extraFactors: sensitive.length ? [{ label: 'Acceso a información sensible', points: 10 }] : [],
        events: evidence,
        // El servidor destino (p. ej. un file server) es compartido por muchos usuarios: no se usa como clave de correlación
        correlationKeys: [`user:${logon.userKey}`, `host:${from.toUpperCase().replace(/[^A-Z0-9]/g, '')}`],
        summary: `${logon.user} inició sesión de red (LogonType=3) en ${logon.host} desde ${from} a las ${hhmm(logon)}${priorFails.length ? ` tras ${priorFails.length} intento(s) fallido(s)` : ''} y accedió a: ${access.map((e) => e.desc).join(' | ')}.`,
        technicalExplanation: `Un logon de red (tipo 3) originado en otro servidor seguido de eventos 5140/5145 (acceso a recurso compartido / archivo) es el patrón de movimiento lateral mediante recursos compartidos de Windows (MITRE T1021.002) usando credenciales válidas (T1078)${sensitive.length ? `, con acceso a información sensible (T1039 Data from Network Shared Drive)` : ''}. Evidencia: ${logIds(evidence)}.`,
        impact: `Acceso a datos del servidor ${logon.host}${sensitive.length ? ` incluyendo ${fmtList(nonEmpty(sensitive.map((e) => e.desc.replace(/^.*?:\s*/, ''))), 3)}` : ''}; confidencialidad de la información comprometida.`,
        actionPlan: {
          investigate: [`Determinar qué archivos se leyeron/copiaron en ${logon.host} y si se transfirieron a ${from}.`, `Revisar la actividad de ${logon.user} en ${from} antes de ${hhmm(logon)}.`],
          contain: [`Bloquear SMB entre ${from} y ${logon.host} y deshabilitar ${logon.user}.`],
          remediate: ['Segmentar la red para limitar SMB entre servidores.', 'Aplicar mínimo privilegio sobre los recursos compartidos sensibles.'],
        },
      });
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 8. Acceso masivo a archivos en recursos compartidos
// ─────────────────────────────────────────────────────────────────────────────
const massFileAccess: Rule = {
  id: 'COLL-MASS-ACCESS',
  name: 'Acceso masivo a archivos',
  run(ctx) {
    const out: RawFinding[] = [];
    const access = unclaimed(ctx, ctx.events.filter((e) => ['4663', '5145', '5140'].includes(e.eventId) && /file access|\\[^\\]+\.\w{2,5}$/i.test(`${e.cmd} ${e.desc}`)));
    for (const [, evs] of groupBy(access, (e) => `${e.userKey}|${e.hostKey}`)) {
      for (const burst of bursts(evs, THRESHOLDS.massAccessWindowMin * MIN)) {
        const files = nonEmpty(burst.map((e) => e.cmd || e.desc));
        if (files.length < THRESHOLDS.massAccessMinFiles) continue;
        claim(ctx, burst);
        const e0 = burst[0];
        const sensitive = SENSITIVE_DATA.test(`${files.join(' ')} ${e0.dest}`);
        out.push({
          ruleId: 'COLL-MASS-ACCESS',
          title: `Acceso masivo a archivos en ${e0.dest || e0.host} por ${e0.user}`,
          techniques: ['T1039'],
          baseScore: 50,
          baseLabel: `Lectura de ${files.length} archivos en pocos minutos`,
          extraFactors: sensitive ? [{ label: 'Carpeta con información sensible', points: 10 }] : [],
          events: burst,
          // El Hostname es el servidor de archivos accedido (recurso compartido por todos): se correlaciona por usuario
          correlationKeys: [`user:${e0.userKey}`],
          summary: `${e0.user} (desde ${e0.srcIp}) accedió a ${files.length} archivos en ${e0.dest || e0.host} entre ${span(burst)} (p. ej. ${files.slice(0, 3).join('; ')}).`,
          technicalExplanation: `La lectura secuencial y rápida de muchos archivos de una misma carpeta compartida (un archivo cada pocos segundos) no corresponde a uso humano normal y es típica de recolección automatizada de datos (MITRE T1039) previa a exfiltración o cifrado. Evidencia: ${logIds(burst)}.`,
          impact: `Posible robo o preparación para cifrado de ${files.length} documentos${sensitive ? ' de un área sensible' : ''}.`,
          actionPlan: {
            investigate: [`Verificar si ${e0.user} es una cuenta de servicio con una tarea programada legítima de respaldo en ese horario.`, `Revisar actividad del equipo ${e0.srcIp} en el mismo intervalo.`],
            contain: [`Revocar temporalmente el acceso de ${e0.user} a ${e0.dest || 'el recurso'} si la actividad no está justificada.`],
            remediate: ['Restringir permisos de cuentas de servicio al mínimo necesario y monitorear accesos masivos (alertas por umbral).'],
          },
        });
      }
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 9. Eliminación de copias de seguridad (precursor de ransomware)
// ─────────────────────────────────────────────────────────────────────────────
const INHIBIT = /vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete|bcdedit(\.exe)?.*recoveryenabled\s+no|delete-?shadow/i;
const inhibitRecovery: Rule = {
  id: 'IMPACT-INHIBIT-RECOVERY',
  name: 'Eliminación de shadow copies',
  run(ctx) {
    const hits = unclaimed(ctx, ctx.events.filter((e) => INHIBIT.test(e.cmd)));
    return [...groupBy(hits, (e) => e.hostKey)].map(([, evs]) => {
      claim(ctx, evs);
      const e0 = evs[0];
      return {
        ruleId: 'IMPACT-INHIBIT-RECOVERY',
        title: `Eliminación de copias de recuperación en ${e0.host}`,
        techniques: ['T1490'],
        baseScore: 85,
        baseLabel: 'Borrado de shadow copies / recuperación',
        events: evs,
        summary: `${e0.user} ejecutó "${e0.cmd}" en ${e0.host} a las ${hhmm(e0)}.`,
        technicalExplanation: `Borrar las Volume Shadow Copies impide restaurar archivos y es uno de los pasos previos más característicos del cifrado por ransomware (MITRE T1490 Inhibit System Recovery). No es una operación habitual de una cuenta de usuario o servicio. Evidencia: ${logIds(evs)}.`,
        impact: 'Pérdida de la capacidad de recuperación local; alta probabilidad de un evento de ransomware o sabotaje inminente.',
        actionPlan: {
          investigate: [`Buscar en ${e0.host} y en servidores accesibles por ${e0.user} señales de cifrado (extensiones nuevas, notas de rescate).`, 'Verificar el estado de los respaldos fuera de línea.'],
          contain: [`Aislar inmediatamente ${e0.host}.`, `Deshabilitar ${e0.user} en todo el dominio.`],
          remediate: ['Restaurar desde respaldos inmutables/fuera de línea verificados.', 'Restringir vssadmin/wbadmin a administradores y alertar su uso.'],
        },
      } satisfies RawFinding;
    });
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 10. Persistencia: tareas programadas y servicios
// ─────────────────────────────────────────────────────────────────────────────
const persistence: Rule = {
  id: 'PERSIST',
  name: 'Persistencia (tareas / servicios)',
  run(ctx) {
    const out: RawFinding[] = [];
    const created = unclaimed(
      ctx,
      ctx.events.filter((e) => ['4698', '7045', '4697'].includes(e.eventId) || /scheduled task was created|service was installed/i.test(e.desc)),
    );
    for (const e of created) {
      const isTask = e.eventId === '4698' || /scheduled task/i.test(e.desc);
      const name = /(?:TaskName|ServiceName)=([^;]+)/i.exec(e.cmd)?.[1]?.trim() ?? '(sin nombre en el log)';
      const action = /(?:Action|ImagePath)=(.+)$/i.exec(e.cmd)?.[1]?.trim() ?? e.cmd;
      const suspiciousPath = SUSPICIOUS_PATH.test(action);
      const masquerade = /microsoft|windows|update|svchost|defender/i.test(name);
      const binary = /([a-z]:\\[^\s;]+\.(exe|ps1|bat|dll))/i.exec(action)?.[1];
      // Ejecuciones posteriores del mismo binario (demuestra que la persistencia está activa)
      const executions = binary
        ? ctx.events.filter((x) => x.id !== e.id && x.hostKey === e.hostKey && x.cmd.toLowerCase().includes(binary.toLowerCase()) && x.t >= e.t)
        : [];
      const evidence = [e, ...executions].sort(byTime);
      claim(ctx, evidence);
      out.push({
        ruleId: isTask ? 'PERSIST-SCHEDULED-TASK' : 'PERSIST-SERVICE',
        title: isTask ? `Tarea programada sospechosa "${name}" en ${e.host}` : `Servicio sospechoso "${name}" instalado en ${e.host}`,
        techniques: [isTask ? 'T1053.005' : 'T1543.003', ...(masquerade ? ['T1036.004'] : []), ...(/powershell/i.test(action) ? ['T1059.001'] : [])],
        baseScore: 55,
        baseLabel: isTask ? 'Creación de tarea programada' : 'Instalación de servicio',
        extraFactors: [
          ...(suspiciousPath ? [{ label: 'Ejecutable en ruta no estándar (ProgramData/Temp/Public)', points: 10 }] : []),
          ...(masquerade ? [{ label: 'Nombre que imita componentes legítimos de Windows', points: 5 }] : []),
          ...(executions.length ? [{ label: `El binario se ejecutó ${executions.length} vez/veces después`, points: 5 }] : []),
        ],
        events: evidence,
        summary: `${e.user} ${isTask ? 'creó la tarea programada' : 'instaló el servicio'} "${name}" en ${e.host} a las ${hhmm(e)} que ejecuta ${action}${executions.length ? `; el binario se ejecutó ${executions.length} veces entre ${span(executions)}` : ''}.`,
        technicalExplanation: `${isTask ? 'Las tareas programadas (evento 4698, MITRE T1053.005)' : 'Los servicios nuevos (evento 7045, MITRE T1543.003)'} permiten que un programa se ejecute automáticamente y sobreviva a reinicios.${suspiciousPath ? ` El ejecutable está en ${action}, una ruta escribible por usuarios y poco habitual para software legítimo.` : ''}${masquerade ? ` El nombre "${name}" imita componentes de Windows para pasar desapercibido (T1036.004).` : ''}${executions.length ? ` Las ejecuciones periódicas posteriores confirman que el mecanismo está activo.` : ''} Evidencia: ${logIds(evidence)}.`,
        impact: `Acceso persistente del atacante a ${e.host} aunque se cambien contraseñas o se reinicie el equipo; posible ejecución periódica de malware.`,
        actionPlan: {
          investigate: [`Obtener ${binary ?? 'el ejecutable'} de ${e.host}, calcular su hash y analizarlo (sandbox / VirusTotal).`, `Verificar si ${e.user} tenía un cambio aprobado que justifique la creación.`],
          contain: [`Deshabilitar ${isTask ? 'la tarea' : 'el servicio'} "${name}" y aislar ${e.host}.`],
          remediate: [`Eliminar ${isTask ? 'la tarea' : 'el servicio'} y el binario; revisar otras persistencias (Run keys, WMI).`, `Restablecer credenciales de ${e.user}.`],
        },
      });
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 11. Compresión de datos para extracción (staging)
// ─────────────────────────────────────────────────────────────────────────────
const ARCHIVE = /\b(7z|7za|7zr|rar|winrar)(\.exe)?\s+a\b|\btar(\.exe)?\s+[^|]*-[a-z]*c[a-z]*\b|compress-archive|\bzip(\.exe)?\s+-r\b/i;
const archiveStaging: Rule = {
  id: 'COLL-ARCHIVE',
  name: 'Compresión de datos',
  run(ctx) {
    const hits = unclaimed(ctx, ctx.events.filter((e) => ARCHIVE.test(e.cmd)));
    return hits.map((e) => {
      claim(ctx, [e]);
      const sensitive = SENSITIVE_DATA.test(e.cmd);
      const staging = SUSPICIOUS_PATH.test(e.cmd) || /\\temp\\|\\public\\/i.test(e.cmd);
      return {
        ruleId: 'COLL-ARCHIVE',
        title: `Compresión de datos${sensitive ? ' sensibles' : ''} en ${e.host} (${e.user})`,
        techniques: ['T1560.001', ...(staging ? ['T1074.001'] : [])],
        baseScore: 50,
        baseLabel: 'Empaquetado de archivos con utilidad de compresión',
        extraFactors: [
          ...(sensitive ? [{ label: 'Origen con información sensible (Finanzas/Legal/RR.HH.)', points: 10 }] : []),
          ...(staging ? [{ label: 'Archivo resultante en carpeta temporal/pública (staging)', points: 5 }] : []),
        ],
        events: [e],
        summary: `${e.user} ejecutó "${e.cmd}" en ${e.host} a las ${hhmm(e)}.`,
        technicalExplanation: `Comprimir carpetas completas en un único archivo, especialmente en rutas temporales o públicas, es la preparación típica para extraer información (MITRE T1560.001 Archive via Utility${staging ? ', T1074.001 Local Data Staging' : ''}). Evidencia: ${e.logId}.`,
        impact: `Preparación para exfiltrar ${sensitive ? 'información sensible de la organización' : 'información'}; si se confirma la salida, implica una fuga de datos con posibles obligaciones legales.`,
        actionPlan: {
          investigate: [`Verificar si el archivo comprimido aún existe en ${e.host} y su contenido.`, `Revisar conexiones salientes de ${e.host} en los minutos siguientes.`],
          contain: [`Bloquear la salida a Internet de ${e.host} y suspender la cuenta ${e.user} si no está justificado.`],
          remediate: ['Implementar DLP y alertas sobre compresión de carpetas sensibles.'],
        },
      } satisfies RawFinding;
    });
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 12. Exfiltración por volumen (proxy / firewall con bytes_out)
// ─────────────────────────────────────────────────────────────────────────────
const exfilVolume: Rule = {
  id: 'EXFIL-VOLUME',
  name: 'Exfiltración por volumen',
  run(ctx) {
    const out: RawFinding[] = [];
    const transfers = ctx.events.filter((e) => bytesOut(e) > 0 && isPublicIp(ipOf(e.dest)));
    for (const [, evs] of groupBy(transfers, (e) => `${e.hostKey || e.srcIp}|${ipOf(e.dest)}`)) {
      for (const burst of bursts(evs, THRESHOLDS.exfilWindowMin * MIN)) {
        const total = burst.reduce((s, e) => s + bytesOut(e), 0);
        if (total < THRESHOLDS.exfilMinBytes && burst.length < THRESHOLDS.exfilMinRequests) continue;
        claim(ctx, burst);
        const e0 = burst[0];
        const chunked = burst.length >= 5;
        out.push({
          ruleId: 'EXFIL-VOLUME',
          title: `Exfiltración de ${mb(total)} desde ${e0.host} hacia ${e0.dest}`,
          techniques: ['T1048.002', ...(chunked ? ['T1030'] : [])],
          baseScore: 75,
          baseLabel: 'Gran volumen de datos enviado a destino externo',
          extraFactors: total >= 200 * 1024 * 1024 ? [{ label: `Volumen superior a 200 MB (${mb(total)})`, points: 10 }] : [],
          events: burst,
          correlationKeys: [`host:${e0.hostKey}`, `user:${e0.userKey}`, `ip:${ipOf(e0.dest)}`],
          summary: `${burst.length} envíos (${e0.desc || 'POST'}) desde ${e0.host} (${e0.user}, ${e0.srcIp}) a ${e0.dest} entre ${span(burst)}, total ${mb(total)}.`,
          technicalExplanation: `Los registros del ${e0.logSource || 'proxy'} muestran ${burst.length} subidas consecutivas con bytes_out entre ${mb(Math.min(...burst.map(bytesOut)))} y ${mb(Math.max(...burst.map(bytesOut)))} hacia un destino externo por HTTPS. Enviar grandes volúmenes en fragmentos de tamaño similar es característico de exfiltración sobre canal cifrado (MITRE T1048.002)${chunked ? ' con límite de tamaño por transferencia (T1030)' : ''}. Evidencia: ${logIds(burst)}.`,
          impact: `Fuga confirmada de aproximadamente ${mb(total)} de información hacia un tercero no autorizado: riesgo legal, regulatorio y reputacional.`,
          actionPlan: {
            investigate: [`Identificar qué datos salieron (relacionar con archivos comprimidos o accesos previos de ${e0.user}).`, `Investigar el destino ${e0.dest} (reputación, dominio, propietario).`],
            contain: [`Bloquear ${ipOf(e0.dest)} en proxy/firewall y aislar ${e0.host}.`, `Suspender la cuenta ${e0.user}.`],
            remediate: ['Activar el proceso de gestión de brechas de datos (legal/cumplimiento).', 'Implementar DLP y alertas por volumen de subida por usuario.'],
          },
        });
      }
    }
    return out;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 13. Conexión saliente de un intérprete de comandos a IP externa
// ─────────────────────────────────────────────────────────────────────────────
const SCRIPT_PROC = /\b(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin)(\.exe)?\b/i;
const suspiciousOutbound: Rule = {
  id: 'C2-OUTBOUND',
  name: 'Conexión saliente sospechosa',
  run(ctx) {
    const hits = unclaimed(
      ctx,
      ctx.events.filter((e) => isPublicIp(ipOf(e.dest) || ipOf(e.desc)) && SCRIPT_PROC.test(`${e.cmd} ${e.desc}`) && /connection|outbound|5156/i.test(`${e.eventId} ${e.desc}`)),
    );
    return hits.map((e) => {
      claim(ctx, [e]);
      const dst = e.dest || ipOf(e.desc);
      const proc = SCRIPT_PROC.exec(`${e.cmd} ${e.desc}`)?.[0] ?? 'proceso';
      // ¿Hubo compresión de datos en el mismo equipo/usuario en la hora previa?
      const prior = ctx.events.filter((x) => ARCHIVE.test(x.cmd) && (x.hostKey === e.hostKey || x.userKey === e.userKey) && x.t <= e.t && x.t >= e.t - 60 * MIN);
      return {
        ruleId: 'C2-OUTBOUND',
        title: `Conexión saliente de ${proc} a ${dst} desde ${e.host}`,
        techniques: ['T1071.001', ...(prior.length ? ['T1041'] : [])],
        baseScore: 60,
        baseLabel: 'Intérprete de comandos conectando a IP externa',
        extraFactors: prior.length ? [{ label: `Precedida por compresión de datos (${prior.map((p) => p.logId).join(', ')})`, points: 10 }] : [],
        events: [e],
        summary: `El firewall permitió una conexión de ${proc} en ${e.host} (${e.user}) hacia ${dst} a las ${hhmm(e)}${prior.length ? `, ${Math.round((e.t - prior[prior.length - 1].t) / MIN)} min después de comprimir datos` : ''}.`,
        technicalExplanation: `Los intérpretes de comandos rara vez necesitan conectarse directamente a IPs de Internet; hacerlo es típico de descarga de herramientas o canal de comando y control sobre HTTPS (MITRE T1071.001)${prior.length ? '. Al ocurrir justo después de empaquetar datos en el mismo equipo, es consistente con exfiltración por ese canal (T1041), aunque el log no indica el volumen transferido' : ''}. Evidencia: ${e.logId}.`,
        impact: 'Canal de control remoto o de salida de datos establecido desde la red interna.',
        actionPlan: {
          investigate: [`Revisar volumen y duración de la conexión a ${dst} en proxy/NetFlow.`, `Buscar ${ipOf(dst)} en todo el entorno (otros equipos que la contacten).`],
          contain: [`Bloquear ${ipOf(dst)} y aislar ${e.host}.`],
          remediate: ['Forzar salida a Internet solo a través de proxy autenticado y bloquear conexiones directas de intérpretes.'],
        },
      } satisfies RawFinding;
    });
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 14. Acceso a recursos compartidos sensibles (residual)
// ─────────────────────────────────────────────────────────────────────────────
const sensitiveShare: Rule = {
  id: 'COLL-SENSITIVE-SHARE',
  name: 'Acceso a recurso sensible',
  run(ctx) {
    const hits = unclaimed(ctx, ctx.events.filter((e) => ['5140', '5145'].includes(e.eventId) && SENSITIVE_DATA.test(`${e.dest} ${e.desc}`)));
    return [...groupBy(hits, (e) => `${e.userKey}|${e.dest}`)].map(([, evs]) => {
      claim(ctx, evs);
      const e0 = evs[0];
      return {
        ruleId: 'COLL-SENSITIVE-SHARE',
        title: `Acceso a recurso compartido sensible ${e0.dest} por ${e0.user}`,
        techniques: ['T1039'],
        baseScore: 30,
        baseLabel: 'Acceso a carpeta compartida sensible',
        events: evs,
        correlationKeys: [`user:${e0.userKey}`],
        summary: `${e0.user} (${e0.srcIp}) accedió a ${e0.dest} a las ${hhmm(e0)}${evs.length > 1 ? ` (${evs.length} accesos)` : ''}.`,
        technicalExplanation: `Acceso a un recurso compartido con información sensible. Puede ser legítimo; se reporta porque adquiere relevancia si se correlaciona con compresión o envío de datos del mismo usuario/equipo. Evidencia: ${logIds(evs)}.`,
        impact: 'Posible acceso no autorizado a información confidencial.',
        actionPlan: {
          investigate: [`Validar si ${e0.user} tiene necesidad de negocio para acceder a ${e0.dest}.`],
          contain: ['Revocar el acceso si no está justificado.'],
          remediate: ['Revisar permisos del recurso (mínimo privilegio) y habilitar auditoría detallada (5145).'],
        },
      } satisfies RawFinding;
    });
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 15. Inicio de sesión exitoso / privilegios desde IP externa (residual)
// ─────────────────────────────────────────────────────────────────────────────
const externalLogon: Rule = {
  id: 'ACCESS-EXTERNAL-LOGON',
  name: 'Inicio de sesión desde IP externa',
  run(ctx) {
    const hits = unclaimed(ctx, ctx.events.filter((e) => (isSuccessLogon(e) || isPrivilegedLogon(e)) && isPublicIp(e.srcIp)));
    return [...groupBy(hits, (e) => `${e.srcIp}|${e.userKey}`)].map(([, evs]) => {
      claim(ctx, evs);
      const e0 = evs[0];
      const priv = evs.some(isPrivilegedLogon);
      return {
        ruleId: 'ACCESS-EXTERNAL-LOGON',
        title: `Inicio de sesión de ${e0.user} desde IP externa ${e0.srcIp}`,
        techniques: ['T1078', 'T1133'],
        baseScore: priv ? 60 : 50,
        baseLabel: priv ? 'Sesión con privilegios desde IP externa' : 'Inicio de sesión desde IP externa',
        events: evs,
        summary: `${evs.length} evento(s) de inicio de sesión${priv ? '/privilegios' : ''} de ${e0.user} desde ${e0.srcIp} en ${fmtList(nonEmpty(evs.map((e) => e.host)))} (${span(evs)}).`,
        technicalExplanation: `Los inicios de sesión de Windows directamente desde direcciones públicas indican servicios expuestos a Internet o credenciales usadas fuera de la red (MITRE T1133/T1078). Evidencia: ${logIds(evs)}.`,
        impact: 'Acceso a sistemas internos desde fuera del perímetro.',
        actionPlan: {
          investigate: [`Confirmar con ${e0.user} si reconoce el acceso y desde dónde.`],
          contain: [`Bloquear ${e0.srcIp} si no es una IP corporativa conocida.`],
          remediate: ['Exigir VPN + MFA para cualquier acceso remoto.'],
        },
      } satisfies RawFinding;
    });
  },
};

/** Orden de ejecución: de lo más específico a lo más genérico */
export const RULES: Rule[] = [
  credentialAttack,
  targetedBruteForce,
  webShell,
  webScan,
  persistence,
  inhibitRecovery,
  encodedPowershell,
  lateralSmb,
  massFileAccess,
  exfilVolume,
  archiveStaging,
  suspiciousOutbound,
  discovery,
  sensitiveShare,
  externalLogon,
];
