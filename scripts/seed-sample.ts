/**
 * Seed the CCN-CERT database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force   # drop and recreate
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CCN_DB_PATH"] ?? "data/ccn.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "ccn-stic",
    name: "Guías CCN-STIC",
    name_en: "CCN-STIC Technical Guidelines",
    description: "Las Guías CCN-STIC son documentos técnicos del Centro Criptológico Nacional (CCN) con recomendaciones y requisitos de seguridad para sistemas de información. Se organizan en series: 100 (Política), 300 (Procedimientos), 400 (Guías generales), 500 (Sistemas operativos), 600 (Aplicaciones), 800 (ENS), 900 (Entornos específicos).",
    document_count: 250,
  },
  {
    id: "ens",
    name: "Esquema Nacional de Seguridad (ENS)",
    name_en: "National Security Framework (ENS)",
    description: "El Esquema Nacional de Seguridad (ENS), aprobado por Real Decreto 311/2022, establece la política de seguridad para el uso de medios electrónicos en las Administraciones Públicas. Define categorías ALTA, MEDIA y BÁSICA y medidas de seguridad en tres dimensiones: marco organizativo, marco operacional y medidas de protección.",
    document_count: 35,
  },
  {
    id: "ccn-cert-av",
    name: "Avisos CCN-CERT",
    name_en: "CCN-CERT Advisories",
    description: "Los Avisos de Seguridad del CCN-CERT informan sobre vulnerabilidades y amenazas de ciberseguridad. Se clasifican por peligrosidad: CRÍTICO, ALTO, MEDIO, BAJO. Incluyen descripción, productos afectados, solución y referencias CVE.",
    document_count: 500,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);

for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}

console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "CCN-STIC-807",
    title: "Criptografía de empleo en el ENS",
    title_en: "Cryptography for use in the National Security Framework",
    date: "2022-06-01",
    type: "ens_guide",
    series: "ENS",
    summary: "CCN-STIC-807 establece algoritmos criptográficos aprobados para sistemas ENS: cifrado simétrico AES-256, hash SHA-256/384, firma ECDSA P-256+, protocolo TLS 1.2 mínimo. Incluye periodos de validez de claves y requisitos de gestión. HSM obligatorio para categoría ALTA.",
    full_text: "CCN-STIC-807 Criptografía de empleo en el ENS. Cifrado simétrico: AES-256-GCM recomendado; AES-128 aceptable en BÁSICA; 3DES prohibido. Hash: SHA-256 mínimo para MEDIA y ALTA; SHA-384/512 para ALTA; MD5 y SHA-1 prohibidos. Firma digital: RSA mínimo 3072 bits; ECDSA P-256, P-384 o P-521; EdDSA Ed25519/Ed448. Acuerdo de claves: ECDH P-256+; X25519 aceptable. TLS: versión mínima 1.2; TLS 1.3 recomendado; TLS 1.0/1.1 prohibidos; solo cipher suites con forward secrecy. Certificados X.509 v3: RSA 3072+ o EC P-256+; SHA-256+; validez máxima 2 años TLS. HSM obligatorio en ALTA. Números aleatorios: DRBG conforme NIST SP 800-90A.",
    topics: JSON.stringify(["criptografía", "ENS", "TLS", "algoritmos"]),
    status: "current",
  },
  {
    reference: "CCN-STIC-830",
    title: "Medidas de implantación del ENS",
    title_en: "ENS Implementation Measures Guide",
    date: "2022-09-01",
    type: "ens_guide",
    series: "ENS",
    summary: "Guía práctica para implantar las medidas de seguridad del ENS. Incluye fichas por medida del marco organizativo, marco operacional y medidas de protección, con categoría requerida (BÁSICA, MEDIA, ALTA).",
    full_text: "CCN-STIC-830 Medidas de implantación ENS. Marco organizativo: [org.1] Política de seguridad — todas las categorías; [org.2] Normativa — MEDIA y ALTA; [org.3] Procedimientos — MEDIA y ALTA; [org.4] Proceso de autorización — ALTA. Marco operacional: [op.pl.1] Análisis de riesgos — todas; [op.pl.2] Arquitectura de seguridad — MEDIA y ALTA; [op.acc.1] Identificación — todas; [op.acc.5] Autenticación usuarios externos — MEDIA y ALTA; [op.acc.6] Autenticación organización — todas; [op.acc.7] Acceso remoto — MEDIA y ALTA; [op.exp.1] Inventario de activos — todas; [op.exp.2] Configuración de seguridad — todas; [op.mon.1] Detección intrusión — ALTA. Medidas de protección: [mp.if] Instalaciones; [mp.per] Personal; [mp.eq] Equipos; [mp.com] Comunicaciones; [mp.si] Soportes; [mp.sw] Aplicaciones; [mp.info] Información; [mp.s] Servicios.",
    topics: JSON.stringify(["ENS", "medidas de seguridad", "implantación"]),
    status: "current",
  },
  {
    reference: "CCN-STIC-302",
    title: "Recomendaciones de configuración TLS",
    title_en: "TLS Configuration Recommendations",
    date: "2023-03-01",
    type: "technical_guideline",
    series: "CCN-STIC",
    summary: "CCN-STIC-302 establece configuraciones TLS para sistemas del sector público. TLS 1.3 obligatorio en ALTA; TLS 1.2 mínimo; TLS 1.1/1.0 prohibidos. Define cipher suites aceptables, requisitos HSTS, OCSP Stapling y mTLS para comunicaciones máquina a máquina.",
    full_text: "CCN-STIC-302 Configuración TLS. Versiones: TLS 1.3 obligatorio en ALTA; TLS 1.2 permitido; TLS 1.1/1.0/SSL prohibidos. TLS 1.3 suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256. TLS 1.2 suites: solo ECDHE o DHE (forward secrecy); ECDHE-RSA-AES256-GCM-SHA384 recomendado; RC4, 3DES, NULL, EXPORT prohibidos. Certificados: RSA 3072+ o EC P-256+; SHA-256+; SAN correcto. HSTS: max-age mínimo 6 meses; includeSubDomains en ALTA. OCSP Stapling: recomendado. Renegociación insegura: prohibida. Compresión TLS: prohibida (CRIME). mTLS: recomendado para M2M en ALTA. nginx: ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384.",
    topics: JSON.stringify(["TLS", "configuración segura", "cifrado"]),
    status: "current",
  },
  {
    reference: "CCN-STIC-811",
    title: "Interconexión en el ENS — Seguridad en las comunicaciones",
    title_en: "ENS Interconnection — Communication Security",
    date: "2022-11-01",
    type: "ens_guide",
    series: "ENS",
    summary: "CCN-STIC-811 establece medidas de seguridad para interconexión de sistemas ENS con redes externas. Cubre cortafuegos, IDS/IPS, segmentación de red, DMZ y cifrado de VPN. Aplica a la medida [mp.com.1] del ENS.",
    full_text: "CCN-STIC-811 Interconexión en el ENS. Perímetro: cortafuegos obligatorio en puntos de conexión externa; denegación por defecto; logs de tráfico. Segmentación: DMZ obligatoria en MEDIA y ALTA; separación física o VLAN. IDS/IPS: obligatorio en ALTA; monitorización tráfico interno. Cifrado: VPN con IPsec o TLS 1.2+ para interconexiones; algoritmos conforme CCN-STIC-807. Filtrado: proxy de salida recomendado; filtrado URLs maliciosas. Dispositivos de red: credenciales por defecto cambiadas; acceso gestión desde redes admin; SNMPv3 o SSH; firmware actualizado. Zonas: zona pública, DMZ externa, DMZ interna, zona usuarios, zona servidores, zona gestión.",
    topics: JSON.stringify(["red", "perímetro", "cortafuegos", "ENS"]),
    status: "current",
  },
  {
    reference: "CCN-STIC-570",
    title: "Bastionado de Active Directory en entornos Microsoft",
    title_en: "Active Directory Hardening in Microsoft Environments",
    date: "2023-07-01",
    type: "technical_guideline",
    series: "CCN-STIC",
    summary: "CCN-STIC-570 proporciona guías de bastionado para Active Directory. Incluye modelo de niveles Tier (0/1/2), LAPS, protección de cuentas privilegiadas, Kerberos AES256, detección de ataques Pass-the-Hash y Kerberoasting.",
    full_text: "CCN-STIC-570 Bastionado Active Directory. Cuentas privilegiadas: separar cuentas admin de usuario; Tier 0 (DC), Tier 1 (servidores), Tier 2 (estaciones); prohibir login admin con Internet. Contraseñas: mínimo 12 caracteres usuarios, 16 admins; complejidad habilitada; historial 12; LAPS para cuentas locales. DC: login restringido a Tier 0; no software adicional; Windows Firewall habilitado; BitLocker en OS. Autenticación: Kerberos primario; NTLMv2 mínimo si se necesita NTLM; deshabilitar NTLMv1 y LM. Kerberos: TGT máximo 10 horas; renewals 7 días; AES256 por defecto; RC4 deshabilitado. Auditoría: Event 4625 (fallos login), 4648 (login explícito), 4720 (creación cuenta); alertas cambios grupos privilegiados. GPO: AppLocker o WDAC en ALTA; auditoría completa.",
    topics: JSON.stringify(["Active Directory", "bastionado", "Windows", "identidad"]),
    status: "current",
  },
  {
    reference: "CCN-STIC-839",
    title: "Análisis de riesgos en el ENS — MAGERIT y PILAR",
    title_en: "Risk Analysis in the ENS — MAGERIT and PILAR",
    date: "2022-08-01",
    type: "ens_guide",
    series: "ENS",
    summary: "CCN-STIC-839 describe la metodología MAGERIT v3 y la herramienta PILAR para análisis de riesgos en el ENS. Aplica a la medida [op.pl.1]. El resultado determina la categoría del sistema (BÁSICA, MEDIA, ALTA). Actualización mínima anual o ante cambios significativos.",
    full_text: "CCN-STIC-839 Análisis de riesgos MAGERIT y PILAR. MAGERIT v3 es la metodología oficial del CCN. Fases: (1) Activos: identificar, valorar en ACID+T (Autenticidad, Confidencialidad, Integridad, Disponibilidad, Trazabilidad); escala 0-10. (2) Amenazas: catálogo MAGERIT — [N] naturales, [I] industriales, [E] errores, [A] ataques; frecuencia e impacto. (3) Salvaguardas: controles existentes y eficacia. (4) Riesgo: impacto × frecuencia ajustado por salvaguardas. PILAR: herramienta oficial CCN; importa catálogos activos; genera informe de riesgos y declaración de aplicabilidad (DA). Categoría ENS: resultado del análisis determina BÁSICA, MEDIA o ALTA según dimensión más crítica. Periodicidad: actualizar ante cambios significativos o mínimo anual.",
    topics: JSON.stringify(["análisis de riesgos", "MAGERIT", "PILAR", "ENS"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

for (const g of guidance) {
  insertGuidance.run(
    g.reference, g.title, g.title_en, g.date, g.type, g.series,
    g.summary, g.full_text, g.topics, g.status,
  );
}

console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "CCN-CERT-AV-24/001",
    title: "Vulnerabilidad crítica en Ivanti Connect Secure y Policy Secure",
    date: "2024-01-12",
    severity: "critical",
    affected_products: "Ivanti Connect Secure (versiones anteriores a 9.1R18.3, 22.3R3.2, 22.4R2.4, 22.5R1.3, 22.5R2.4, 22.6R1.3); Ivanti Policy Secure (versiones anteriores a 9.1R17.2, 22.5R1.1)",
    summary: "CCN-CERT alerta sobre explotación activa de CVE-2023-46805 y CVE-2024-21887 en Ivanti Connect Secure y Policy Secure. La combinación permite RCE sin autenticación. Se han detectado actores APT explotando estas vulnerabilidades en organizaciones del sector público y defensa.",
    full_text: "CCN-CERT-AV-24/001 Ivanti Connect Secure. CVE-2023-46805 (CVSS 8.2): bypass de autenticación en el componente web. CVE-2024-21887 (CVSS 9.1): inyección de comandos para administradores autenticados. Encadenamiento: bypass auth + inyección comandos = RCE sin autenticación. APT con webshells personalizadas; persistencia eludiendo restablecimientos de fábrica. IoC: tráfico a /api/v1/totp/user-backup-code/; archivos de configuración modificados. Mitigación: aplicar parches Ivanti (desde 22 enero 2024); ejecutar herramienta de integridad; monitorizar IoC. Sistemas ALTA: considerar desconexión hasta parchear.",
    cve_references: "CVE-2023-46805, CVE-2024-21887",
  },
  {
    reference: "CCN-CERT-AV-23/045",
    title: "Campaña de ransomware Akira dirigida a VPN Cisco sin MFA",
    date: "2023-09-18",
    severity: "high",
    affected_products: "Cisco ASA VPN sin MFA; Cisco FTD VPN sin MFA",
    summary: "CCN-CERT alerta sobre la campaña activa del grupo Akira que explota VPN Cisco sin MFA. Acceden con credenciales comprometidas y despliegan ransomware (doble extorsión). Detectados múltiples incidentes en organizaciones españolas.",
    full_text: "CCN-CERT-AV-23/045 Ransomware Akira en VPN Cisco. Grupo Akira activo desde marzo 2023; doble extorsión; rescates 200.000 a varios millones. Acceso: credenciales válidas en VPN Cisco ASA/FTD sin MFA; obtenidas por infostealers, phishing o mercados. ATT&CK: T1021.002 (SMB Admin Shares), T1570 (Lateral Tool Transfer), T1486 (Data Encrypted for Impact), T1041 (Exfiltration C2). Herramientas: AnyDesk, WinRAR, PCHunter, RClone a Mega.nz. IoC: conexiones VPN en horario inusual; admin remoto no autorizado; consultas LDAP masivas; tráfico salida elevado. Mitigación: habilitar MFA en VPN (obligatorio ENS MEDIA y ALTA); revisar logs VPN; actualizar Cisco ASA/FTD; deshabilitar cuentas inactivas.",
    cve_references: null,
  },
  {
    reference: "CCN-CERT-AV-24/022",
    title: "Vulnerabilidades críticas en Microsoft Exchange Server — Explotación activa",
    date: "2024-02-14",
    severity: "critical",
    affected_products: "Microsoft Exchange Server 2016 CU23; Exchange Server 2019 CU13 y CU14 (anteriores a parche febrero 2024)",
    summary: "CCN-CERT informa sobre CVE-2024-21410 (CVSS 9.8) en Exchange Server con explotación activa confirmada. Permite relay de credenciales NTLM sin autenticación. La actualización de febrero 2024 habilita EPA automáticamente en Exchange 2019 CU14.",
    full_text: "CCN-CERT-AV-24/022 Exchange Server febrero 2024. CVE-2024-21410 (CVSS 9.8 CRÍTICO): elevación de privilegios por relay NTLM en Exchange. Atacante fuerza autenticación de Outlook en servidor malicioso y relaya credenciales a Exchange objetivo. Actualización feb 2024 habilita EPA automáticamente en Exchange 2019 CU14. Exchange 2019 CU13 y Exchange 2016 CU23: instalar actualización Y ejecutar script para habilitar EPA manualmente. CVE-2024-21762 (CVSS 7.6 ALTO): divulgación de información; lector de archivos arbitrarios para autenticado. Mitigación: aplicar parches febrero 2024; habilitar EPA; revisar logs NTLM; validar versión de build.",
    cve_references: "CVE-2024-21410, CVE-2024-21762",
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

for (const a of advisories) {
  insertAdvisory.run(
    a.reference, a.title, a.date, a.severity, a.affected_products,
    a.summary, a.full_text, a.cve_references,
  );
}

console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT COUNT(*) as n FROM guidance").get() as { n: number }).n;
const advisoryCount = (db.prepare("SELECT COUNT(*) as n FROM advisories").get() as { n: number }).n;
const frameworkCount = (db.prepare("SELECT COUNT(*) as n FROM frameworks").get() as { n: number }).n;

console.log(`\nDatabase summary:`);
console.log(`  Guidance documents: ${guidanceCount}`);
console.log(`  Advisories:         ${advisoryCount}`);
console.log(`  Frameworks:         ${frameworkCount}`);
console.log(`\nSeed complete.`);
