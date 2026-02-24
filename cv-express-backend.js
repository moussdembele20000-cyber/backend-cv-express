/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║          CV EXPRESS 24 — BACKEND COMPLET v2             ║
 * ╠══════════════════════════════════════════════════════════╣
 * ║  Stack : Node.js · Express · Supabase · JWT · Puppeteer ║
 * ║  Admin : munupage@gmail.com / 441755                    ║
 * ╠══════════════════════════════════════════════════════════╣
 * ║  ROUTES PUBLIQUES                                        ║
 * ║    GET  /api/health              → statut serveur        ║
 * ║    GET  /api/products            → catalogue produits    ║
 * ║    POST /api/submit-cv           → soumettre CV+paiement ║
 * ║    GET  /api/cv-status/:id       → statut paiement       ║
 * ║    GET  /api/download/:id        → télécharger PDF       ║
 * ║    GET  /api/push/vapid-key      → clé push publique     ║
 * ║  ROUTES ADMIN (JWT requis)                               ║
 * ║    POST /api/admin/login         → authentification      ║
 * ║    GET  /api/admin/submissions   → liste soumissions     ║
 * ║    GET  /api/admin/stats         → statistiques          ║
 * ║    POST /api/admin/validate/:id  → valider paiement      ║
 * ║    DELETE /api/admin/reject/:id  → rejeter soumission    ║
 * ║    POST /api/admin/push-subscribe→ abonner notifications ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * DÉPLOIEMENT RAPIDE :
 *   1. npm install
 *   2. cp .env.example .env  (remplir les variables)
 *   3. node -e "require('./setup')" (créer tables Supabase)
 *   4. node server.js
 *
 * GÉNÉRATION CLÉS VAPID :
 *   node -e "const w=require('web-push');const k=w.generateVAPIDKeys();console.log(k)"
 */

'use strict';
require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const webpush   = require('web-push');
const { createClient } = require('@supabase/supabase-js');
const puppeteer = require('puppeteer');

// ═══════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════

const PORT      = process.env.PORT || 3000;
const JWT_SEC   = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION_SECRET_VERY_LONG';
const JWT_EXP   = process.env.JWT_EXPIRES_IN || '8h';

// Admin credentials (définis en .env, préremplis ici pour MVP)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'munupage@gmail.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '441755';

// ═══════════════════════════════════════════════════════════
// INITIALISATION
// ═══════════════════════════════════════════════════════════

const app = express();

// Supabase (service key pour accès complet côté backend)
const supabase = createClient(
  process.env.SUPABASE_URL      || 'https://VOTRE_PROJECT.supabase.co',
  process.env.SUPABASE_SERVICE_KEY || 'VOTRE_SERVICE_ROLE_KEY'
);

// Web Push
try {
  webpush.setVapidDetails(
    `mailto:${ADMIN_USERNAME}`,
    process.env.VAPID_PUBLIC_KEY  || '',
    process.env.VAPID_PRIVATE_KEY || ''
  );
} catch (e) {
  console.warn('⚠️  VAPID non configuré. Push désactivé. Génère les clés avec : npm run gen-vapid');
}

// Stockage push subscriptions (mémoire MVP — migrer vers BDD en production)
let pushSubs = [];

// Hash mot de passe admin (au démarrage)
let ADMIN_HASH = null;
(async () => {
  ADMIN_HASH = await bcrypt.hash(ADMIN_PASSWORD, 12);
  console.log('✅ Hash admin initialisé');
})();

// ═══════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════

app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS — autoriser les frontends (à restreindre en production)
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiters
const rl = (max, window, msg) => rateLimit({
  windowMs: window, max,
  message: { error: msg },
  standardHeaders: true, legacyHeaders: false
});

const limitSubmit = rl(5,  60*60*1000,  'Trop de soumissions. Réessaie dans 1h.');
const limitStatus = rl(30, 60*1000,     'Trop de requêtes. Ralentis.');
const limitLogin  = rl(5,  15*60*1000,  'Trop de tentatives. Attends 15 min.');

// ═══════════════════════════════════════════════════════════
// MIDDLEWARE JWT ADMIN
// ═══════════════════════════════════════════════════════════

function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant ou invalide.' });
  }
  try {
    req.admin = jwt.verify(header.split(' ')[1], JWT_SEC);
    next();
  } catch {
    return res.status(401).json({ error: 'Token expiré. Reconnecte-toi.' });
  }
}

// ═══════════════════════════════════════════════════════════
// UTILITAIRES
// ═══════════════════════════════════════════════════════════

const san   = (s, n = 200) => !s ? '' : String(s).trim().substring(0, n);
const isUUID = id => /^[0-9a-f-]{36}$/i.test(id);

// Envoyer une notification push à tous les admins abonnés
async function notifyAdmins(title, body, data = {}) {
  if (!pushSubs.length) return;
  const payload = JSON.stringify({ title, body, data, timestamp: Date.now() });
  const results = await Promise.allSettled(
    pushSubs.map(sub => webpush.sendNotification(sub, payload).catch(e => Promise.reject(e)))
  );
  // Supprimer les subscriptions expirées (410 Gone)
  pushSubs = pushSubs.filter((_, i) => results[i].status === 'fulfilled');
}

// ═══════════════════════════════════════════════════════════
// GÉNÉRATION HTML CV (pour PDF côté serveur)
// ═══════════════════════════════════════════════════════════

function e(s) {
  return !s ? '' : String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildCVHtml(cvData, productCode) {
  const fmts = (cvData.formations || []).map(f => `
    <div class="entry">
      <div class="entry-title">${e(f.diplome)}</div>
      <div class="entry-sub">${e(f.ecole)}${f.annee ? ' · ' + e(f.annee) : ''}</div>
    </div>`).join('');

  const exps = (cvData.experiences || []).map(ex => `
    <div class="entry">
      <div class="entry-title">${e(ex.poste)}</div>
      <div class="entry-sub">${e(ex.entreprise)}${ex.duree ? ' · ' + e(ex.duree) : ''}</div>
      <div class="entry-desc">${e(ex.description || '')}</div>
    </div>`).join('');

  const skills = (cvData.competences || []).map(s => `<span class="skill">${e(s)}</span>`).join('');

  const cvHTML = cvData.template === 2
    ? buildT2(cvData, fmts, exps, skills)
    : buildT1(cvData, fmts, exps, skills);

  // Lettre incluse selon le produit
  const withLettre = ['CV_PRO_LETTRE','CV_PREMIUM','LETTRE_STANDARD','LETTRE_PREMIUM'].includes(productCode);
  const lettreHTML = withLettre ? buildLettre(cvData) : '';

  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:white}
  .page-break{page-break-before:always}
  .t1{display:flex;width:210mm;min-height:297mm}
  .t1-side{width:72mm;background:#0D1B3E;padding:28px 18px;color:white;flex-shrink:0}
  .t1-main{flex:1;padding:28px 20px}
  .t1-name{font-size:22px;font-weight:900;margin-bottom:4px;line-height:1.2}
  .t1-role{color:#94A3B8;font-size:11px;margin-bottom:22px}
  .t1-sh{font-size:9px;text-transform:uppercase;letter-spacing:2px;color:#F5A623;margin:18px 0 8px;font-weight:700;border-bottom:1px solid #1E2D4F;padding-bottom:4px}
  .t1-ci{font-size:10px;color:#CBD5E1;margin-bottom:5px}
  .skill{display:inline-block;background:#1E2D4F;border-radius:4px;padding:3px 8px;font-size:9px;margin:2px;color:#E2E8F0}
  .t1-sec{font-size:9px;text-transform:uppercase;letter-spacing:2px;color:#1A4DB8;font-weight:700;margin:18px 0 8px;border-bottom:2px solid #EEF2FF;padding-bottom:4px}
  .t2{width:210mm;min-height:297mm}
  .t2-hd{background:linear-gradient(135deg,#0D1B3E,#1A4DB8);padding:28px 24px;color:white;display:flex;align-items:center;gap:18px}
  .t2-av{width:60px;height:60px;background:#F5A623;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:900;color:#0D1B3E;flex-shrink:0}
  .t2-body{display:flex}
  .t2-main{flex:1.6;padding:20px}
  .t2-side{flex:1;background:#F8FAFF;padding:20px 16px;border-left:1px solid #E2E8F0}
  .t2-sh{font-size:9px;text-transform:uppercase;letter-spacing:2px;color:#1A4DB8;font-weight:700;margin-bottom:8px}
  .t2-ci{font-size:11px;color:#64748B;margin-bottom:7px}
  .entry{margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid #F1F5F9}
  .entry:last-child{border-bottom:none}
  .entry-title{font-weight:700;font-size:12px;color:#0D1B3E}
  .entry-sub{font-size:11px;color:#1A4DB8;margin-bottom:3px}
  .entry-desc{font-size:11px;color:#475569;line-height:1.5}
  .summary{font-size:11px;color:#475569;line-height:1.6;margin-bottom:14px}
  .lettre{width:210mm;min-height:297mm;padding:40px;font-size:12px;color:#1e293b;line-height:1.7}
  .l-sign{margin-top:40px}
</style>
</head><body>${cvHTML}${lettreHTML}</body></html>`;
}

function buildT1(d, fmts, exps, skills) {
  return `<div class="t1">
    <div class="t1-side">
      <div class="t1-name">${e(d.nom)}</div>
      <div class="t1-role">${e(d.poste)}</div>
      <div class="t1-sh">Contact</div>
      ${d.telephone?`<div class="t1-ci">📞 ${e(d.telephone)}</div>`:''}
      ${d.email?`<div class="t1-ci">✉ ${e(d.email)}</div>`:''}
      ${d.adresse?`<div class="t1-ci">📍 ${e(d.adresse)}</div>`:''}
      ${skills?`<div class="t1-sh" style="margin-top:22px">Compétences</div><div>${skills}</div>`:''}
    </div>
    <div class="t1-main">
      <div style="font-size:20px;font-weight:900;color:#0D1B3E;margin-bottom:6px">${e(d.nom)}</div>
      ${d.resume?`<div class="summary">${e(d.resume)}</div>`:''}
      ${fmts?`<div class="t1-sec">Formation</div>${fmts}`:''}
      ${exps?`<div class="t1-sec">Expérience professionnelle</div>${exps}`:''}
    </div>
  </div>`;
}

function buildT2(d, fmts, exps, skills) {
  const ini = d.nom.split(' ').map(n => n[0]||'').join('').substring(0,2).toUpperCase();
  const skillBars = (d.competences || []).map((s,i) => `
    <div style="margin-bottom:8px">
      <div style="font-size:11px;color:#0D1B3E;margin-bottom:3px">${e(s)}</div>
      <div style="height:5px;background:#E2E8F0;border-radius:3px;overflow:hidden">
        <div style="height:100%;background:#1A4DB8;border-radius:3px;width:${65+(i*7)%28}%"></div>
      </div>
    </div>`).join('');
  return `<div class="t2">
    <div class="t2-hd">
      <div class="t2-av">${ini}</div>
      <div>
        <div style="font-size:24px;font-weight:900">${e(d.nom)}</div>
        <div style="color:#93C5FD;font-size:13px">${e(d.poste)}</div>
      </div>
    </div>
    <div class="t2-body">
      <div class="t2-main">
        ${d.resume?`<div class="t2-sh">Profil</div><div class="summary">${e(d.resume)}</div>`:''}
        ${exps?`<div class="t2-sh" style="margin-top:14px">Expériences</div>${exps}`:''}
        ${fmts?`<div class="t2-sh" style="margin-top:14px">Formations</div>${fmts}`:''}
      </div>
      <div class="t2-side">
        <div class="t2-sh">Contact</div>
        ${d.telephone?`<div class="t2-ci">📞 ${e(d.telephone)}</div>`:''}
        ${d.email?`<div class="t2-ci">✉ ${e(d.email)}</div>`:''}
        ${d.adresse?`<div class="t2-ci">📍 ${e(d.adresse)}</div>`:''}
        ${skillBars?`<div class="t2-sh" style="margin-top:16px">Compétences</div>${skillBars}`:''}
      </div>
    </div>
  </div>`;
}

function buildLettre(d) {
  const today = new Date().toLocaleDateString('fr-FR', {day:'numeric',month:'long',year:'numeric'});
  const competencesStr = (d.competences||[]).slice(0,3).join(', ') || 'divers domaines';
  const diplome  = (d.formations&&d.formations[0]?.diplome) || 'diplôme professionnel';
  const ecole    = (d.formations&&d.formations[0]?.ecole)   || "l'université";
  return `
  <div class="page-break"></div>
  <div class="lettre">
    <div style="display:flex;justify-content:space-between;margin-bottom:32px">
      <div>
        <strong>${e(d.nom)}</strong><br>
        ${d.telephone?e(d.telephone)+'<br>':''} 
        ${d.email?e(d.email)+'<br>':''}
        ${d.adresse?e(d.adresse):''}
      </div>
      <div style="text-align:right">
        <strong>Le Directeur des Ressources Humaines</strong><br>
        Nom de l'entreprise<br>
        Adresse de l'entreprise
      </div>
    </div>
    <div style="text-align:right;color:#64748B;margin-bottom:28px">${e(d.adresse||'Dakar')}, le ${today}</div>
    <div style="font-weight:700;margin-bottom:22px">Objet : Candidature au poste de ${e(d.poste||'collaborateur')}</div>
    <p style="margin-bottom:14px">Madame, Monsieur,</p>
    <p style="margin-bottom:14px">Titulaire d'un <strong>${e(diplome)}</strong> obtenu à ${e(ecole)}, je me permets de vous adresser ma candidature pour le poste de <strong>${e(d.poste||'collaborateur')}</strong> au sein de votre structure.</p>
    <p style="margin-bottom:14px">${e(d.resume||'Fort de mon expérience professionnelle et de ma motivation, je suis convaincu de pouvoir apporter une contribution significative à votre équipe.')}</p>
    <p style="margin-bottom:14px">Au cours de mon parcours, j'ai développé des compétences solides en <strong>${e(competencesStr)}</strong>, qui me permettront de m'intégrer rapidement et efficacement dans votre organisation.</p>
    <p style="margin-bottom:14px">Convaincu que mon profil correspond à vos attentes, je reste disponible pour un entretien à votre convenance.</p>
    <p style="margin-bottom:28px">Dans l'attente de vous lire, veuillez agréer, Madame, Monsieur, l'expression de mes salutations distinguées.</p>
    <div class="l-sign"><strong>${e(d.nom)}</strong></div>
  </div>`;
}

// ═══════════════════════════════════════════════════════════
// ROUTES PUBLIQUES
// ═══════════════════════════════════════════════════════════

/** Health check */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0', ts: new Date().toISOString() });
});

/** GET /api/products — Catalogue produits actifs */
app.get('/api/products', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('id, code, name, description, price, includes_cv, includes_lettre')
      .eq('active', true)
      .order('price', { ascending: true });
    if (error) throw error;
    return res.json({ products: data });
  } catch (err) {
    console.error('GET /products:', err.message);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/**
 * POST /api/submit-cv
 * Reçoit les données CV + product_id + transaction_number
 * Stocke paiement_valide = false (JAMAIS true à la soumission)
 */
app.post('/api/submit-cv', limitSubmit, async (req, res) => {
  try {
    const { nom, email, telephone, poste, adresse, cv_data, transaction_number, product_id, template_id } = req.body;

    // Validation
    const errs = [];
    if (!nom || nom.trim().length < 2)               errs.push('Nom invalide (min 2 caractères).');
    if (!telephone || telephone.trim().length < 8)    errs.push('Téléphone invalide.');
    if (!transaction_number || transaction_number.trim().length < 4) errs.push('Numéro de transaction invalide.');
    if (!product_id || !Number.isInteger(Number(product_id))) errs.push('Produit invalide.');
    if (!cv_data || typeof cv_data !== 'object')      errs.push('Données CV manquantes.');
    if (errs.length) return res.status(400).json({ error: 'Données invalides.', details: errs });

    // Vérifier que le produit existe et est actif
    const { data: prod, error: pErr } = await supabase
      .from('products')
      .select('id, code, name, price, active')
      .eq('id', Number(product_id))
      .eq('active', true)
      .single();
    if (pErr || !prod) return res.status(400).json({ error: 'Produit invalide ou inactif.' });

    // Vérifier doublon de transaction
    const { data: dup } = await supabase
      .from('cv_submissions')
      .select('id')
      .eq('transaction_number', transaction_number.trim())
      .maybeSingle();
    if (dup) return res.status(409).json({ error: 'Ce numéro de transaction a déjà été utilisé.' });

    // Insérer
    const { data: ins, error: iErr } = await supabase
      .from('cv_submissions')
      .insert([{
        nom:                san(nom, 100),
        email:              san(email, 200),
        telephone:          san(telephone, 25),
        poste:              san(poste, 100),
        adresse:            san(adresse, 200),
        cv_data,
        product_id:         prod.id,
        transaction_number: san(transaction_number, 100),
        paiement_valide:    false,    // ← TOUJOURS false à la soumission
        statut_prix:        'INCONNU',
        template_id:        template_id || 1,
        ip_address:         req.ip
      }])
      .select('id')
      .single();
    if (iErr) throw iErr;

    console.log(`📥 Soumission | ${san(nom)} | ${prod.code} | ${prod.price} FCFA | TXN: ${san(transaction_number)}`);

    // Notifier l'admin
    notifyAdmins(
      '🔔 Nouveau paiement à valider',
      `${san(nom)} — ${prod.name} (${prod.price.toLocaleString('fr-FR')} FCFA)`,
      { cv_id: ins.id, product_code: prod.code }
    ).catch(() => {});

    return res.status(201).json({
      status:  'pending',
      cv_id:   ins.id,
      product: { code: prod.code, name: prod.name, price: prod.price },
      message: 'Soumission enregistrée. En attente de validation du paiement.'
    });
  } catch (err) {
    console.error('POST /submit-cv:', err.message);
    return res.status(500).json({ error: 'Erreur serveur. Réessaie.' });
  }
});

/**
 * GET /api/cv-status/:id
 * Retourne UNIQUEMENT le statut booléen — rien d'autre
 */
app.get('/api/cv-status/:id', limitStatus, async (req, res) => {
  if (!isUUID(req.params.id)) return res.status(400).json({ error: 'ID invalide.' });
  try {
    const { data, error } = await supabase
      .from('cv_submissions')
      .select('paiement_valide')
      .eq('id', req.params.id)
      .single();
    if (error || !data) return res.status(404).json({ error: 'Soumission introuvable.' });
    return res.json({ paiement_valide: data.paiement_valide });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/**
 * GET /api/download/:id
 * ⚠️  Génère le PDF CÔTÉ SERVEUR uniquement si paiement_valide === true
 * Le contenu (CV seul, CV+Lettre) dépend du product_code — jamais du frontend
 */
app.get('/api/download/:id', async (req, res) => {
  if (!isUUID(req.params.id)) return res.status(400).json({ error: 'ID invalide.' });
  let browser = null;
  try {
    // Récupérer via la vue jointure
    const { data, error } = await supabase
      .from('cv_submissions_with_product')
      .select('nom, cv_data, paiement_valide, product_code, product_name, template_id')
      .eq('id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ error: 'Soumission introuvable.' });

    // ── VÉRIFICATION DE SÉCURITÉ ─────────────────────────────
    if (data.paiement_valide !== true) {
      return res.status(403).json({ error: 'Paiement non validé. Téléchargement bloqué.' });
    }

    // ── GÉNÉRATION PDF CONDITIONNELLE ─────────────────────────
    const html = buildCVHtml(
      { ...data.cv_data, template: data.template_id },
      data.product_code   // ← le backend décide du contenu
    );

    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
    });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '0', right: '0', bottom: '0', left: '0' }
    });
    await browser.close(); browser = null;

    const fname = `CV_${(data.nom||'').replace(/\s+/g,'_')}_${data.product_code}.pdf`;
    console.log(`📄 PDF téléchargé : ${fname}`);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Content-Length', pdf.length);
    return res.send(pdf);
  } catch (err) {
    if (browser) await browser.close().catch(() => {});
    console.error('GET /download:', err.message);
    return res.status(500).json({ error: 'Erreur génération PDF.' });
  }
});

/** Clé VAPID publique pour le frontend push */
app.get('/api/push/vapid-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY || '' });
});

// ═══════════════════════════════════════════════════════════
// ROUTES ADMIN (JWT obligatoire)
// ═══════════════════════════════════════════════════════════

/** POST /api/admin/login */
app.post('/api/admin/login', limitLogin, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Identifiants manquants.' });

    // Timing-safe : toujours faire le bcrypt même si username faux
    const usernameOk = username === ADMIN_USERNAME;
    const hashToCompare = ADMIN_HASH || await bcrypt.hash('dummy', 12);
    const passOk = await bcrypt.compare(password, hashToCompare);

    if (!usernameOk || !passOk) {
      return res.status(401).json({ error: 'Identifiants incorrects.' });
    }

    const token = jwt.sign(
      { role: 'admin', username },
      JWT_SEC,
      { expiresIn: JWT_EXP }
    );
    console.log(`🔐 Login admin : ${username}`);
    return res.json({ token, expires_in: JWT_EXP });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/** POST /api/admin/push-subscribe */
app.post('/api/admin/push-subscribe', auth, async (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription?.endpoint) return res.status(400).json({ error: 'Subscription invalide.' });
    const exists = pushSubs.some(s => s.endpoint === subscription.endpoint);
    if (!exists) {
      pushSubs.push(subscription);
      console.log(`🔔 Push subscription admin enregistrée (total: ${pushSubs.length})`);
    }
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur push.' });
  }
});

/** GET /api/admin/submissions */
app.get('/api/admin/submissions', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('cv_submissions_with_product')
      .select('id, nom, email, telephone, poste, transaction_number, paiement_valide, statut_prix, date_creation, date_validation, validated_by, product_code, product_name, product_price, includes_lettre')
      .order('paiement_valide', { ascending: true })
      .order('date_creation',   { ascending: false });
    if (error) throw error;
    return res.json({ submissions: data || [], count: data?.length || 0 });
  } catch (err) {
    console.error('GET /admin/submissions:', err.message);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/** GET /api/admin/stats */
app.get('/api/admin/stats', auth, async (req, res) => {
  try {
    const [all, pend, validated] = await Promise.all([
      supabase.from('cv_submissions').select('*', { count: 'exact', head: true }),
      supabase.from('cv_submissions').select('*', { count: 'exact', head: true }).eq('paiement_valide', false),
      supabase.from('cv_submissions_with_product').select('product_price').eq('paiement_valide', true)
    ]);
    const revenue = (validated.data || []).reduce((a, r) => a + (r.product_price || 0), 0);

    const { data: byProd } = await supabase
      .from('cv_submissions_with_product')
      .select('product_code, product_name, product_price, paiement_valide');

    const byProduct = {};
    (byProd || []).forEach(r => {
      if (!byProduct[r.product_code]) {
        byProduct[r.product_code] = { name: r.product_name, total: 0, validated: 0, revenue: 0 };
      }
      byProduct[r.product_code].total++;
      if (r.paiement_valide) {
        byProduct[r.product_code].validated++;
        byProduct[r.product_code].revenue += r.product_price || 0;
      }
    });

    return res.json({
      total:        all.count    || 0,
      pending:      pend.count   || 0,
      validated:    validated.data?.length || 0,
      revenue_fcfa: revenue,
      by_product:   byProduct
    });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/**
 * POST /api/admin/validate/:id
 * Valide le paiement — met paiement_valide à true
 */
app.post('/api/admin/validate/:id', auth, async (req, res) => {
  if (!isUUID(req.params.id)) return res.status(400).json({ error: 'ID invalide.' });
  try {
    const { statut_prix = 'CORRECT' } = req.body;
    const valid = ['CORRECT','INFERIEUR','SUPERIEUR'];

    const { data: existing } = await supabase
      .from('cv_submissions_with_product')
      .select('id, nom, paiement_valide, product_name, product_price')
      .eq('id', req.params.id)
      .single();

    if (!existing) return res.status(404).json({ error: 'Soumission introuvable.' });
    if (existing.paiement_valide) return res.status(409).json({ error: 'Paiement déjà validé.' });

    const { error } = await supabase
      .from('cv_submissions')
      .update({
        paiement_valide: true,    // ← débloque le PDF
        statut_prix:     valid.includes(statut_prix) ? statut_prix : 'CORRECT',
        date_validation: new Date().toISOString(),
        validated_by:    req.admin.username
      })
      .eq('id', req.params.id);
    if (error) throw error;

    console.log(`✅ Validé par ${req.admin.username} : ${existing.nom} | ${existing.product_name} | ${existing.product_price} FCFA`);
    return res.json({
      success: true,
      message: `Paiement validé. PDF "${existing.product_name}" débloqué pour ${existing.nom}.`
    });
  } catch (err) {
    console.error('POST /admin/validate:', err.message);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/** DELETE /api/admin/reject/:id */
app.delete('/api/admin/reject/:id', auth, async (req, res) => {
  if (!isUUID(req.params.id)) return res.status(400).json({ error: 'ID invalide.' });
  try {
    const { error } = await supabase.from('cv_submissions').delete().eq('id', req.params.id);
    if (error) throw error;
    console.log(`🗑  Rejeté par ${req.admin.username} | ID: ${req.params.id}`);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ═══════════════════════════════════════════════════════════
// 404 + START
// ═══════════════════════════════════════════════════════════

app.use((req, res) => res.status(404).json({ error: 'Route introuvable.' }));

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║       CV EXPRESS 24 v2 — BACKEND             ║
╠══════════════════════════════════════════════╣
║  Port       : ${String(PORT).padEnd(28)} ║
║  Env        : ${(process.env.NODE_ENV||'development').padEnd(28)} ║
║  Admin      : ${ADMIN_USERNAME.padEnd(28)} ║
║  Supabase   : ${(process.env.SUPABASE_URL?'✅ Configuré':'❌ Non configuré').padEnd(28)} ║
║  Push/VAPID : ${(process.env.VAPID_PUBLIC_KEY?'✅ Configuré':'⚠️  Non configuré').padEnd(28)} ║
╚══════════════════════════════════════════════╝
  `);
});

module.exports = app;
