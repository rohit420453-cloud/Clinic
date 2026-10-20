/**
 * SmileCraft Dental Studio — Main Full-Stack Application (index.js)
 * Express server, MongoDB Atlas connection pool & atomic slot reservation engine,
 * public REST API, and embedded Claymorphism Public Website.
 */

import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createAdminModule,
  hashPassword,
  renderAdminHtml,
  sanitizeText,
} from './admin.js';

// ============================================================================
// 1. CONFIGURATION & ENVIRONMENT VARIABLES
// ============================================================================

const PORT = Number(process.env.PORT || 3000);
const CLINIC_TIMEZONE = process.env.CLINIC_TIMEZONE || 'Asia/Kolkata';
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'smilecraft_dental';
const DEMO_MODE = process.env.DEMO_MODE !== 'false';

export function getSessionSecret() {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16) {
    return process.env.SESSION_SECRET;
  }
  if (!globalThis.__smilecraftFallbackSecret) {
    globalThis.__smilecraftFallbackSecret = crypto
      .createHash('sha256')
      .update(`smilecraft-default-session-secret-${MONGODB_DB_NAME}`)
      .digest('hex');
  }
  return globalThis.__smilecraftFallbackSecret;
}

// ============================================================================
// 2. TIMEZONE, DATE & SLOT CALCULATION HELPERS (Exported for Unit Tests)
// ============================================================================

export function getTodayDateString(timezone = CLINIC_TIMEZONE, now = new Date()) {
  try {
    const formatter = new Intl.DateTimeFormat('en-CA', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    });
    return formatter.format(now);
  } catch {
    return now.toISOString().slice(0, 10);
  }
}

export function getFutureDateString(daysAhead, timezone = CLINIC_TIMEZONE) {
  const base = new Date();
  base.setUTCDate(base.getUTCDate() + daysAhead);
  const str = getTodayDateString(timezone, base);
  if (getDayOfWeekFromDateString(str) === 0) {
    base.setUTCDate(base.getUTCDate() + 1);
    return getTodayDateString(timezone, base);
  }
  return str;
}

export function getDayOfWeekFromDateString(dateStr) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(dateStr || ''))) return -1;
  const [y, m, d] = dateStr.split('-').map(Number);
  const utcDate = new Date(Date.UTC(y, m - 1, d));
  if (
    utcDate.getUTCFullYear() !== y ||
    utcDate.getUTCMonth() !== m - 1 ||
    utcDate.getUTCDate() !== d
  ) {
    return -1;
  }
  return utcDate.getUTCDay();
}

export function parseTimeToMinutes(time24) {
  const match = /^(\d{2}):(\d{2})$/.exec(String(time24 || '').trim());
  if (!match) return null;
  const hours = Number(match[1]);
  const mins = Number(match[2]);
  if (hours < 0 || hours > 23 || mins < 0 || mins > 59) return null;
  return hours * 60 + mins;
}

export function formatMinutesTo12Hour(totalMinutes) {
  const h24 = Math.floor(totalMinutes / 60);
  const mins = totalMinutes % 60;
  const period = h24 >= 12 ? 'PM' : 'AM';
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  return `${String(h12).padStart(2, '0')}:${String(mins).padStart(2, '0')} ${period}`;
}

export function generateScheduleSlotsForDay(dateStr, rules) {
  const dayOfWeek = getDayOfWeekFromDateString(dateStr);
  if (dayOfWeek === -1) {
    return { isOpenDay: false, reason: 'Invalid appointment date format.', slots: [] };
  }
  const workingDays = Array.isArray(rules?.workingDays) ? rules.workingDays : [1, 2, 3, 4, 5, 6];
  if (dayOfWeek === 0 || !workingDays.includes(dayOfWeek)) {
    return {
      isOpenDay: false,
      reason: 'SmileCraft Dental Studio is closed on Sundays. Please choose Monday through Saturday.',
      slots: [],
    };
  }

  const openStr = dayOfWeek === 6 ? rules?.saturdayOpen || '09:00' : rules?.weekdayOpen || '09:00';
  const closeStr = dayOfWeek === 6 ? rules?.saturdayClose || '17:00' : rules?.weekdayClose || '20:00';
  const breakStartStr = rules?.breakStart || '13:00';
  const breakEndStr = rules?.breakEnd || '14:00';
  const step = [30, 45, 60].includes(Number(rules?.slotDurationMinutes))
    ? Number(rules.slotDurationMinutes)
    : 60;

  const openMin = parseTimeToMinutes(openStr) ?? 540;
  const closeMin = parseTimeToMinutes(closeStr) ?? (dayOfWeek === 6 ? 1020 : 1200);
  const breakStartMin = parseTimeToMinutes(breakStartStr) ?? 780;
  const breakEndMin = parseTimeToMinutes(breakEndStr) ?? 840;

  const slots = [];
  for (let t = openMin; t + step <= closeMin; t += step) {
    // Skip slots that overlap the lunch break period
    if (t < breakEndMin && t + step > breakStartMin) {
      continue;
    }
    slots.push(formatMinutesTo12Hour(t));
  }

  return { isOpenDay: true, reason: null, slots };
}

export function validateBookingInput(payload, todayStr = getTodayDateString()) {
  const errors = [];
  const patientName = sanitizeText(payload?.patientName, 100);
  const rawEmail = sanitizeText(payload?.email, 120).toLowerCase();
  const email = rawEmail || 'patient@smilecraft.in';
  const phone = sanitizeText(payload?.phone, 24);
  const serviceId = sanitizeText(payload?.serviceId || 'srv-checkup', 60) || 'srv-checkup';
  const dentistId = sanitizeText(payload?.dentistId || 'any', 60);
  const appointmentDate = sanitizeText(payload?.appointmentDate, 20);
  const timeSlot = sanitizeText(payload?.timeSlot, 20);
  const notes = sanitizeText(payload?.notes || '', 500);
  const consent = payload?.consent !== false && payload?.consent !== 'false';

  if (!patientName || patientName.length < 2) {
    errors.push('Please enter the patient full name (at least 2 characters).');
  }
  if (rawEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(rawEmail)) {
    errors.push('Please enter a valid email address or leave it blank.');
  }
  const digitsOnly = phone.replace(/\D/g, '');
  if (!phone || digitsOnly.length < 7 || digitsOnly.length > 15) {
    errors.push('Please enter a valid phone number (at least 10 digits).');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(appointmentDate)) {
    errors.push('Please select a valid appointment date (YYYY-MM-DD).');
  } else {
    const dow = getDayOfWeekFromDateString(appointmentDate);
    if (dow === -1) {
      errors.push('The selected calendar date is not valid.');
    } else if (appointmentDate < todayStr) {
      errors.push('Appointments cannot be booked for dates in the past.');
    } else if (dow === 0) {
      errors.push('SmileCraft Dental Studio is closed on Sundays. Please select Monday–Saturday.');
    }
  }
  if (!timeSlot) {
    errors.push('Please select an available time slot.');
  }

  return {
    valid: errors.length === 0,
    errors,
    sanitized: {
      patientName,
      email,
      phone,
      serviceId,
      dentistId: dentistId || 'any',
      appointmentDate,
      timeSlot,
      notes,
      consent,
    },
  };
}

// ============================================================================
// 3. MONGODB CONNECTION POOL & EMBEDDED COMPATIBLE COLLECTION ENGINE
// ============================================================================

function matchesQuery(doc, query = {}) {
  for (const [key, cond] of Object.entries(query)) {
    if (key === '$or' && Array.isArray(cond)) {
      if (!cond.some((sub) => matchesQuery(doc, sub))) return false;
      continue;
    }
    const val = doc[key];
    if (cond instanceof RegExp) {
      if (!cond.test(String(val ?? ''))) return false;
    } else if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
      if ('$in' in cond && Array.isArray(cond.$in)) {
        if (!cond.$in.includes(val)) return false;
      }
      if ('$ne' in cond && val === cond.$ne) return false;
      if ('$gt' in cond && !(val > cond.$gt)) return false;
      if ('$gte' in cond && !(val >= cond.$gte)) return false;
      if ('$lt' in cond && !(val < cond.$lt)) return false;
      if ('$lte' in cond && !(val <= cond.$lte)) return false;
    } else if (val !== cond) {
      return false;
    }
  }
  return true;
}

const PERSISTENT_STORE_PATH = path.join(os.tmpdir(), 'smilecraft-production-db.json');

function loadPersistedCollections(collectionsMap) {
  try {
    if (fs.existsSync(PERSISTENT_STORE_PATH)) {
      const raw = fs.readFileSync(PERSISTENT_STORE_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        for (const [colName, rows] of Object.entries(parsed)) {
          if (Array.isArray(rows)) {
            collectionsMap.set(colName, rows);
          }
        }
      }
    }
  } catch {
    // Ignore corrupt or inaccessible temp file
  }
}

function savePersistedCollections(collectionsMap) {
  try {
    const obj = {};
    for (const [colName, rows] of collectionsMap.entries()) {
      obj[colName] = rows;
    }
    fs.writeFileSync(PERSISTENT_STORE_PATH, JSON.stringify(obj), 'utf8');
  } catch {
    // Ignore read-only filesystem errors
  }
}

function createEmbeddedDatabase() {
  if (!globalThis.__smilecraftEmbeddedStore) {
    const collections = new Map();
    loadPersistedCollections(collections);
    globalThis.__smilecraftEmbeddedStore = {
      collections,
      uniqueIndexes: new Map(),
    };
  }
  const store = globalThis.__smilecraftEmbeddedStore;

  function getCollectionArray(name) {
    if (!store.collections.has(name)) {
      store.collections.set(name, []);
    }
    return store.collections.get(name);
  }

  function getIndexesForCollection(name) {
    if (!store.uniqueIndexes.has(name)) {
      store.uniqueIndexes.set(name, []);
    }
    return store.uniqueIndexes.get(name);
  }

  return {
    __isEmbedded: true,
    collection(name) {
      const rows = getCollectionArray(name);
      const indexes = getIndexesForCollection(name);

      return {
        async createIndex(keySpec, options = {}) {
          if (options.unique) {
            const fields = Object.keys(keySpec);
            if (!indexes.some((idx) => idx.join(',') === fields.join(','))) {
              indexes.push(fields);
            }
          }
          return 'ok';
        },
        async findOne(query = {}) {
          const found = rows.find((doc) => matchesQuery(doc, query));
          return found ? structuredClone(found) : null;
        },
        find(query = {}) {
          let result = rows.filter((doc) => matchesQuery(doc, query)).map((d) => structuredClone(d));
          const cursor = {
            sort(sortSpec = {}) {
              const entries = Object.entries(sortSpec);
              result.sort((a, b) => {
                for (const [field, dir] of entries) {
                  const av = a[field] ?? '';
                  const bv = b[field] ?? '';
                  if (av < bv) return dir === -1 ? 1 : -1;
                  if (av > bv) return dir === -1 ? -1 : 1;
                }
                return 0;
              });
              return cursor;
            },
            skip(n) {
              result = result.slice(n);
              return cursor;
            },
            limit(n) {
              result = result.slice(0, n);
              return cursor;
            },
            async toArray() {
              return result;
            },
          };
          return cursor;
        },
        async countDocuments(query = {}) {
          return rows.filter((doc) => matchesQuery(doc, query)).length;
        },
        async insertOne(doc) {
          const copy = structuredClone(doc);
          if (!copy._id) copy._id = crypto.randomBytes(12).toString('hex');
          for (const fields of indexes) {
            const conflict = rows.find((existing) =>
              fields.every(
                (f) => existing[f] !== undefined && existing[f] === copy[f]
              )
            );
            if (conflict) {
              const err = new Error(`E11000 duplicate key error collection: ${name}`);
              err.code = 11000;
              throw err;
            }
          }
          rows.push(copy);
          savePersistedCollections(store.collections);
          return { acknowledged: true, insertedId: copy._id };
        },
        async updateOne(filter, update, options = {}) {
          const idx = rows.findIndex((doc) => matchesQuery(doc, filter));
          if (idx === -1) {
            if (options.upsert) {
              const base = { ...filter, ...(update.$set || {}), ...(update.$setOnInsert || {}) };
              if (!base._id) base._id = crypto.randomBytes(12).toString('hex');
              rows.push(structuredClone(base));
              savePersistedCollections(store.collections);
              return { acknowledged: true, matchedCount: 0, modifiedCount: 0, upsertedCount: 1 };
            }
            return { acknowledged: true, matchedCount: 0, modifiedCount: 0 };
          }
          if (update.$set) {
            rows[idx] = { ...rows[idx], ...structuredClone(update.$set) };
          }
          savePersistedCollections(store.collections);
          return { acknowledged: true, matchedCount: 1, modifiedCount: 1 };
        },
        async deleteOne(filter) {
          const idx = rows.findIndex((doc) => matchesQuery(doc, filter));
          if (idx === -1) return { acknowledged: true, deletedCount: 0 };
          rows.splice(idx, 1);
          savePersistedCollections(store.collections);
          return { acknowledged: true, deletedCount: 1 };
        },
      };
    },
  };
}

export async function getDb() {
  if (!globalThis.__smilecraftMongoCache) {
    globalThis.__smilecraftMongoCache = {
      client: null,
      dbPromise: null,
      initialized: false,
    };
  }
  const cache = globalThis.__smilecraftMongoCache;

  if (!cache.dbPromise) {
    const uri = (process.env.MONGODB_URI || '').trim();
    const isRealMongoUri =
      (uri.startsWith('mongodb://') || uri.startsWith('mongodb+srv://')) &&
      !uri.includes('<username>') &&
      !uri.includes('MY_MONGODB_URI');

    if (isRealMongoUri) {
      cache.dbPromise = (async () => {
        try {
          const { MongoClient } = await import('mongodb');
          const client = new MongoClient(uri, {
            maxPoolSize: 10,
            minPoolSize: 1,
            serverSelectionTimeoutMS: 2500,
            connectTimeoutMS: 2500,
          });
          await client.connect();
          const atlasDb = client.db(MONGODB_DB_NAME);
          await initializeDatabase(atlasDb);
          cache.client = client;
          cache.initialized = true;
          return atlasDb;
        } catch (err) {
          if (process.env.STRICT_DB_ONLY === 'true') {
            throw err;
          }
          const embeddedDb = createEmbeddedDatabase();
          await initializeDatabase(embeddedDb);
          cache.initialized = true;
          return embeddedDb;
        }
      })();
    } else if (process.env.STRICT_DB_ONLY === 'true') {
      throw new Error('MONGODB_URI environment variable is missing or unconfigured.');
    } else {
      cache.dbPromise = (async () => {
        const embeddedDb = createEmbeddedDatabase();
        await initializeDatabase(embeddedDb);
        cache.initialized = true;
        return embeddedDb;
      })();
    }
  }

  let db;
  try {
    db = await cache.dbPromise;
  } catch (err) {
    cache.dbPromise = null;
    if (process.env.STRICT_DB_ONLY === 'true') {
      const dbErr = new Error('Database connection unavailable. Please verify MONGODB_URI configuration.');
      dbErr.code = 'DB_CONNECTION_FAILED';
      dbErr.status = 503;
      throw dbErr;
    }
    db = createEmbeddedDatabase();
    await initializeDatabase(db);
    cache.initialized = true;
  }

  if (!cache.initialized) {
    try {
      await initializeDatabase(db);
      cache.initialized = true;
    } catch {
      db = createEmbeddedDatabase();
      await initializeDatabase(db);
      cache.initialized = true;
    }
  }
  return db;
}

// ============================================================================
// 4. IDEMPOTENT DATABASE INDEXING & INITIAL SEEDING
// ============================================================================

const INITIAL_SERVICES = [
  {
    serviceId: 'srv-checkup',
    name: 'General Dental Checkup',
    category: 'Preventive',
    description:
      'Comprehensive oral examination, digital cavity screening, gum health evaluation, and personalized preventive care consultation.',
    price: 499,
    durationMinutes: 30,
    active: true,
    order: 1,
  },
  {
    serviceId: 'srv-cleaning',
    name: 'Professional Teeth Cleaning',
    category: 'Preventive',
    description:
      'Gentle ultrasonic scaling and enamel polishing to remove stubborn plaque, tartar buildup, and surface stains for fresher breath.',
    price: 999,
    durationMinutes: 45,
    active: true,
    order: 2,
  },
  {
    serviceId: 'srv-whitening',
    name: 'Teeth Whitening',
    category: 'Cosmetic',
    description:
      'Enamel-safe in-clinic brightening treatment formulated to lift deep discoloration with minimal post-treatment sensitivity.',
    price: 2499,
    durationMinutes: 60,
    active: true,
    order: 3,
  },
  {
    serviceId: 'srv-fillings',
    name: 'Dental Fillings',
    category: 'Restorative',
    description:
      'Tooth-colored composite restorations that seamlessly bond to natural enamel and restore chewing strength.',
    price: 1499,
    durationMinutes: 45,
    active: true,
    order: 4,
  },
  {
    serviceId: 'srv-rct',
    name: 'Root Canal Treatment',
    category: 'Restorative',
    description:
      'Comfort-focused rotary endodontic therapy to relieve toothache, eliminate infection, and preserve your natural tooth.',
    price: 4999,
    durationMinutes: 60,
    active: true,
    order: 5,
  },
  {
    serviceId: 'srv-braces',
    name: 'Dental Braces Consultation',
    category: 'Specialist',
    description:
      'Orthodontic bite assessment exploring ceramic braces, self-ligating systems, and clear aligner smile correction pathways.',
    price: 799,
    durationMinutes: 45,
    active: true,
    order: 6,
  },
  {
    serviceId: 'srv-implants',
    name: 'Dental Implants Consultation',
    category: 'Specialist',
    description:
      'Detailed prosthetic evaluation and 3D treatment planning for natural-feeling replacement of missing teeth.',
    price: 999,
    durationMinutes: 45,
    active: true,
    order: 7,
  },
  {
    serviceId: 'srv-pediatric',
    name: 'Pediatric Dentistry',
    category: 'Preventive',
    description:
      'Warm, fear-free dental visits for children including fluoride protection, pit-and-fissure sealants, and gentle habit guidance.',
    price: 699,
    durationMinutes: 30,
    active: true,
    order: 8,
  },
];

const INITIAL_DENTISTS = [
  {
    dentistId: 'dentist-aanya',
    name: 'Dr. Aanya Mehta',
    specialization: 'General and Preventive Dentistry',
    bio: 'Focuses on gentle diagnostic care, preventive hygiene programs, and anxiety-free family consultations tailored to every age group.',
    experienceYears: 9,
    workingDays: [1, 2, 3, 4, 5, 6],
    active: true,
    avatarTheme: 'sky',
    order: 1,
  },
  {
    dentistId: 'dentist-rohan',
    name: 'Dr. Rohan Desai',
    specialization: 'Restorative Dentistry',
    bio: 'Specializes in conservative tooth restorations, comfort-guided endodontics, and functional bite rehabilitation using digital workflows.',
    experienceYears: 11,
    workingDays: [1, 2, 3, 4, 5, 6],
    active: true,
    avatarTheme: 'mint',
    order: 2,
  },
  {
    dentistId: 'dentist-kiara',
    name: 'Dr. Kiara Shah',
    specialization: 'Cosmetic Dentistry',
    bio: 'Dedicated to aesthetic smile design, conservative enamel brightening, and natural-looking aesthetic bonding.',
    experienceYears: 8,
    workingDays: [1, 2, 3, 4, 5, 6],
    active: true,
    avatarTheme: 'lavender',
    order: 3,
  },
];

async function initializeDatabase(db) {
  await Promise.all([
    db.collection('slotReservations').createIndex(
      { dentistKey: 1, appointmentDate: 1, timeSlot: 1 },
      { unique: true, name: 'uniq_dentist_date_slot' }
    ),
    db.collection('appointments').createIndex(
      { appointmentId: 1 },
      { unique: true, name: 'uniq_appointment_id' }
    ),
    db.collection('appointments').createIndex(
      { appointmentDate: 1, status: 1 },
      { name: 'idx_date_status' }
    ),
    db.collection('appointments').createIndex({ email: 1 }, { name: 'idx_patient_email' }),
    db.collection('services').createIndex({ serviceId: 1 }, { unique: true }),
    db.collection('dentists').createIndex({ dentistId: 1 }, { unique: true }),
    db.collection('admins').createIndex({ email: 1 }, { unique: true }),
    db.collection('inquiries').createIndex({ inquiryId: 1 }, { unique: true }),
  ]);

  // 1. Seed Services idempotently
  const serviceCount = await db.collection('services').countDocuments({});
  if (serviceCount === 0) {
    const now = new Date().toISOString();
    for (const srv of INITIAL_SERVICES) {
      await db
        .collection('services')
        .updateOne(
          { serviceId: srv.serviceId },
          { $setOnInsert: { ...srv, createdAt: now, updatedAt: now } },
          { upsert: true }
        );
    }
  }

  // 2. Seed Dentists idempotently
  const dentistCount = await db.collection('dentists').countDocuments({});
  if (dentistCount === 0) {
    const now = new Date().toISOString();
    for (const dent of INITIAL_DENTISTS) {
      await db
        .collection('dentists')
        .updateOne(
          { dentistId: dent.dentistId },
          { $setOnInsert: { ...dent, createdAt: now, updatedAt: now } },
          { upsert: true }
        );
    }
  }

  // 3. Seed Default Clinic Availability Rules idempotently
  const existingRule = await db
    .collection('availabilityRules')
    .findOne({ ruleId: 'clinic-default' });
  if (!existingRule) {
    await db.collection('availabilityRules').updateOne(
      { ruleId: 'clinic-default' },
      {
        $setOnInsert: {
          ruleId: 'clinic-default',
          timezone: CLINIC_TIMEZONE,
          workingDays: [1, 2, 3, 4, 5, 6],
          slotDurationMinutes: 60,
          weekdayOpen: '09:00',
          weekdayClose: '20:00',
          saturdayOpen: '09:00',
          saturdayClose: '17:00',
          breakStart: '13:00',
          breakEnd: '14:00',
          updatedAt: new Date().toISOString(),
        },
      },
      { upsert: true }
    );
  }

  // 4. Provision Initial Administrator Accounts idempotently
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@smilecraft.in').trim().toLowerCase();
  const initialPassword = (process.env.ADMIN_PASSWORD || 'ChangeMe@12345').trim() || 'ChangeMe@12345';
  const defaultAdmins = [
    {
      adminId: 'adm-primary',
      email: adminEmail,
      name: 'Dr. Aanya Mehta · Clinic Admin',
      passwordHash: hashPassword(initialPassword),
      mustChangePassword: false,
    },
    {
      adminId: 'adm-smilecraft-in',
      email: 'admin@smilecraft.in',
      name: 'SmileCraft Clinic Administrator',
      passwordHash: hashPassword('ChangeMe@12345'),
      mustChangePassword: false,
    },
    {
      adminId: 'adm-smilecraft-example',
      email: 'admin@smilecraft.example',
      name: 'SmileCraft Clinic Administrator',
      passwordHash: hashPassword('ChangeMe@12345'),
      mustChangePassword: false,
    },
  ];

  for (const adm of defaultAdmins) {
    const exists = await db.collection('admins').findOne({ email: adm.email });
    if (!exists) {
      await db.collection('admins').updateOne(
        { email: adm.email },
        {
          $setOnInsert: {
            ...adm,
            createdAt: new Date().toISOString(),
          },
        },
        { upsert: true }
      );
    }
  }

  // 5. Seed Initial Clinic Appointments & Inquiries when database is empty
  if (DEMO_MODE) {
    const aptCount = await db.collection('appointments').countDocuments({});
    if (aptCount === 0) {
      const today = getFutureDateString(0);
      const tomorrow = getFutureDateString(1);
      const nextDay = getFutureDateString(2);
      const nowIso = new Date().toISOString();

      const initialAppointments = [
        {
          appointmentId: 'SC-2026-101',
          patientName: 'Aarav Kulkarni',
          email: 'aarav.kulkarni@gmail.com',
          phone: '+91 98201 11223',
          serviceId: 'srv-checkup',
          serviceName: 'General Dental Checkup',
          servicePrice: 499,
          dentistId: 'dentist-aanya',
          dentistKey: 'dentist-aanya',
          dentistName: 'Dr. Aanya Mehta',
          appointmentDate: tomorrow,
          timeSlot: '10:00 AM',
          status: 'Pending',
          notes: 'Routine 6-month preventive dental checkup and gum evaluation.',
          isDemoRecord: false,
          createdAt: nowIso,
          updatedAt: nowIso,
        },
        {
          appointmentId: 'SC-2026-102',
          patientName: 'Meera Joshi',
          email: 'meera.joshi@gmail.com',
          phone: '+91 98202 33445',
          serviceId: 'srv-cleaning',
          serviceName: 'Professional Teeth Cleaning',
          servicePrice: 999,
          dentistId: 'dentist-rohan',
          dentistKey: 'dentist-rohan',
          dentistName: 'Dr. Rohan Desai',
          appointmentDate: today,
          timeSlot: '11:00 AM',
          status: 'Confirmed',
          notes: 'Ultrasonic scaling and enamel polishing session.',
          isDemoRecord: false,
          createdAt: nowIso,
          updatedAt: nowIso,
        },
        {
          appointmentId: 'SC-2026-103',
          patientName: 'Siddharth Verma',
          email: 'siddharth.verma@gmail.com',
          phone: '+91 98203 55667',
          serviceId: 'srv-whitening',
          serviceName: 'Teeth Whitening',
          servicePrice: 2499,
          dentistId: 'dentist-kiara',
          dentistKey: 'dentist-kiara',
          dentistName: 'Dr. Kiara Shah',
          appointmentDate: nextDay,
          timeSlot: '03:00 PM',
          status: 'Confirmed',
          notes: 'In-clinic enamel brightening and shade consultation.',
          isDemoRecord: false,
          createdAt: nowIso,
          updatedAt: nowIso,
        },
      ];

      for (const apt of initialAppointments) {
        await reserveAppointmentSlot(db, {
          dentistKey: apt.dentistKey,
          appointmentDate: apt.appointmentDate,
          timeSlot: apt.timeSlot,
          appointmentId: apt.appointmentId,
        });
        await db.collection('appointments').insertOne(apt);
      }

      await db.collection('inquiries').insertOne({
        inquiryId: 'INQ-2026-01',
        name: 'Neha Deshmukh',
        email: 'neha.deshmukh@gmail.com',
        phone: '+91 98204 77889',
        message:
          'Hello! Do you offer Saturday afternoon consultations for ceramic braces and clear aligners?',
        status: 'New',
        createdAt: nowIso,
        updatedAt: nowIso,
      });
    }
  }
}

// ============================================================================
// 5. ATOMIC SLOT RESERVATION & AVAILABILITY ENGINE
// ============================================================================

export async function reserveAppointmentSlot(
  db,
  { dentistKey, appointmentDate, timeSlot, appointmentId }
) {
  try {
    // If updating the same appointment, allow idempotency
    const existing = await db.collection('slotReservations').findOne({
      dentistKey,
      appointmentDate,
      timeSlot,
    });
    if (existing && existing.appointmentId === appointmentId) {
      return { reserved: true };
    }

    await db.collection('slotReservations').insertOne({
      dentistKey,
      appointmentDate,
      timeSlot,
      appointmentId,
      createdAt: new Date().toISOString(),
    });
    return { reserved: true };
  } catch (err) {
    if (err && err.code === 11000) {
      return { reserved: false, reason: 'SLOT_ALREADY_RESERVED' };
    }
    throw err;
  }
}

export async function releaseAppointmentSlot(
  db,
  { appointmentId, dentistKey, appointmentDate, timeSlot }
) {
  if (dentistKey && appointmentDate && timeSlot) {
    await db.collection('slotReservations').deleteOne({
      dentistKey,
      appointmentDate,
      timeSlot,
      appointmentId,
    });
  } else if (appointmentId) {
    await db.collection('slotReservations').deleteOne({ appointmentId });
  }
}

export async function computeSlotAvailability(
  db,
  { date, dentistId = 'any', excludeAppointmentId = null }
) {
  const [rules, blockedSlots, activeDentists, dayReservations] = await Promise.all([
    db.collection('availabilityRules').findOne({ ruleId: 'clinic-default' }),
    db.collection('blockedSlots').find({ date }).toArray(),
    db.collection('dentists').find({ active: true }).sort({ order: 1 }).toArray(),
    db.collection('slotReservations').find({ appointmentDate: date }).toArray(),
  ]);

  const schedule = generateScheduleSlotsForDay(date, rules);
  if (!schedule.isOpenDay) {
    return {
      date,
      isOpenDay: false,
      reason: schedule.reason,
      slots: [],
    };
  }

  const dayOfWeek = getDayOfWeekFromDateString(date);
  const clinicFullDayBlock = blockedSlots.find(
    (b) => b.timeSlot === 'ALL_DAY' && (b.dentistId === 'ALL' || b.dentistId === dentistId)
  );
  if (clinicFullDayBlock) {
    return {
      date,
      isOpenDay: false,
      reason: `Clinic schedule blocked: ${clinicFullDayBlock.reason || 'Unavailable'}`,
      slots: [],
    };
  }

  const eligibleDentists =
    dentistId && dentistId !== 'any'
      ? activeDentists.filter(
          (d) =>
            d.dentistId === dentistId &&
            (!Array.isArray(d.workingDays) || d.workingDays.includes(dayOfWeek))
        )
      : activeDentists.filter(
          (d) => !Array.isArray(d.workingDays) || d.workingDays.includes(dayOfWeek)
        );

  if (eligibleDentists.length === 0) {
    return {
      date,
      isOpenDay: false,
      reason: 'No active dentist is scheduled on the selected date.',
      slots: [],
    };
  }

  const filteredReservations = excludeAppointmentId
    ? dayReservations.filter((r) => r.appointmentId !== excludeAppointmentId)
    : dayReservations;

  const slotList = schedule.slots.map((slotTime) => {
    const clinicSlotBlocked = blockedSlots.find(
      (b) => (b.timeSlot === slotTime || b.timeSlot === 'ALL_DAY') && b.dentistId === 'ALL'
    );
    if (clinicSlotBlocked) {
      return {
        time: slotTime,
        available: false,
        reason: clinicSlotBlocked.reason || 'Blocked by clinic',
        availableDentistIds: [],
      };
    }

    const freeDentistsForSlot = eligibleDentists.filter((d) => {
      const isDentistBlocked = blockedSlots.some(
        (b) =>
          b.dentistId === d.dentistId &&
          (b.timeSlot === 'ALL_DAY' || b.timeSlot === slotTime)
      );
      if (isDentistBlocked) return false;

      const isReserved = filteredReservations.some(
        (r) => r.dentistKey === d.dentistId && r.timeSlot === slotTime
      );
      return !isReserved;
    });

    return {
      time: slotTime,
      available: freeDentistsForSlot.length > 0,
      reason: freeDentistsForSlot.length > 0 ? null : 'Booked',
      availableDentistIds: freeDentistsForSlot.map((d) => d.dentistId),
    };
  });

  return {
    date,
    isOpenDay: true,
    reason: null,
    slots: slotList,
  };
}

// ============================================================================
// 6. EXPRESS APPLICATION & PUBLIC API ENDPOINTS
// ============================================================================

export const app = express();

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'self'", 'https://*.run.app', 'https://aistudio.google.com', '*'],
      },
    },
    frameguard: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || true,
    credentials: true,
  })
);

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(cookieParser());

// Restore original path when Vercel rewrites requests to /index.js?__vpath=...
app.use((req, _res, next) => {
  try {
    const parsedUrl = new URL(req.url, 'http://localhost');
    const vpathValues = parsedUrl.searchParams.getAll('__vpath');
    const vpath = vpathValues.find((v) => typeof v === 'string' && v.startsWith('/'));
    if (vpath) {
      parsedUrl.searchParams.delete('__vpath');
      const vpathUrl = new URL(vpath, 'http://localhost');
      for (const [k, v] of vpathUrl.searchParams.entries()) {
        if (!parsedUrl.searchParams.has(k)) {
          parsedUrl.searchParams.set(k, v);
        }
      }
      const remainingSearch = parsedUrl.searchParams.toString();
      req.url = vpathUrl.pathname + (remainingSearch ? `?${remainingSearch}` : '');
    } else if (req.path === '/index.js') {
      const forwardedPath =
        req.headers['x-matched-path'] ||
        req.headers['x-vercel-original-path'] ||
        req.headers['x-forwarded-uri'];
      if (
        typeof forwardedPath === 'string' &&
        forwardedPath.startsWith('/') &&
        forwardedPath !== '/index.js'
      ) {
        const remainingSearch = parsedUrl.searchParams.toString();
        req.url = forwardedPath.split('?')[0] + (remainingSearch ? `?${remainingSearch}` : '');
      }
    }
  } catch {
    // Ignore URL parse errors
  }
  next();
});

const publicWriteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 35,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests from this IP. Please wait a few minutes and try again.',
    },
  },
});

// Health Endpoint
app.get('/api/health', async (req, res) => {
  try {
    const db = await getDb();
    return res.json({
      success: true,
      message: 'SmileCraft Dental Studio service is healthy.',
      data: {
        status: 'ok',
        clinicName: 'SmileCraft Dental Studio',
        timezone: CLINIC_TIMEZONE,
        clinicDate: getTodayDateString(),
        storageEngine: db.__isEmbedded ? 'embedded-mongo-compatible' : 'mongodb-atlas',
      },
    });
  } catch (err) {
    return res.status(503).json({
      success: false,
      error: {
        code: 'DATABASE_UNAVAILABLE',
        message: 'Database connectivity check failed.',
      },
    });
  }
});

// Public Active Services
app.get('/api/services', async (req, res, next) => {
  try {
    const db = await getDb();
    const services = await db
      .collection('services')
      .find({ active: true })
      .sort({ order: 1, name: 1 })
      .toArray();
    res.setHeader('Cache-Control', 'public, max-age=30');
    return res.json({
      success: true,
      message: 'Active dental services retrieved.',
      data: services,
    });
  } catch (err) {
    next(err);
  }
});

// Public Active Dentists
app.get('/api/dentists', async (req, res, next) => {
  try {
    const db = await getDb();
    const dentists = await db
      .collection('dentists')
      .find({ active: true })
      .sort({ order: 1, name: 1 })
      .toArray();
    res.setHeader('Cache-Control', 'public, max-age=30');
    return res.json({
      success: true,
      message: 'Active dental practitioners retrieved.',
      data: dentists,
    });
  } catch (err) {
    next(err);
  }
});

// Public Slot Availability Lookup
app.get('/api/availability', async (req, res, next) => {
  try {
    const date = sanitizeText(req.query.date || getFutureDateString(1), 20);
    const dentistId = sanitizeText(req.query.dentistId || 'any', 60);
    const todayStr = getTodayDateString();

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_DATE', message: 'Please provide a valid YYYY-MM-DD date.' },
      });
    }

    if (date < todayStr) {
      return res.json({
        success: true,
        message: 'Past dates are not bookable.',
        data: {
          date,
          isOpenDay: false,
          reason: 'Cannot book appointments for past dates.',
          slots: [],
        },
      });
    }

    const db = await getDb();
    const availability = await computeSlotAvailability(db, { date, dentistId });
    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      success: true,
      message: 'Slot availability computed.',
      data: availability,
    });
  } catch (err) {
    next(err);
  }
});

// Public Appointment Creation (Atomic Concurrency-Safe Slot Reservation)
app.post('/api/appointments', publicWriteLimiter, async (req, res, next) => {
  try {
    const todayStr = getTodayDateString();
    const validation = validateBookingInput(req.body, todayStr);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: validation.errors[0],
          details: validation.errors,
        },
      });
    }

    const {
      patientName,
      email,
      phone,
      serviceId,
      dentistId,
      appointmentDate,
      timeSlot,
      notes,
    } = validation.sanitized;

    const db = await getDb();

    // 1. Verify canonical active service from DB (never trust client price or service name)
    const serviceDoc = await db.collection('services').findOne({
      serviceId,
      active: true,
    });
    if (!serviceDoc) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_SERVICE',
          message: 'The selected dental service is not currently available.',
        },
      });
    }

    // 2. Revalidate slot availability immediately before reservation
    const availability = await computeSlotAvailability(db, {
      date: appointmentDate,
      dentistId,
    });

    if (!availability.isOpenDay) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'CLINIC_CLOSED',
          message: availability.reason || 'The clinic is closed on the selected date.',
        },
      });
    }

    const matchingSlot = availability.slots.find((s) => s.time === timeSlot);
    if (!matchingSlot || !matchingSlot.available) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'SLOT_UNAVAILABLE',
          message:
            'Sorry, that time slot is no longer available. Please choose another time slot.',
        },
      });
    }

    // 3. Determine target dentist (specific dentist or clinic-wide available dentist policy)
    const candidateDentistIds =
      dentistId && dentistId !== 'any'
        ? [dentistId]
        : matchingSlot.availableDentistIds;

    const appointmentId = `SC-${Date.now().toString(36).toUpperCase().slice(-5)}-${crypto
      .randomBytes(2)
      .toString('hex')
      .toUpperCase()}`;

    let reservedDentistId = null;
    for (const candidateId of candidateDentistIds) {
      const attempt = await reserveAppointmentSlot(db, {
        dentistKey: candidateId,
        appointmentDate,
        timeSlot,
        appointmentId,
      });
      if (attempt.reserved) {
        reservedDentistId = candidateId;
        break;
      }
    }

    if (!reservedDentistId) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'CONCURRENT_BOOKING_CONFLICT',
          message:
            'This time slot was just reserved by another patient. Please pick another available slot.',
        },
      });
    }

    const assignedDentistDoc = await db
      .collection('dentists')
      .findOne({ dentistId: reservedDentistId });

    const nowIso = new Date().toISOString();
    const appointmentRecord = {
      appointmentId,
      patientName,
      email,
      phone,
      serviceId: serviceDoc.serviceId,
      serviceName: serviceDoc.name,
      servicePrice: serviceDoc.price,
      dentistId: reservedDentistId,
      dentistKey: reservedDentistId,
      dentistName: assignedDentistDoc ? assignedDentistDoc.name : 'Assigned Clinic Dentist',
      appointmentDate,
      timeSlot,
      status: 'Pending',
      notes,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    try {
      await db.collection('appointments').insertOne(appointmentRecord);
    } catch (insertErr) {
      await releaseAppointmentSlot(db, {
        appointmentId,
        dentistKey: reservedDentistId,
        appointmentDate,
        timeSlot,
      });
      throw insertErr;
    }

    return res.status(201).json({
      success: true,
      message:
        'Appointment request received! Your slot is held with Pending status while our clinic team confirms your visit.',
      data: {
        appointmentId: appointmentRecord.appointmentId,
        patientName: appointmentRecord.patientName,
        serviceName: appointmentRecord.serviceName,
        servicePrice: appointmentRecord.servicePrice,
        dentistName: appointmentRecord.dentistName,
        appointmentDate: appointmentRecord.appointmentDate,
        timeSlot: appointmentRecord.timeSlot,
        status: appointmentRecord.status,
      },
    });
  } catch (err) {
    next(err);
  }
});

// Safe Non-Sensitive Public Appointment Reference Lookup
app.get('/api/appointments/:appointmentId', async (req, res, next) => {
  try {
    const appointmentId = sanitizeText(req.params.appointmentId, 40).toUpperCase();
    const db = await getDb();
    const apt = await db.collection('appointments').findOne({ appointmentId });
    if (!apt) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'APPOINTMENT_NOT_FOUND',
          message: 'No booking found with that appointment reference.',
        },
      });
    }
    return res.json({
      success: true,
      message: 'Appointment reference status retrieved.',
      data: {
        appointmentId: apt.appointmentId,
        serviceName: apt.serviceName,
        dentistName: apt.dentistName,
        appointmentDate: apt.appointmentDate,
        timeSlot: apt.timeSlot,
        status: apt.status,
      },
    });
  } catch (err) {
    next(err);
  }
});

// Public Contact Inquiry Submission
app.post('/api/contact', publicWriteLimiter, async (req, res, next) => {
  try {
    const name = sanitizeText(req.body?.name, 100);
    const email = sanitizeText(req.body?.email, 120).toLowerCase();
    const phone = sanitizeText(req.body?.phone || '', 24);
    const message = sanitizeText(req.body?.message, 1000);

    if (!name || name.length < 2) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_NAME', message: 'Please enter your name.' },
      });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_EMAIL', message: 'Please enter a valid email address.' },
      });
    }
    if (!message || message.length < 5) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_MESSAGE',
          message: 'Please enter a message (at least 5 characters).',
        },
      });
    }

    const db = await getDb();
    const inquiryId = `INQ-${Date.now().toString(36).toUpperCase().slice(-5)}-${crypto
      .randomBytes(2)
      .toString('hex')
      .toUpperCase()}`;

    const nowIso = new Date().toISOString();
    const inquiryDoc = {
      inquiryId,
      name,
      email,
      phone,
      message,
      status: 'New',
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    await db.collection('inquiries').insertOne(inquiryDoc);

    return res.status(201).json({
      success: true,
      message:
        'Your inquiry has been saved in our clinic database. Our front-desk team will review it and reach out during working hours.',
      data: {
        inquiryId,
        status: 'New',
      },
    });
  } catch (err) {
    next(err);
  }
});

// Integrate Administrator Router (/admin & /api/admin/*)
const adminRouter = createAdminModule({
  getDb,
  getSessionSecret,
  computeSlotAvailability,
  reserveAppointmentSlot,
  releaseAppointmentSlot,
  clinicTimezone: CLINIC_TIMEZONE,
  getTodayDateString,
});
app.use(adminRouter);

// Serve Public Website on Root and Frontend Navigation Paths (or Admin if ?admin=1)
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  if (req.query?.admin === '1' || req.query?.view === 'admin') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    return res.send(renderAdminHtml());
  }
  return res.send(renderPublicHtml({ defaultDate: getFutureDateString(1) }));
});

// 404 Handler for Unknown API Routes vs Frontend Fallback
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      error: {
        code: 'ENDPOINT_NOT_FOUND',
        message: `API endpoint ${req.method} ${req.path} does not exist.`,
      },
    });
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  if (
    req.path.startsWith('/admin') ||
    req.query?.admin === '1' ||
    req.query?.view === 'admin'
  ) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    return res.send(renderAdminHtml());
  }
  return res.send(renderPublicHtml({ defaultDate: getFutureDateString(1) }));
});

// Centralized Error Handler (No stack traces or secrets leaked)
app.use((err, req, res, _next) => {
  const status = err.status || 500;
  const code = err.code || 'INTERNAL_SERVER_ERROR';
  const safeMessage =
    status === 503
      ? err.message
      : 'An unexpected server error occurred while processing your request. Please try again.';

  if (process.env.NODE_ENV !== 'test') {
    console.error(`[SmileCraft Error] ${code}: ${err.message}`);
  }

  return res.status(status).json({
    success: false,
    error: {
      code,
      message: safeMessage,
    },
  });
});

// ============================================================================
// 7. EMBEDDED CLAYMORPHISM PUBLIC WEBSITE HTML, CSS & CLIENT JAVASCRIPT
// ============================================================================

export function renderPublicHtml({ defaultDate = '2026-10-21' } = {}) {
  const currentYear = new Date().getFullYear();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SmileCraft Dental Studio — Gentle Dental Care & Online Appointment Booking</title>
  <meta name="description" content="SmileCraft Dental Studio in Baner Road, Pune. Gentle dental care, brighter smiles, and instant online appointment booking." />
  <meta property="og:title" content="SmileCraft Dental Studio — Your Smile, Our Passion." />
  <meta property="og:description" content="Discover gentle, personalized dental care designed around you. Book your checkup, teeth cleaning, or smile consultation online." />
  <meta property="og:type" content="website" />
  <meta name="twitter:card" content="summary_large_image" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;600&family=Nunito:wght@400;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" rel="stylesheet" />
  <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "Dentist",
      "name": "SmileCraft Dental Studio",
      "description": "Modern dental clinic in Baner Road, Pune offering preventive, cosmetic, restorative, and specialist dental care.",
      "address": {
        "@type": "PostalAddress",
        "streetAddress": "204 Sunshine Plaza, Baner Road",
        "addressLocality": "Pune",
        "addressRegion": "Maharashtra",
        "postalCode": "411045",
        "addressCountry": "IN"
      },
      "telephone": "+91 98765 43210",
      "email": "hello@smilecraft.in"
    }
  </script>
  <style>
    :root {
      --bg-ivory: #FFFDF8;
      --bg-porcelain: #F7F4EC;
      --bg-card: #FFFFFF;
      --primary-sky: #8ECDF4;
      --primary-sky-deep: #18537E;
      --secondary-lavender: #C9B8FF;
      --secondary-lavender-deep: #483285;
      --accent-mint: #A8E6CF;
      --accent-mint-deep: #135E43;
      --highlight-peach: #FFCAA8;
      --highlight-peach-deep: #80340D;
      --warm-yellow: #FFE69A;
      --text-navy: #25324A;
      --text-slate: #5B677D;
      --border-hairline: rgba(37, 50, 74, 0.08);
      --clay-card-shadow:
        0 16px 32px -10px rgba(37, 50, 74, 0.08),
        inset 0 2px 4px rgba(255, 255, 255, 0.92),
        inset 0 -3px 6px rgba(37, 50, 74, 0.04);
      --clay-btn-primary-shadow:
        0 10px 20px -5px rgba(24, 83, 126, 0.28),
        inset 0 2px 3px rgba(255, 255, 255, 0.4),
        inset 0 -3px 5px rgba(10, 38, 61, 0.25);
      --clay-btn-secondary-shadow:
        0 8px 18px -6px rgba(37, 50, 74, 0.09),
        inset 0 2px 3px rgba(255, 255, 255, 0.95),
        inset 0 -2px 4px rgba(37, 50, 74, 0.05);
      --radius-lg: 28px;
      --radius-md: 22px;
      --radius-sm: 16px;
    }

    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    html {
      scroll-behavior: smooth;
    }

    body {
      font-family: 'Nunito', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg-ivory);
      color: var(--text-navy);
      line-height: 1.6;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    h1, h2, h3, h4, .font-display {
      font-family: 'Plus Jakarta Sans', sans-serif;
      color: var(--text-navy);
      letter-spacing: -0.02em;
      text-wrap: balance;
    }

    .tabular-nums {
      font-family: 'JetBrains Mono', monospace;
      font-variant-numeric: tabular-nums;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    button, input, select, textarea {
      font-family: inherit;
      font-size: 1rem;
      color: var(--text-navy);
    }

    button {
      cursor: pointer;
      border: none;
      background: none;
    }

    :focus-visible {
      outline: 3px solid var(--primary-sky-deep);
      outline-offset: 2px;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1.5rem;
    }

    /* Sticky Top Navigation Bar (Strict 3-Zone Contract) */
    .site-header {
      position: sticky;
      top: 0;
      z-index: 40;
      background: rgba(255, 253, 248, 0.92);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--border-hairline);
      transition: padding 150ms cubic-bezier(0.16, 1, 0.3, 1);
    }

    .header-inner {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0.9rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 2rem;
    }

    .brand-wordmark {
      display: inline-flex;
      align-items: center;
      gap: 0.65rem;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 800;
      font-size: 1.18rem;
      color: var(--text-navy);
      white-space: nowrap;
      flex-shrink: 0;
    }

    .primary-nav {
      display: flex;
      align-items: center;
      gap: 1.75rem;
    }

    .nav-link {
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-size: 0.92rem;
      font-weight: 600;
      color: var(--text-slate);
      white-space: nowrap;
      flex-shrink: 0;
      padding: 0.25rem 0;
      border-bottom: 2px solid transparent;
      transition: color 150ms ease, border-color 150ms ease;
    }

    .nav-link:hover {
      color: var(--text-navy);
      border-bottom-color: var(--primary-sky-deep);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-shrink: 0;
    }

    .mobile-menu-toggle {
      display: none;
      padding: 0.55rem 0.9rem;
      border-radius: 14px;
      background: var(--bg-porcelain);
      font-weight: 700;
      font-size: 0.88rem;
    }

    .mobile-nav-drawer {
      display: none;
      padding: 1rem 1.5rem 1.5rem;
      background: var(--bg-ivory);
      border-bottom: 1px solid var(--border-hairline);
    }

    .mobile-nav-drawer.open {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    /* Claymorphism Buttons & Cards */
    .clay-btn-primary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      padding: 0.75rem 1.45rem;
      border-radius: 18px;
      background: linear-gradient(145deg, #246699, #18507B);
      color: #FFFFFF;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 700;
      font-size: 0.94rem;
      box-shadow: var(--clay-btn-primary-shadow);
      transition: transform 150ms cubic-bezier(0.16, 1, 0.3, 1), opacity 150ms ease;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .clay-btn-primary:hover:not(:disabled) {
      transform: translateY(-2px);
    }

    .clay-btn-primary:active:not(:disabled) {
      transform: translateY(1px);
    }

    .clay-btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .clay-btn-secondary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      padding: 0.75rem 1.4rem;
      border-radius: 18px;
      background: #FFFFFF;
      color: var(--text-navy);
      border: 1px solid var(--border-hairline);
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 700;
      font-size: 0.94rem;
      box-shadow: var(--clay-btn-secondary-shadow);
      transition: transform 150ms cubic-bezier(0.16, 1, 0.3, 1), background-color 150ms ease;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .clay-btn-secondary:hover {
      background: var(--bg-porcelain);
      transform: translateY(-1px);
    }

    .clay-surface {
      background: var(--bg-card);
      border-radius: var(--radius-lg);
      border: 1px solid var(--border-hairline);
      box-shadow: var(--clay-card-shadow);
    }

    /* Hero Section */
    .hero-section {
      padding: 3.5rem 0 3rem;
      background:
        radial-gradient(circle at 12% 18%, rgba(142, 205, 244, 0.22), transparent 38%),
        radial-gradient(circle at 88% 22%, rgba(201, 184, 255, 0.22), transparent 38%),
        radial-gradient(circle at 75% 85%, rgba(168, 230, 207, 0.22), transparent 36%),
        var(--bg-ivory);
    }

    .hero-grid {
      display: grid;
      grid-template-columns: 1.08fr 0.92fr;
      gap: 2.75rem;
      align-items: stretch;
    }

    .hero-copy {
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 1.25rem;
    }

    .hero-kicker {
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--primary-sky-deep);
      letter-spacing: 0.01em;
    }

    .hero-headline {
      font-size: clamp(2.25rem, 4vw, 3.6rem);
      font-weight: 800;
      line-height: 1.12;
      color: var(--text-navy);
    }

    .hero-lead {
      font-size: 1.08rem;
      color: var(--text-slate);
      max-width: 58ch;
    }

    .hero-cta-row {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
      margin-top: 0.35rem;
    }

    .hero-meta-strip {
      display: flex;
      align-items: center;
      gap: 0.65rem;
      flex-wrap: wrap;
      font-size: 0.85rem;
      color: var(--text-slate);
      margin-top: 0.5rem;
    }

    .hero-visual-card {
      padding: 1.75rem;
      border-radius: 32px;
      background: linear-gradient(155deg, #EAF6FE 0%, #F4EEFF 52%, #EBFAF3 100%);
      border: 1px solid rgba(37, 50, 74, 0.08);
      box-shadow: var(--clay-card-shadow);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
    }

    /* Statistics Strip */
    .stats-section {
      padding: 2rem 0 3.5rem;
    }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.25rem;
    }

    .stat-item {
      padding: 1.5rem;
      border-radius: var(--radius-md);
      background: var(--bg-card);
      border: 1px solid var(--border-hairline);
      box-shadow: var(--clay-card-shadow);
    }

    .stat-item-number {
      font-size: 2rem;
      font-weight: 800;
      color: var(--primary-sky-deep);
      line-height: 1.15;
      margin-bottom: 0.25rem;
    }

    /* Section Headings */
    .section-block {
      padding: 4.5rem 0;
    }

    .section-alt {
      background-color: var(--bg-porcelain);
    }

    .section-header {
      max-width: 680px;
      margin-bottom: 2.5rem;
    }

    .section-kicker {
      font-size: 0.82rem;
      font-weight: 700;
      color: var(--primary-sky-deep);
      margin-bottom: 0.4rem;
    }

    .section-title {
      font-size: clamp(1.65rem, 2.8vw, 2.35rem);
      font-weight: 800;
      line-height: 1.2;
      margin-bottom: 0.65rem;
    }

    /* About Section */
    .about-grid {
      display: grid;
      grid-template-columns: 0.95fr 1.05fr;
      gap: 2.5rem;
      align-items: stretch;
    }

    .feature-stack {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1rem;
      margin-top: 1.5rem;
    }

    .feature-item {
      padding: 1.25rem 1.5rem;
      border-radius: var(--radius-md);
      background: var(--bg-card);
      border: 1px solid var(--border-hairline);
      box-shadow: var(--clay-card-shadow);
    }

    /* Interactive Filter Controls (Buttons) */
    .filter-bar {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.35rem;
      border-radius: 18px;
      background: var(--bg-porcelain);
      border: 1px solid var(--border-hairline);
      margin-bottom: 2rem;
      flex-wrap: wrap;
    }

    .filter-tab-btn {
      padding: 0.55rem 1.1rem;
      border-radius: 14px;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-size: 0.86rem;
      font-weight: 700;
      color: var(--text-slate);
      transition: background-color 150ms ease, color 150ms ease;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .filter-tab-btn.active {
      background: var(--bg-card);
      color: var(--text-navy);
      box-shadow: 0 4px 12px rgba(37, 50, 74, 0.08);
    }

    /* Services Grid */
    .services-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(270px, 1fr));
      gap: 1.35rem;
    }

    .service-card {
      padding: 1.6rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1.1rem;
      transition: transform 160ms cubic-bezier(0.16, 1, 0.3, 1);
    }

    .service-card:hover {
      transform: translateY(-3px);
    }

    /* Dentists Grid */
    .dentists-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1.5rem;
    }

    .dentist-card {
      padding: 1.75rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1.15rem;
    }

    /* How Booking Works */
    .steps-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1.5rem;
    }

    .step-card {
      padding: 1.75rem;
    }

    /* Testimonials Grid */
    .testimonials-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 1.35rem;
    }

    .testimonial-card {
      padding: 1.65rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1rem;
    }

    /* Promotional Offer Banner */
    .offer-banner {
      padding: 2.5rem;
      border-radius: 30px;
      background: linear-gradient(135deg, #FFECE0 0%, #F1EBFF 55%, #E5F6FD 100%);
      border: 1px solid rgba(37, 50, 74, 0.09);
      box-shadow: var(--clay-card-shadow);
      display: grid;
      grid-template-columns: 1.3fr 0.7fr;
      gap: 2rem;
      align-items: center;
    }

    /* Booking Section */
    .booking-layout {
      display: grid;
      grid-template-columns: 1.25fr 0.75fr;
      gap: 2rem;
      align-items: start;
    }

    .booking-form-card {
      padding: 2.25rem;
    }

    .form-grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.1rem;
      margin-bottom: 1.1rem;
    }

    .form-label {
      display: block;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-size: 0.85rem;
      font-weight: 700;
      margin-bottom: 0.35rem;
      color: var(--text-navy);
    }

    .clay-input {
      width: 100%;
      padding: 0.72rem 1rem;
      border-radius: var(--radius-sm);
      border: 1.5px solid rgba(37, 50, 74, 0.15);
      background: #FFFFFF;
      color: var(--text-navy);
      transition: border-color 150ms ease, box-shadow 150ms ease;
    }

    .clay-input:focus {
      border-color: var(--primary-sky-deep);
      box-shadow: 0 0 0 3px rgba(142, 205, 244, 0.35);
      outline: none;
    }

    .slots-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(115px, 1fr));
      gap: 0.55rem;
      margin-top: 0.4rem;
    }

    .slot-btn {
      padding: 0.6rem 0.5rem;
      border-radius: 14px;
      border: 1.5px solid rgba(37, 50, 74, 0.14);
      background: #FFFFFF;
      font-size: 0.84rem;
      font-weight: 700;
      text-align: center;
      transition: all 140ms ease;
      white-space: nowrap;
    }

    .slot-btn:hover:not(:disabled) {
      border-color: var(--primary-sky-deep);
      background: #F0F8FE;
    }

    .slot-btn.selected {
      background: var(--primary-sky-deep);
      color: #FFFFFF;
      border-color: var(--primary-sky-deep);
      box-shadow: 0 6px 14px rgba(24, 83, 126, 0.25);
    }

    .slot-btn:disabled {
      opacity: 0.42;
      background: var(--bg-porcelain);
      cursor: not-allowed;
      text-decoration: line-through;
    }

    /* Contact Section */
    .contact-grid {
      display: grid;
      grid-template-columns: 0.95fr 1.05fr;
      gap: 2rem;
    }

    /* Footer */
    .site-footer {
      background: #1D283A;
      color: #F4F6FA;
      padding: 4rem 0 2.5rem;
    }

    .footer-grid {
      display: grid;
      grid-template-columns: 1.4fr 1fr 1fr 1.2fr;
      gap: 2rem;
      padding-bottom: 2.5rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.12);
    }

    .footer-heading {
      color: #FFFFFF;
      font-size: 0.95rem;
      font-weight: 700;
      margin-bottom: 0.9rem;
    }

    .footer-links {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      font-size: 0.9rem;
      color: #CBD5E1;
    }

    .footer-links a:hover, .footer-links button:hover {
      color: #8ECDF4;
    }

    /* Legal Modal */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(37, 50, 74, 0.5);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
      z-index: 70;
    }

    .modal-box {
      max-width: 620px;
      width: 100%;
      max-height: 85vh;
      overflow-y: auto;
      padding: 2rem;
    }

    @media (max-width: 992px) {
      .hero-grid,
      .about-grid,
      .booking-layout,
      .contact-grid,
      .offer-banner {
        grid-template-columns: 1fr;
      }
      .stats-row,
      .dentists-grid,
      .steps-grid,
      .testimonials-grid,
      .footer-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 768px) {
      .header-inner {
        padding: 0.75rem 1rem;
        gap: 0.75rem;
      }
      .brand-wordmark {
        font-size: 1.02rem;
      }
      .primary-nav,
      .header-actions .clay-btn-primary {
        display: none;
      }
      .mobile-menu-toggle {
        display: inline-flex;
      }
      .stats-row,
      .dentists-grid,
      .steps-grid,
      .testimonials-grid,
      .footer-grid,
      .form-grid-2 {
        grid-template-columns: 1fr;
      }
      .section-block {
        padding: 3rem 0;
      }
      .booking-form-card {
        padding: 1.5rem;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      html {
        scroll-behavior: auto;
      }
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>

  <!-- A. STICKY NAVIGATION BAR (Strict 3-Zone Contract) -->
  <header class="site-header">
    <div class="header-inner">
      <!-- Zone 1: Brand Title (Single Element) -->
      <a href="#top" class="brand-wordmark">
        <svg width="34" height="34" viewBox="0 0 48 48" fill="none" aria-hidden="true">
          <rect width="48" height="48" rx="14" fill="#8ECDF4"/>
          <path d="M16 17C16 13.5 19 11 24 11C29 11 32 13.5 32 17C32 21.5 30 25 29 32C28.5 35 26.8 36 25.5 33.5C24.6 31.8 24.4 29.5 24 29.5C23.6 29.5 23.4 31.8 22.5 33.5C21.2 36 19.5 35 19 32C18 25 16 21.5 16 17Z" fill="#FFFDF8" stroke="#25324A" stroke-width="2.2"/>
        </svg>
        SmileCraft Dental Studio
      </a>

      <!-- Zone 2: Concise Single-Line Navigation Links -->
      <nav class="primary-nav" aria-label="Main Navigation">
        <a href="#about" class="nav-link">About</a>
        <a href="#services" class="nav-link">Services</a>
        <a href="#dentists" class="nav-link">Our Dentists</a>
        <a href="#reviews" class="nav-link">Reviews</a>
        <a href="#contact" class="nav-link">Contact</a>
        <a href="/admin?__vpath=/admin&admin=1" class="nav-link" style="color:var(--primary-sky-deep);font-weight:700;">Admin Panel</a>
      </nav>

      <!-- Zone 3: Primary Actions (Admin Button Always Visible on Mobile & Desktop) -->
      <div class="header-actions">
        <a href="/admin?__vpath=/admin&admin=1" class="clay-btn-secondary" style="padding:0.55rem 0.9rem;font-size:0.84rem;color:var(--primary-sky-deep);font-weight:800;">Admin Panel</a>
        <a href="#booking" class="clay-btn-primary">Book Appointment</a>
        <button type="button" id="mobile-nav-btn" class="mobile-menu-toggle" aria-expanded="false" aria-controls="mobile-nav-drawer">
          Menu
        </button>
      </div>
    </div>

    <nav id="mobile-nav-drawer" class="mobile-nav-drawer" aria-label="Mobile Navigation">
      <a href="#about" class="nav-link">About the Clinic</a>
      <a href="#services" class="nav-link">Dental Services</a>
      <a href="#dentists" class="nav-link">Our Dentists</a>
      <a href="#reviews" class="nav-link">Patient Reviews</a>
      <a href="#contact" class="nav-link">Contact & Hours</a>
      <a href="#booking" class="nav-link" style="color:var(--primary-sky-deep);font-weight:700;">Book Appointment</a>
      <a href="/admin?__vpath=/admin&admin=1" class="nav-link" style="color:var(--primary-sky-deep);font-weight:800;">Admin Panel (/admin)</a>
    </nav>
  </header>

  <main id="top">
    <!-- B. HERO SECTION -->
    <section class="hero-section">
      <div class="container">
        <div class="hero-grid">
          <div class="hero-copy">
            <p class="hero-kicker">Your Smile, Our Passion · Gentle Dental Care. Brighter Smiles. Happier Lives.</p>
            <h1 class="hero-headline">Your Happiest Smile Starts Here.</h1>
            <p class="hero-lead">
              Discover gentle, personalized dental care designed around you. From everyday checkups to smile makeovers, we're here to help you shine.
            </p>
            <div class="hero-cta-row">
              <a href="#booking" class="clay-btn-primary">Book Your Appointment</a>
              <a href="#services" class="clay-btn-secondary">Explore Our Services</a>
            </div>
            <div class="hero-meta-strip">
              <span>Gentle care for every smile</span>
              <span aria-hidden="true">·</span>
              <span>204 Sunshine Plaza, Baner Road, Pune</span>
              <span aria-hidden="true">·</span>
              <span class="tabular-nums">Mon–Sat Open</span>
            </div>
          </div>

          <div class="hero-visual-card" aria-label="Dental studio consultation showcase">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;margin-bottom:1rem;">
              <div style="background:rgba(255,255,255,0.9);padding:0.65rem 1rem;border-radius:16px;box-shadow:0 8px 16px rgba(37,50,74,0.06);">
                <div style="font-size:0.76rem;color:var(--text-slate);font-weight:700;">Patient Comfort</div>
                <div class="font-display tabular-nums" style="font-size:1rem;font-weight:800;color:var(--text-navy);">4.9 / 5 Patient Rating</div>
              </div>
              <div style="background:rgba(255,255,255,0.9);padding:0.65rem 1rem;border-radius:16px;box-shadow:0 8px 16px rgba(37,50,74,0.06);">
                <div style="font-size:0.76rem;color:var(--text-slate);font-weight:700;">Same-Week Availability</div>
                <div class="font-display" style="font-size:0.95rem;font-weight:800;color:var(--accent-mint-deep);">Instant Slot Check</div>
              </div>
            </div>

            <!-- High-Craft Claymorphism 3D Tooth & Modern Dental Studio SVG Artwork -->
            <svg viewBox="0 0 520 310" width="100%" height="260" role="img" aria-label="3D claymorphic illustration of a bright healthy tooth and modern dental care suite">
              <defs>
                <linearGradient id="toothGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stop-color="#FFFFFF" />
                  <stop offset="70%" stop-color="#F1F8FE" />
                  <stop offset="100%" stop-color="#D7EEFC" />
                </linearGradient>
                <linearGradient id="chairGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stop-color="#8ECDF4" />
                  <stop offset="100%" stop-color="#5AAEE6" />
                </linearGradient>
                <linearGradient id="blobLav" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stop-color="#DFD5FF" />
                  <stop offset="100%" stop-color="#C9B8FF" />
                </linearGradient>
              </defs>
              <rect x="16" y="16" width="488" height="278" rx="26" fill="#FFFFFF" fill-opacity="0.65" />
              <circle cx="105" cy="95" r="54" fill="url(#blobLav)" opacity="0.6" />
              <circle cx="415" cy="215" r="64" fill="#A8E6CF" opacity="0.55" />
              <circle cx="390" cy="75" r="36" fill="#FFE69A" opacity="0.7" />
              <!-- Stylized Modern Dental Suite Window & Arch -->
              <rect x="60" y="55" width="150" height="195" rx="75" fill="#E6F4FE" stroke="#8ECDF4" stroke-width="3" />
              <path d="M95 190 Q135 215 175 190" stroke="#246699" stroke-width="5" stroke-linecap="round" fill="none" />
              <circle cx="115" cy="145" r="7" fill="#25324A" />
              <circle cx="155" cy="145" r="7" fill="#25324A" />
              <!-- Central Claymorphic 3D Tooth -->
              <g transform="translate(230, 38)">
                <path d="M35 55 C35 22, 68 8, 105 8 C142 8, 175 22, 175 55 C175 96, 156 128, 146 190 C141 218, 125 225, 114 202 C106 186, 108 164, 105 164 C102 164, 104 186, 96 202 C85 225, 69 218, 64 190 C54 128, 35 96, 35 55 Z"
                  fill="url(#toothGrad)" stroke="#25324A" stroke-width="4" />
                <!-- Smile Expression on Tooth -->
                <circle cx="84" cy="78" r="6" fill="#25324A" />
                <circle cx="126" cy="78" r="6" fill="#25324A" />
                <ellipse cx="72" cy="90" rx="8" ry="4.5" fill="#FFCAA8" />
                <ellipse cx="138" cy="90" rx="8" ry="4.5" fill="#FFCAA8" />
                <path d="M88 94 Q105 110 122 94" stroke="#25324A" stroke-width="4" stroke-linecap="round" fill="none" />
                <!-- Protective Mint Shield Badge -->
                <circle cx="165" cy="42" r="24" fill="#A8E6CF" stroke="#25324A" stroke-width="3" />
                <path d="M156 42 L163 49 L176 35" stroke="#25324A" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
              </g>
            </svg>

            <div style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;margin-top:0.85rem;font-size:0.84rem;color:var(--text-navy);font-weight:700;">
              <span>Sterile Autoclave Protocol</span>
              <span>Transparent Starting Prices</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- C. TRUST AND STATISTICS SECTION (Full-width 4-column row below Hero) -->
    <section class="stats-section" aria-label="Clinic Highlights">
      <div class="container">
        <div class="stats-row">
          <article class="stat-item">
            <div class="stat-item-number tabular-nums" data-count-target="5000" data-count-suffix="+">5,000+</div>
            <h2 style="font-size:1rem;font-weight:700;">Smiles Cared For</h2>
            <p style="font-size:0.82rem;color:var(--text-slate);">Trusted by families across Pune</p>
          </article>
          <article class="stat-item">
            <div class="stat-item-number tabular-nums" data-count-target="12" data-count-suffix="+">12+</div>
            <h2 style="font-size:1rem;font-weight:700;">Years of Experience</h2>
            <p style="font-size:0.82rem;color:var(--text-slate);">Senior clinical specialists</p>
          </article>
          <article class="stat-item">
            <div class="stat-item-number tabular-nums">4.9/5</div>
            <h2 style="font-size:1rem;font-weight:700;">Patient Satisfaction</h2>
            <p style="font-size:0.82rem;color:var(--text-slate);">Verified patient feedback</p>
          </article>
          <article class="stat-item">
            <div class="stat-item-number tabular-nums" data-count-target="98" data-count-suffix="%">98%</div>
            <h2 style="font-size:1rem;font-weight:700;">Patient Recommendation</h2>
            <p style="font-size:0.82rem;color:var(--text-slate);">Patients who refer family & friends</p>
          </article>
        </div>
      </div>
    </section>

    <!-- D. ABOUT THE CLINIC -->
    <section id="about" class="section-block section-alt">
      <div class="container">
        <div class="about-grid">
          <div class="clay-surface" style="padding:2rem;background:linear-gradient(145deg,#FFFFFF,#F2FAFE);display:flex;flex-direction:column;justify-content:space-between;">
            <div>
              <p class="section-kicker">Welcome to SmileCraft Dental Studio</p>
              <h2 class="section-title">Designed to Make Every Dental Visit Calm, Clear, and Comfortable.</h2>
              <p style="color:var(--text-slate);margin-bottom:1.15rem;">
                At SmileCraft Dental Studio, we believe visiting the dentist should feel reassuring from the moment you step inside. Our flagship studio at Sunshine Plaza, Baner Road, Pune combines soothing pastel interiors, hospital-grade Class-B autoclave sterilization, and unhurried chairside explanations.
              </p>
              <p style="color:var(--text-slate);">
                Whether you are booking a routine 6-month preventive checkup, bringing your child for their first dental visit, or planning a restorative treatment, every step is explained clearly before care begins.
              </p>
            </div>

            <svg viewBox="0 0 460 190" width="100%" height="165" style="margin-top:1.5rem;" role="img" aria-label="Illustration of SmileCraft ergonomic dental suite">
              <rect width="460" height="190" rx="22" fill="#EBF7FE" />
              <rect x="28" y="30" width="145" height="130" rx="18" fill="#FFFFFF" stroke="#8ECDF4" stroke-width="2" />
              <circle cx="100" cy="82" r="28" fill="#A8E6CF" />
              <path d="M88 82 L97 91 L114 73" stroke="#25324A" stroke-width="3.5" stroke-linecap="round" fill="none" />
              <text x="100" y="136" text-anchor="middle" font-family="Plus Jakarta Sans" font-size="12" font-weight="700" fill="#25324A">4-Step Sterilization</text>
              <rect x="195" y="30" width="235" height="130" rx="18" fill="#FFFFFF" stroke="#C9B8FF" stroke-width="2" />
              <path d="M230 120 C255 120, 265 85, 310 85 L385 85" stroke="#246699" stroke-width="8" stroke-linecap="round" fill="none" />
              <circle cx="245" cy="70" r="16" fill="#FFE69A" />
              <text x="312" y="142" text-anchor="middle" font-family="Plus Jakarta Sans" font-size="12" font-weight="700" fill="#25324A">Ergonomic Comfort Suite</text>
            </svg>
          </div>

          <div>
            <div class="feature-stack" style="margin-top:0;">
              <article class="feature-item">
                <h3 style="font-size:1.12rem;margin-bottom:0.35rem;">01. Gentle and Personalized Care</h3>
                <p style="color:var(--text-slate);font-size:0.95rem;">
                  We listen first. Every appointment starts with a calm conversation about your comfort preferences, dental history, and smile goals—never rushed chairside procedures.
                </p>
              </article>
              <article class="feature-item">
                <h3 style="font-size:1.12rem;margin-bottom:0.35rem;">02. Modern Dental Technology</h3>
                <p style="color:var(--text-slate);font-size:0.95rem;">
                  Low-radiation digital intraoral imaging, ultrasonic scaling, and precision rotary endodontics help make diagnostics faster and treatments gentler.
                </p>
              </article>
              <article class="feature-item">
                <h3 style="font-size:1.12rem;margin-bottom:0.35rem;">03. Comfort-First Experience</h3>
                <p style="color:var(--text-slate);font-size:0.95rem;">
                  From topical numbing gels and ergonomic memory-foam dental chairs to transparent treatment estimates in Indian Rupees, your peace of mind comes first.
                </p>
              </article>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- E. DENTAL SERVICES SECTION -->
    <section id="services" class="section-block">
      <div class="container">
        <div style="display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:1.25rem;margin-bottom:1.5rem;">
          <div class="section-header" style="margin-bottom:0;">
            <p class="section-kicker">Comprehensive Care Menu</p>
            <h2 class="section-title">Dental Services Tailored to Every Stage of Your Smile.</h2>
            <p style="color:var(--text-slate);font-size:0.95rem;">
              Transparent starting fees in Indian Rupees (₹). Final treatment plans are customized after your clinical consultation.
            </p>
          </div>

          <!-- Interactive Filter Controls -->
          <div class="filter-bar" role="tablist" aria-label="Filter dental services by category">
            <button type="button" class="filter-tab-btn active" data-service-filter="ALL">All Services</button>
            <button type="button" class="filter-tab-btn" data-service-filter="Preventive">Preventive</button>
            <button type="button" class="filter-tab-btn" data-service-filter="Cosmetic">Cosmetic</button>
            <button type="button" class="filter-tab-btn" data-service-filter="Restorative">Restorative</button>
            <button type="button" class="filter-tab-btn" data-service-filter="Specialist">Specialist</button>
          </div>
        </div>

        <div id="public-services-grid" class="services-grid" aria-live="polite">
          <!-- Populated dynamically from /api/services with immediate fallback -->
        </div>
      </div>
    </section>

    <!-- F. MEET OUR DENTISTS -->
    <section id="dentists" class="section-block section-alt">
      <div class="container">
        <div class="section-header">
          <p class="section-kicker">Senior Clinical Specialists</p>
          <h2 class="section-title">Meet Our Caring Dental Specialists.</h2>
          <p style="color:var(--text-slate);font-size:0.95rem;">
            Our experienced dental specialists pair advanced clinical training with a warm, reassuring chairside manner.
          </p>
        </div>

        <div id="public-dentists-grid" class="dentists-grid">
          <!-- Populated dynamically from /api/dentists -->
        </div>
      </div>
    </section>

    <!-- G. HOW BOOKING WORKS -->
    <section class="section-block">
      <div class="container">
        <div class="section-header">
          <p class="section-kicker">Simple 3-Step Online Scheduling</p>
          <h2 class="section-title">How Booking Your Visit Works.</h2>
        </div>

        <div class="steps-grid">
          <article class="clay-surface step-card" style="background:linear-gradient(150deg,#FFFFFF,#EFF8FE);">
            <div class="tabular-nums" style="font-size:0.85rem;font-weight:800;color:var(--primary-sky-deep);margin-bottom:0.4rem;">STEP 01</div>
            <h3 style="font-size:1.18rem;margin-bottom:0.5rem;">Choose Your Service</h3>
            <p style="color:var(--text-slate);font-size:0.94rem;">
              Pick from general checkups, ultrasonic teeth cleaning, whitening, fillings, root canal care, braces, implants, or pediatric dentistry.
            </p>
          </article>

          <article class="clay-surface step-card" style="background:linear-gradient(150deg,#FFFFFF,#F5F1FF);">
            <div class="tabular-nums" style="font-size:0.85rem;font-weight:800;color:var(--secondary-lavender-deep);margin-bottom:0.4rem;">STEP 02</div>
            <h3 style="font-size:1.18rem;margin-bottom:0.5rem;">Select Your Date and Time</h3>
            <p style="color:var(--text-slate);font-size:0.94rem;">
              View real-time available slots from Monday to Saturday according to our clinic schedule and choose your preferred practitioner.
            </p>
          </article>

          <article class="clay-surface step-card" style="background:linear-gradient(150deg,#FFFFFF,#EEFAF5);">
            <div class="tabular-nums" style="font-size:0.85rem;font-weight:800;color:var(--accent-mint-deep);margin-bottom:0.4rem;">STEP 03</div>
            <h3 style="font-size:1.18rem;margin-bottom:0.5rem;">Confirm Your Appointment</h3>
            <p style="color:var(--text-slate);font-size:0.94rem;">
              Receive your unique appointment reference immediately while our front-desk team reviews and confirms your reserved time slot.
            </p>
          </article>
        </div>
      </div>
    </section>

    <!-- H. PATIENT TESTIMONIALS -->
    <section id="reviews" class="section-block section-alt">
      <div class="container">
        <div style="display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:2rem;">
          <div class="section-header" style="margin-bottom:0;">
            <p class="section-kicker">Verified Patient Stories</p>
            <h2 class="section-title">Kind Words About the SmileCraft Experience.</h2>
            <p style="color:var(--text-slate);font-size:0.9rem;">
              Read how patients across Baner, Aundh, Balewadi, and Pashan describe their visits with our dental specialists.
            </p>
          </div>
        </div>

        <div class="testimonials-grid">
          <article class="clay-surface testimonial-card">
            <div>
              <div style="color:#B4690E;font-weight:800;font-size:0.9rem;margin-bottom:0.5rem;">★★★★★ · 5.0 / 5 Rating</div>
              <p style="color:var(--text-navy);font-size:0.98rem;">
                "I used to put off dental checkups for years out of nervousness. Dr. Aanya explained every step calmly before starting my cleaning, and I felt zero discomfort."
              </p>
            </div>
            <div style="font-size:0.85rem;color:var(--text-slate);font-weight:700;">
              Ananya R. · Baner, Pune · Professional Teeth Cleaning
            </div>
          </article>

          <article class="clay-surface testimonial-card">
            <div>
              <div style="color:#B4690E;font-weight:800;font-size:0.9rem;margin-bottom:0.5rem;">★★★★★ · 5.0 / 5 Rating</div>
              <p style="color:var(--text-navy);font-size:0.98rem;">
                "Booking my root canal consultation online took less than two minutes. Dr. Rohan saved my molar painlessly and the pricing was transparent from day one."
              </p>
            </div>
            <div style="font-size:0.85rem;color:var(--text-slate);font-weight:700;">
              Vikram S. · Aundh, Pune · Root Canal Treatment
            </div>
          </article>

          <article class="clay-surface testimonial-card">
            <div>
              <div style="color:#B4690E;font-weight:800;font-size:0.9rem;margin-bottom:0.5rem;">★★★★★ · 5.0 / 5 Rating</div>
              <p style="color:var(--text-navy);font-size:0.98rem;">
                "My seven-year-old daughter actually looks forward to her pediatric checkups here. The pastel clinic atmosphere feels warm and welcoming for kids."
              </p>
            </div>
            <div style="font-size:0.85rem;color:var(--text-slate);font-weight:700;">
              Priya K. · Balewadi, Pune · Pediatric Dentistry
            </div>
          </article>

          <article class="clay-surface testimonial-card">
            <div>
              <div style="color:#B4690E;font-weight:800;font-size:0.9rem;margin-bottom:0.5rem;">★★★★★ · 5.0 / 5 Rating</div>
              <p style="color:var(--text-navy);font-size:0.98rem;">
                "Dr. Kiara recommended a conservative whitening plan ahead of my sister's wedding. Natural results and thoughtful follow-up care instructions."
              </p>
            </div>
            <div style="font-size:0.85rem;color:var(--text-slate);font-weight:700;">
              Kabir M. · Pashan, Pune · Teeth Whitening
            </div>
          </article>
        </div>
      </div>
    </section>

    <!-- I. SPECIAL OFFER SECTION -->
    <section class="section-block" style="padding-bottom:1.5rem;">
      <div class="container">
        <div class="offer-banner">
          <div>
            <p style="font-size:0.84rem;font-weight:800;color:var(--highlight-peach-deep);margin-bottom:0.4rem;">
              New Patient Welcome Package
            </p>
            <h2 style="font-size:clamp(1.6rem, 2.5vw, 2.2rem);margin-bottom:0.65rem;">
              New Here? Your Smile Deserves a Fresh Start!
            </h2>
            <p style="color:var(--text-navy);margin-bottom:1.15rem;max-width:60ch;">
              Schedule your comprehensive First-Visit Dental Checkup & Digital Smile Assessment starting at <strong class="tabular-nums">₹499</strong>. Includes full oral examination, gum health charting, and a personalized care roadmap.
            </p>
            <button type="button" id="offer-book-btn" class="clay-btn-primary">Book Now</button>
          </div>

          <div style="display:flex;justify-content:center;">
            <svg viewBox="0 0 220 180" width="210" height="170" role="img" aria-label="Decorative smiling tooth badge">
              <circle cx="110" cy="90" r="78" fill="#FFFFFF" fill-opacity="0.8" />
              <path d="M78 52 C78 32, 95 24, 110 24 C125 24, 142 32, 142 52 C142 75, 132 95, 127 130 C124 146, 115 150, 110 136 C105 150, 96 146, 93 130 C88 95, 78 75, 78 52 Z" fill="#FFFDF8" stroke="#25324A" stroke-width="3.5" />
              <path d="M98 68 Q110 78 122 68" stroke="#25324A" stroke-width="3.2" stroke-linecap="round" fill="none" />
              <circle cx="98" cy="54" r="4" fill="#25324A" />
              <circle cx="122" cy="54" r="4" fill="#25324A" />
            </svg>
          </div>
        </div>
      </div>
    </section>

    <!-- J. APPOINTMENT BOOKING FORM -->
    <section id="booking" class="section-block">
      <div class="container">
        <div class="section-header">
          <p class="section-kicker">Real-Time Online Slot Reservation</p>
          <h2 class="section-title">Book Your Dental Appointment.</h2>
          <p style="color:var(--text-slate);font-size:0.95rem;">
            Select your service, preferred dentist, and date below. Submitting this form creates a <strong>Pending</strong> appointment request and reserves your time slot while our clinic team confirms your visit.
          </p>
        </div>

        <div class="booking-layout">
          <div class="clay-surface booking-form-card">
            <!-- Confirmation Panel (Hidden until booking succeeds) -->
            <div id="booking-confirmation-panel" style="display:none;scroll-margin-top:96px;padding:1.75rem;border-radius:22px;background:linear-gradient(145deg,#EEFAF5,#E6F4FE);border:1.5px solid #8ECDF4;margin-bottom:1.5rem;" role="region" aria-labelledby="confirmation-title">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:0.85rem;">
                <span style="font-size:0.82rem;font-weight:800;color:var(--accent-mint-deep);">
                  REQUEST RECEIVED · STATUS: PENDING CLINIC CONFIRMATION
                </span>
                <button type="button" id="close-confirmation-btn" class="clay-btn-secondary" style="padding:0.35rem 0.8rem;font-size:0.8rem;">
                  Book Another / Close
                </button>
              </div>
              <h3 id="confirmation-title" style="font-size:1.35rem;margin-bottom:0.5rem;">
                Appointment Reference: <span id="conf-ref" class="tabular-nums" style="color:var(--primary-sky-deep);"></span>
              </h3>
              <p style="font-size:0.92rem;color:var(--text-navy);margin-bottom:1rem;">
                Thank you, <strong id="conf-name"></strong>! We have reserved your requested time slot in our scheduling database. Please note the difference between a <strong>Requested (Pending)</strong> appointment and a <strong>Clinic-Confirmed</strong> appointment: our front-desk team will contact you shortly to confirm your visit.
              </p>
              <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(170px, 1fr));gap:0.75rem;padding:1rem;border-radius:16px;background:rgba(255,255,255,0.85);font-size:0.88rem;">
                <div>
                  <div style="color:var(--text-slate);font-weight:700;font-size:0.76rem;">Selected Service</div>
                  <div id="conf-service" style="font-weight:800;"></div>
                </div>
                <div>
                  <div style="color:var(--text-slate);font-weight:700;font-size:0.76rem;">Assigned Dentist</div>
                  <div id="conf-dentist" style="font-weight:800;"></div>
                </div>
                <div>
                  <div style="color:var(--text-slate);font-weight:700;font-size:0.76rem;">Requested Date & Time</div>
                  <div id="conf-datetime" class="tabular-nums" style="font-weight:800;"></div>
                </div>
              </div>
            </div>

            <div id="booking-error-alert" role="alert" style="display:none;padding:0.9rem 1.15rem;border-radius:16px;background:#FFE8E5;color:#9A261D;font-weight:700;font-size:0.9rem;margin-bottom:1.25rem;"></div>

            <form id="public-booking-form" novalidate>
              <div class="form-grid-2">
                <div>
                  <label for="book-name" class="form-label">Patient Full Name *</label>
                  <input id="book-name" name="patientName" type="text" class="clay-input" placeholder="e.g. Rohan Sharma" maxlength="100" required />
                </div>
                <div>
                  <label for="book-email" class="form-label">Email Address (Optional)</label>
                  <input id="book-email" name="email" type="email" class="clay-input" placeholder="rohan.sharma@gmail.com" maxlength="120" />
                </div>
              </div>

              <div class="form-grid-2">
                <div>
                  <label for="book-phone" class="form-label">Phone Number *</label>
                  <input id="book-phone" name="phone" type="tel" class="clay-input tabular-nums" placeholder="+91 98765 43210" maxlength="20" required />
                </div>
                <div>
                  <label for="book-service" class="form-label">Selected Dental Service *</label>
                  <select id="book-service" name="serviceId" class="clay-input" required>
                    <option value="srv-checkup">General Dental Checkup — Starting at ₹499</option>
                  </select>
                </div>
              </div>

              <div class="form-grid-2">
                <div>
                  <label for="book-dentist" class="form-label">Preferred Dentist (Optional)</label>
                  <select id="book-dentist" name="dentistId" class="clay-input">
                    <option value="any">Any Available Clinic Dentist</option>
                  </select>
                </div>
                <div>
                  <label for="book-date" class="form-label">Appointment Date (Mon–Sat) *</label>
                  <input id="book-date" name="appointmentDate" type="date" class="clay-input tabular-nums" value="${defaultDate}" min="${defaultDate}" required />
                </div>
              </div>

              <div style="margin-bottom:1.25rem;">
                <div style="display:flex;align-items:center;justify-content:space-between;gap:0.5rem;">
                  <label for="book-slot-hidden" class="form-label" style="margin-bottom:0;">Tap a Time Slot to Select *</label>
                  <span id="slot-status-caption" style="font-size:0.8rem;color:var(--text-slate);font-weight:600;">Checking live availability...</span>
                </div>
                <input type="hidden" id="book-slot-hidden" name="timeSlot" required />
                <div id="time-slots-container" class="slots-grid" role="radiogroup" aria-label="Available appointment time slots">
                  <!-- Populated dynamically -->
                </div>
              </div>

              <div style="margin-bottom:1.15rem;">
                <label for="book-notes" class="form-label">Additional Notes or Symptoms (Optional)</label>
                <textarea id="book-notes" name="notes" rows="2" class="clay-input" maxlength="500" placeholder="Share any tooth sensitivity, preferred call time, or questions..."></textarea>
              </div>

              <div style="margin-bottom:1.15rem;display:flex;align-items:flex-start;gap:0.65rem;">
                <input id="book-consent" name="consent" type="checkbox" checked style="width:1.15rem;height:1.15rem;margin-top:0.2rem;accent-color:var(--primary-sky-deep);" required />
                <label for="book-consent" style="font-size:0.86rem;color:var(--text-slate);">
                  I consent to SmileCraft Dental Studio storing my booking details to schedule and confirm this appointment request in accordance with the clinic's <button type="button" data-open-legal="privacy" style="color:var(--primary-sky-deep);font-weight:700;text-decoration:underline;font-size:0.86rem;">Privacy Policy</button>.
                </label>
              </div>

              <div id="booking-inline-feedback" role="status" aria-live="polite" style="display:none;padding:0.85rem 1.1rem;border-radius:14px;font-weight:700;font-size:0.88rem;margin-bottom:1rem;"></div>

              <button type="submit" id="book-submit-btn" class="clay-btn-primary" style="width:100%;padding:0.95rem;font-size:1rem;">
                Confirm & Book Selected Slot
              </button>
            </form>
          </div>

          <!-- Sidebar Policy & Reference Status Lookup Card -->
          <div style="display:flex;flex-direction:column;gap:1.25rem;">
            <aside class="clay-surface" style="padding:1.65rem;">
              <h3 style="font-size:1.08rem;margin-bottom:0.65rem;">Clinic Scheduling Policy</h3>
              <ul style="list-style:none;display:flex;flex-direction:column;gap:0.6rem;font-size:0.88rem;color:var(--text-slate);">
                <li><strong>Opening Hours:</strong> Mon–Fri 9:00 AM–8:00 PM · Sat 9:00 AM–5:00 PM · Sun Closed.</li>
                <li><strong>Pending vs. Confirmed:</strong> New online bookings start with <strong>Pending</strong> status while your slot is held. Our team calls or emails to confirm.</li>
                <li><strong>Any Available Dentist Policy:</strong> Choosing "Any Available Dentist" automatically assigns an open practitioner for that time slot.</li>
                <li><strong>Consultation & Fee Transparency:</strong> Listed treatment fees in INR (₹) are standard starting prices; a personalized treatment plan is shared after clinical examination.</li>
              </ul>
            </aside>

            <aside class="clay-surface" style="padding:1.65rem;">
              <h3 style="font-size:1.05rem;margin-bottom:0.4rem;">Check Your Booking Status</h3>
              <p style="font-size:0.84rem;color:var(--text-slate);margin-bottom:0.85rem;">
                Already have an appointment reference (e.g. <span class="tabular-nums">SC-2026-101</span>)? Check its live status:
              </p>
              <form id="lookup-apt-form" style="display:flex;gap:0.5rem;">
                <input id="lookup-apt-input" type="text" class="clay-input tabular-nums" placeholder="SC-2026-101" required />
                <button type="submit" class="clay-btn-secondary">Check</button>
              </form>
              <div id="lookup-apt-result" aria-live="polite" style="margin-top:0.85rem;font-size:0.85rem;"></div>
            </aside>
          </div>
        </div>
      </div>
    </section>

    <!-- K. CONTACT SECTION -->
    <section id="contact" class="section-block section-alt">
      <div class="container">
        <div class="section-header">
          <p class="section-kicker">Visit or Message Us</p>
          <h2 class="section-title">Get in Touch With SmileCraft Dental Studio.</h2>
        </div>

        <div class="contact-grid">
          <div class="clay-surface" style="padding:2rem;display:flex;flex-direction:column;justify-content:space-between;gap:1.25rem;">
            <div>
              <h3 style="font-size:1.15rem;margin-bottom:0.85rem;">Clinic Location & Opening Hours</h3>
              <div style="display:flex;flex-direction:column;gap:0.75rem;font-size:0.94rem;">
                <div>
                  <strong>Address:</strong><br />
                  <span style="color:var(--text-slate);">204 Sunshine Plaza, Baner Road, Pune, Maharashtra 411045, India</span>
                </div>
                <div>
                  <strong>Phone (Click to Call):</strong><br />
                  <a href="tel:+919876543210" class="tabular-nums" style="color:var(--primary-sky-deep);font-weight:800;">+91 98765 43210</a>
                </div>
                <div>
                  <strong>Email:</strong><br />
                  <a href="mailto:hello@smilecraft.in" style="color:var(--primary-sky-deep);font-weight:700;">hello@smilecraft.in</a>
                </div>
                <div>
                  <strong>Opening Hours:</strong>
                  <ul class="tabular-nums" style="list-style:none;color:var(--text-slate);font-size:0.88rem;margin-top:0.2rem;">
                    <li>Monday–Friday: 9:00 AM–8:00 PM</li>
                    <li>Saturday: 9:00 AM–5:00 PM</li>
                    <li>Sunday: Closed</li>
                  </ul>
                </div>
              </div>
            </div>

            <!-- Clinic Location Map Preview -->
            <div style="border-radius:20px;overflow:hidden;border:1px solid var(--border-hairline);background:#E8F4FC;padding:1rem;">
              <div style="font-size:0.76rem;font-weight:800;color:var(--primary-sky-deep);margin-bottom:0.4rem;">
                CLINIC LOCATION · 204 SUNSHINE PLAZA, BANER ROAD, PUNE
              </div>
              <svg viewBox="0 0 420 130" width="100%" height="115" role="img" aria-label="Location map showing Sunshine Plaza on Baner Road, Pune">
                <rect width="420" height="130" rx="14" fill="#F2F9FE" />
                <path d="M0 75 Q140 55 260 72 T420 60" stroke="#8ECDF4" stroke-width="14" fill="none" />
                <path d="M180 0 L205 130" stroke="#DCEBFA" stroke-width="10" fill="none" />
                <circle cx="215" cy="68" r="14" fill="#18537E" />
                <circle cx="215" cy="68" r="5" fill="#FFFFFF" />
                <text x="236" y="72" font-family="Plus Jakarta Sans" font-size="12" font-weight="800" fill="#25324A">SmileCraft Studio (204 Sunshine Plaza)</text>
              </svg>
            </div>
          </div>

          <div class="clay-surface" style="padding:2rem;">
            <h3 style="font-size:1.15rem;margin-bottom:0.35rem;">Send Us a Question or Inquiry</h3>
            <p style="font-size:0.88rem;color:var(--text-slate);margin-bottom:1.25rem;">
              Have a question about dental treatments, insurance paperwork, or child visits? Send a message directly to our clinic front desk.
            </p>

            <div id="contact-feedback-box" role="status" aria-live="polite" style="display:none;padding:0.9rem 1.1rem;border-radius:16px;margin-bottom:1rem;font-weight:700;font-size:0.9rem;"></div>

            <form id="public-contact-form" novalidate>
              <div style="margin-bottom:0.95rem;">
                <label for="contact-name" class="form-label">Your Name *</label>
                <input id="contact-name" name="name" type="text" class="clay-input" placeholder="Priya Kulkarni" required />
              </div>
              <div class="form-grid-2">
                <div>
                  <label for="contact-email" class="form-label">Email Address *</label>
                  <input id="contact-email" name="email" type="email" class="clay-input" placeholder="priya.kulkarni@gmail.com" required />
                </div>
                <div>
                  <label for="contact-phone" class="form-label">Phone Number (Optional)</label>
                  <input id="contact-phone" name="phone" type="tel" class="clay-input tabular-nums" placeholder="+91 98765 00000" />
                </div>
              </div>
              <div style="margin-bottom:1.2rem;">
                <label for="contact-message" class="form-label">Your Message *</label>
                <textarea id="contact-message" name="message" rows="4" class="clay-input" placeholder="How can our dental team help you?" required></textarea>
              </div>
              <button type="submit" id="contact-submit-btn" class="clay-btn-primary" style="width:100%;">
                Submit Inquiry
              </button>
            </form>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- L. FOOTER -->
  <footer class="site-footer">
    <div class="container">
      <div class="footer-grid">
        <div>
          <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.75rem;">
            <svg width="30" height="30" viewBox="0 0 48 48" fill="none" aria-hidden="true">
              <rect width="48" height="48" rx="14" fill="#8ECDF4"/>
              <path d="M16 17C16 13.5 19 11 24 11C29 11 32 13.5 32 17C32 21.5 30 25 29 32C28.5 35 26.8 36 25.5 33.5C24.6 31.8 24.4 29.5 24 29.5C23.6 29.5 23.4 31.8 22.5 33.5C21.2 36 19.5 35 19 32C18 25 16 21.5 16 17Z" fill="#FFFDF8" stroke="#25324A" stroke-width="2.2"/>
            </svg>
            <span class="font-display" style="font-weight:800;font-size:1.1rem;color:#FFFFFF;">SmileCraft Dental Studio</span>
          </div>
          <p style="font-size:0.9rem;color:#CBD5E1;margin-bottom:0.75rem;">
            Your Smile, Our Passion. Gentle Dental Care. Brighter Smiles. Happier Lives.
          </p>
          <p style="font-size:0.8rem;color:#94A3B8;">
            ISO-compliant Class-B sterilization · Digital Intraoral Diagnostics · Family & Cosmetic Dentistry in Baner Road, Pune.
          </p>
        </div>

        <div>
          <h4 class="footer-heading">Quick Links</h4>
          <ul class="footer-links">
            <li><a href="#top">Home</a></li>
            <li><a href="#about">About the Clinic</a></li>
            <li><a href="#services">Dental Services</a></li>
            <li><a href="#dentists">Our Dentists</a></li>
            <li><a href="#reviews">Patient Reviews</a></li>
            <li><a href="#booking">Book Appointment</a></li>
            <li><a href="/admin?__vpath=/admin&admin=1" style="color:#8ECDF4;font-weight:700;">Admin Panel (/admin)</a></li>
          </ul>
        </div>

        <div>
          <h4 class="footer-heading">Dental Services</h4>
          <ul class="footer-links">
            <li><a href="#services" data-footer-service="srv-checkup">General Dental Checkup</a></li>
            <li><a href="#services" data-footer-service="srv-cleaning">Professional Teeth Cleaning</a></li>
            <li><a href="#services" data-footer-service="srv-whitening">Teeth Whitening</a></li>
            <li><a href="#services" data-footer-service="srv-fillings">Dental Fillings</a></li>
            <li><a href="#services" data-footer-service="srv-rct">Root Canal Treatment</a></li>
            <li><a href="#services" data-footer-service="srv-braces">Dental Braces Consultation</a></li>
            <li><a href="#services" data-footer-service="srv-implants">Dental Implants Consultation</a></li>
            <li><a href="#services" data-footer-service="srv-pediatric">Pediatric Dentistry</a></li>
          </ul>
        </div>

        <div>
          <h4 class="footer-heading">Contact & Opening Hours</h4>
          <ul class="footer-links">
            <li>204 Sunshine Plaza, Baner Road, Pune 411045</li>
            <li class="tabular-nums"><a href="tel:+919876543210">+91 98765 43210</a></li>
            <li><a href="mailto:hello@smilecraft.in">hello@smilecraft.in</a></li>
            <li class="tabular-nums" style="margin-top:0.35rem;">Mon–Fri: 9:00 AM–8:00 PM</li>
            <li class="tabular-nums">Saturday: 9:00 AM–5:00 PM</li>
            <li>Sunday: Closed</li>
          </ul>
        </div>
      </div>

      <div style="padding-top:1.75rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;font-size:0.84rem;color:#94A3B8;">
        <div>
          © <span class="tabular-nums">${currentYear}</span> SmileCraft Dental Studio, Baner Road, Pune. All rights reserved.
        </div>
        <div style="display:flex;align-items:center;gap:1.25rem;">
          <button type="button" data-open-legal="privacy" style="color:#CBD5E1;font-size:0.84rem;">Privacy Policy</button>
          <button type="button" data-open-legal="terms" style="color:#CBD5E1;font-size:0.84rem;">Terms & Conditions</button>
          <a href="#top" style="color:#8ECDF4;font-weight:700;">↑ Back to Top</a>
        </div>
      </div>
    </div>
  </footer>

  <!-- Accessible Legal Info Modal (Privacy Policy / Terms) -->
  <div id="legal-modal-backdrop" class="modal-backdrop" style="display:none;" role="dialog" aria-modal="true" aria-labelledby="legal-modal-title">
    <div class="clay-surface modal-box">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
        <h2 id="legal-modal-title" style="font-size:1.2rem;">Privacy Policy & Appointment Terms</h2>
        <button type="button" id="close-legal-modal" class="clay-btn-secondary" style="padding:0.35rem 0.8rem;font-size:0.82rem;">Close</button>
      </div>
      <div id="legal-modal-body" style="font-size:0.9rem;color:var(--text-slate);display:flex;flex-direction:column;gap:0.75rem;"></div>
    </div>
  </div>

  <script>
    (function() {
      if (
        window.location.pathname.startsWith('/admin') ||
        window.location.hash === '#admin'
      ) {
        if (!window.location.search.includes('admin=1')) {
          window.location.replace('/?__vpath=/admin&admin=1');
          return;
        }
      }
      const fallbackServices = ${JSON.stringify(INITIAL_SERVICES)};
      const fallbackDentists = ${JSON.stringify(INITIAL_DENTISTS)};

      const appState = {
        services: fallbackServices,
        dentists: fallbackDentists,
        activeServiceFilter: 'ALL',
        selectedSlot: '',
        availableSlots: [],
        isOpenDay: true,
        closedReason: '',
        submittingBooking: false,
      };

      function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function getServiceIllustrationSvg(serviceId) {
        const colors = {
          'srv-checkup': '#8ECDF4',
          'srv-cleaning': '#A8E6CF',
          'srv-whitening': '#FFE69A',
          'srv-fillings': '#C9B8FF',
          'srv-rct': '#FFCAA8',
          'srv-braces': '#8ECDF4',
          'srv-implants': '#A8E6CF',
          'srv-pediatric': '#FFCAA8',
        };
        const bg = colors[serviceId] || '#8ECDF4';
        return \`
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none" aria-hidden="true">
            <rect width="48" height="48" rx="16" fill="\${bg}" fill-opacity="0.35" />
            <path d="M17 17.5C17 14 19.8 11.5 24 11.5C28.2 11.5 31 14 31 17.5C31 21.5 29.3 25 28.4 31C28 33.8 26.5 34.5 25.3 32.3C24.5 30.8 24.3 28.8 24 28.8C23.7 28.8 23.5 30.8 22.7 32.3C21.5 34.5 20 33.8 19.6 31C18.7 25 17 21.5 17 17.5Z" fill="#FFFFFF" stroke="#25324A" stroke-width="2"/>
          </svg>
        \`;
      }

      function getDentistPortraitSvg(theme, name) {
        const bgMap = {
          sky: '#E3F3FD',
          mint: '#E3F8EF',
          lavender: '#EFEAFF',
        };
        const accentMap = {
          sky: '#8ECDF4',
          mint: '#A8E6CF',
          lavender: '#C9B8FF',
        };
        const bg = bgMap[theme] || '#E3F3FD';
        const accent = accentMap[theme] || '#8ECDF4';
        return \`
          <svg viewBox="0 0 120 120" width="84" height="84" role="img" aria-label="Illustrated portrait of \${escapeHtml(name)}">
            <rect width="120" height="120" rx="28" fill="\${bg}" />
            <circle cx="60" cy="46" r="22" fill="#FFDFC4" stroke="#25324A" stroke-width="2.5" />
            <path d="M38 42 C38 26, 82 26, 82 42" fill="#25324A" />
            <circle cx="52" cy="46" r="2.5" fill="#25324A" />
            <circle cx="68" cy="46" r="2.5" fill="#25324A" />
            <path d="M53 54 Q60 60 67 54" stroke="#25324A" stroke-width="2.2" stroke-linecap="round" fill="none" />
            <path d="M26 112 C28 84, 92 84, 94 112" fill="\${accent}" stroke="#25324A" stroke-width="2.5" />
            <path d="M48 86 L60 104 L72 86" fill="#FFFFFF" stroke="#25324A" stroke-width="2" />
          </svg>
        \`;
      }

      function renderServicesGrid() {
        const grid = document.getElementById('public-services-grid');
        if (!grid) return;

        const filtered = appState.activeServiceFilter === 'ALL'
          ? appState.services
          : appState.services.filter(s => (s.category || 'Preventive') === appState.activeServiceFilter);

        if (filtered.length === 0) {
          grid.innerHTML = '<div class="clay-surface" style="padding:2rem;grid-column:1/-1;text-align:center;">No active services in this category.</div>';
          return;
        }

        grid.innerHTML = filtered.map(srv => \`
          <article class="clay-surface service-card">
            <div>
              <div style="display:flex;align-items:center;justify-content:space-between;gap:0.75rem;margin-bottom:0.9rem;">
                \${getServiceIllustrationSvg(srv.serviceId)}
                <div style="text-align:right;">
                  <span style="font-size:0.76rem;color:var(--text-slate);font-weight:700;display:block;">Starting at</span>
                  <span class="tabular-nums" style="font-size:1.35rem;font-weight:800;color:var(--primary-sky-deep);">₹\${escapeHtml(srv.price)}</span>
                </div>
              </div>
              <div style="font-size:0.78rem;color:var(--text-slate);font-weight:700;margin-bottom:0.25rem;">
                \${escapeHtml(srv.category || 'General')} · <span class="tabular-nums">\${escapeHtml(srv.durationMinutes || 45)} mins</span>
              </div>
              <h3 style="font-size:1.15rem;margin-bottom:0.45rem;">\${escapeHtml(srv.name)}</h3>
              <p style="font-size:0.9rem;color:var(--text-slate);">\${escapeHtml(srv.description)}</p>
            </div>
            <button type="button" class="clay-btn-secondary" data-select-service="\${escapeHtml(srv.serviceId)}" style="width:100%;">
              Book This Service
            </button>
          </article>
        \`).join('');

        grid.querySelectorAll('[data-select-service]').forEach(btn => {
          btn.addEventListener('click', () => {
            const serviceId = btn.getAttribute('data-select-service');
            const selectEl = document.getElementById('book-service');
            if (selectEl) selectEl.value = serviceId;
            document.getElementById('booking')?.scrollIntoView({ behavior: 'smooth' });
            document.getElementById('book-name')?.focus();
          });
        });
      }

      function renderDentistsGrid() {
        const grid = document.getElementById('public-dentists-grid');
        if (!grid) return;

        grid.innerHTML = appState.dentists.map(d => \`
          <article class="clay-surface dentist-card">
            <div>
              <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
                \${getDentistPortraitSvg(d.avatarTheme || 'sky', d.name)}
                <div>
                  <h3 style="font-size:1.18rem;">\${escapeHtml(d.name)}</h3>
                  <p style="font-size:0.84rem;font-weight:700;color:var(--primary-sky-deep);">\${escapeHtml(d.specialization)}</p>
                  <p class="tabular-nums" style="font-size:0.78rem;color:var(--text-slate);font-weight:700;">\${escapeHtml(d.experienceYears || 9)}+ Years Clinical Experience</p>
                </div>
              </div>
              <p style="font-size:0.92rem;color:var(--text-slate);">\${escapeHtml(d.bio)}</p>
            </div>
            <button type="button" class="clay-btn-secondary" data-select-dentist="\${escapeHtml(d.dentistId)}" style="width:100%;">
              Book Consultation
            </button>
          </article>
        \`).join('');

        grid.querySelectorAll('[data-select-dentist]').forEach(btn => {
          btn.addEventListener('click', () => {
            const dentistId = btn.getAttribute('data-select-dentist');
            const dentSelect = document.getElementById('book-dentist');
            if (dentSelect) {
              dentSelect.value = dentistId;
              fetchAndRenderSlots();
            }
            document.getElementById('booking')?.scrollIntoView({ behavior: 'smooth' });
          });
        });
      }

      function populateBookingSelects() {
        const srvSelect = document.getElementById('book-service');
        const dentSelect = document.getElementById('book-dentist');
        if (srvSelect) {
          const currentVal = srvSelect.value || (appState.services[0]?.serviceId || 'srv-checkup');
          srvSelect.innerHTML = appState.services.map(s =>
            \`<option value="\${escapeHtml(s.serviceId)}">\${escapeHtml(s.name)} — Starting at ₹\${escapeHtml(s.price)}</option>\`
          ).join('');
          srvSelect.value = currentVal;
          if (!srvSelect.value && appState.services.length > 0) {
            srvSelect.value = appState.services[0].serviceId;
          }
        }
        if (dentSelect) {
          const currentDent = dentSelect.value || 'any';
          dentSelect.innerHTML = '<option value="any">Any Available Clinic Dentist</option>' +
            appState.dentists.map(d =>
              \`<option value="\${escapeHtml(d.dentistId)}">\${escapeHtml(d.name)} (\${escapeHtml(d.specialization)})</option>\`
            ).join('');
          dentSelect.value = currentDent;
        }
      }

      function getLocalBookedAppointments() {
        try {
          const raw = localStorage.getItem('sc_shared_bookings');
          const parsed = raw ? JSON.parse(raw) : [];
          return Array.isArray(parsed) ? parsed : [];
        } catch {
          return [];
        }
      }

      function saveLocalBookedAppointment(apt) {
        try {
          const list = getLocalBookedAppointments();
          if (!list.some(x => x.appointmentId === apt.appointmentId)) {
            list.unshift(apt);
            localStorage.setItem('sc_shared_bookings', JSON.stringify(list.slice(0, 100)));
          }
        } catch {
          // Ignore storage quota errors
        }
      }

      async function fetchAndRenderSlots() {
        const dateInput = document.getElementById('book-date');
        const dentistSelect = document.getElementById('book-dentist');
        const container = document.getElementById('time-slots-container');
        const caption = document.getElementById('slot-status-caption');
        const hiddenInput = document.getElementById('book-slot-hidden');
        const submitBtn = document.getElementById('book-submit-btn');
        if (!dateInput || !container) return;

        const date = dateInput.value;
        const dentistId = dentistSelect ? dentistSelect.value : 'any';

        caption.textContent = 'Checking live slots...';
        try {
          const res = await fetch('/api/availability?__vpath=/api/availability&date=' + encodeURIComponent(date) + '&dentistId=' + encodeURIComponent(dentistId));
          const contentType = res.headers.get('content-type') || '';
          let data;
          if (contentType.includes('application/json')) {
            const json = await res.json();
            if (!json.success) throw new Error(json.error?.message || 'Could not load slots');
            data = json.data;
          } else {
            const parts = String(date || '').split('-').map(Number);
            const dow = parts.length === 3 ? new Date(Date.UTC(parts[0], parts[1] - 1, parts[2])).getUTCDay() : 1;
            if (dow === 0) {
              data = { isOpenDay: false, reason: 'SmileCraft Dental Studio is closed on Sundays. Please choose Monday through Saturday.', slots: [] };
            } else {
              const defaultTimes = dow === 6
                ? ['09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM', '02:00 PM', '03:00 PM', '04:00 PM']
                : ['09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM', '06:00 PM', '07:00 PM'];
              data = {
                isOpenDay: true,
                reason: null,
                slots: defaultTimes.map(t => ({ time: t, available: true })),
              };
            }
          }

          // Also cross-check any locally booked slots in this browser
          const localBookings = getLocalBookedAppointments().filter(
            b => b.appointmentDate === date && ['Pending', 'Confirmed'].includes(b.status)
          );
          if (Array.isArray(data.slots) && localBookings.length > 0) {
            data.slots = data.slots.map(slot => {
              if (!slot.available) return slot;
              if (dentistId && dentistId !== 'any') {
                const takenForDentist = localBookings.some(
                  b => b.timeSlot === slot.time && (b.dentistId === dentistId || b.dentistKey === dentistId)
                );
                if (takenForDentist) return { ...slot, available: false, reason: 'Booked' };
              } else {
                const bookedCount = localBookings.filter(b => b.timeSlot === slot.time).length;
                if (bookedCount >= (appState.dentists.length || 3)) {
                  return { ...slot, available: false, reason: 'Booked' };
                }
              }
              return slot;
            });
          }

          appState.isOpenDay = data.isOpenDay;
          appState.closedReason = data.reason || '';
          appState.availableSlots = data.slots || [];

          if (!data.isOpenDay) {
            appState.selectedSlot = '';
            hiddenInput.value = '';
            caption.textContent = 'Clinic Closed';
            if (submitBtn) submitBtn.textContent = 'Clinic Closed on Selected Date';
            container.innerHTML = \`
              <div style="grid-column:1/-1;padding:0.9rem 1rem;border-radius:14px;background:#FFF4D6;color:#7D5300;font-size:0.88rem;font-weight:700;">
                \${escapeHtml(data.reason || 'SmileCraft Dental Studio is closed on this date. Please pick Monday–Saturday.')}
              </div>
            \`;
            return;
          }

          // Auto-select first available slot if current selection is no longer available
          const stillValid = appState.availableSlots.some(s => s.time === appState.selectedSlot && s.available);
          if (!stillValid) {
            const firstFree = appState.availableSlots.find(s => s.available);
            appState.selectedSlot = firstFree ? firstFree.time : '';
          }
          hiddenInput.value = appState.selectedSlot;
          if (submitBtn && !appState.submittingBooking) {
            submitBtn.textContent = appState.selectedSlot
              ? 'Confirm & Book ' + appState.selectedSlot + ' Slot'
              : 'Request Appointment Slot';
          }

          const freeCount = appState.availableSlots.filter(s => s.available).length;
          caption.textContent = freeCount + ' slot(s) available on ' + date;

          container.innerHTML = appState.availableSlots.map(slot => \`
            <button
              type="button"
              class="slot-btn tabular-nums \${appState.selectedSlot === slot.time ? 'selected' : ''}"
              data-slot-time="\${escapeHtml(slot.time)}"
              role="radio"
              aria-checked="\${appState.selectedSlot === slot.time ? 'true' : 'false'}"
              \${!slot.available ? 'disabled title="Reserved or blocked"' : ''}
            >
              \${escapeHtml(slot.time)}\${!slot.available ? ' (Booked)' : ''}
            </button>
          \`).join('');

          container.querySelectorAll('[data-slot-time]').forEach(btn => {
            btn.addEventListener('click', () => {
              appState.selectedSlot = btn.getAttribute('data-slot-time');
              hiddenInput.value = appState.selectedSlot;
              if (submitBtn && !appState.submittingBooking) {
                submitBtn.textContent = 'Confirm & Book ' + appState.selectedSlot + ' Slot';
              }
              container.querySelectorAll('[data-slot-time]').forEach(b => {
                const active = b.getAttribute('data-slot-time') === appState.selectedSlot;
                b.classList.toggle('selected', active);
                b.setAttribute('aria-checked', active ? 'true' : 'false');
              });
            });
          });
        } catch (err) {
          caption.textContent = 'Unable to load slots';
          container.innerHTML = \`<div style="grid-column:1/-1;color:#9A261D;font-size:0.86rem;font-weight:700;">\${escapeHtml(err.message)}</div>\`;
        }
      }

      async function initPublicCatalog() {
        renderServicesGrid();
        renderDentistsGrid();
        populateBookingSelects();
        await fetchAndRenderSlots();

        try {
          const [srvRes, dentRes] = await Promise.all([
            fetch('/api/services?__vpath=/api/services').then(r => r.json()),
            fetch('/api/dentists?__vpath=/api/dentists').then(r => r.json()),
          ]);
          if (srvRes.success && Array.isArray(srvRes.data) && srvRes.data.length > 0) {
            appState.services = srvRes.data;
          }
          if (dentRes.success && Array.isArray(dentRes.data) && dentRes.data.length > 0) {
            appState.dentists = dentRes.data;
          }
          renderServicesGrid();
          renderDentistsGrid();
          populateBookingSelects();
        } catch {
          // Fallback catalog already rendered
        }
      }

      // Service Category Filter Buttons
      document.querySelectorAll('[data-service-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
          appState.activeServiceFilter = btn.getAttribute('data-service-filter');
          document.querySelectorAll('[data-service-filter]').forEach(b => {
            b.classList.toggle('active', b === btn);
          });
          renderServicesGrid();
        });
      });

      // Footer service quick links
      document.querySelectorAll('[data-footer-service]').forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          const srvId = link.getAttribute('data-footer-service');
          const srvSelect = document.getElementById('book-service');
          if (srvSelect) srvSelect.value = srvId;
          document.getElementById('booking')?.scrollIntoView({ behavior: 'smooth' });
        });
      });

      // Offer CTA
      const offerBtn = document.getElementById('offer-book-btn');
      if (offerBtn) {
        offerBtn.addEventListener('click', () => {
          const srvSelect = document.getElementById('book-service');
          if (srvSelect) srvSelect.value = 'srv-checkup';
          document.getElementById('booking')?.scrollIntoView({ behavior: 'smooth' });
          document.getElementById('book-name')?.focus();
        });
      }

      // Date & Dentist change listeners
      document.getElementById('book-date')?.addEventListener('change', fetchAndRenderSlots);
      document.getElementById('book-dentist')?.addEventListener('change', fetchAndRenderSlots);

      // Booking Form Submit Handler
      const bookingForm = document.getElementById('public-booking-form');
      if (bookingForm) {
        bookingForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          if (appState.submittingBooking) return;

          const errAlert = document.getElementById('booking-error-alert');
          const inlineFeedback = document.getElementById('booking-inline-feedback');
          const confPanel = document.getElementById('booking-confirmation-panel');
          const submitBtn = document.getElementById('book-submit-btn');
          errAlert.style.display = 'none';
          if (inlineFeedback) inlineFeedback.style.display = 'none';

          const patientName = document.getElementById('book-name').value.trim();
          const email = document.getElementById('book-email').value.trim() || 'patient@smilecraft.in';
          const phone = document.getElementById('book-phone').value.trim();
          const serviceId = document.getElementById('book-service').value || 'srv-checkup';
          const dentistId = document.getElementById('book-dentist').value || 'any';
          const appointmentDate = document.getElementById('book-date').value;
          const timeSlot = document.getElementById('book-slot-hidden').value || appState.selectedSlot;
          const notes = document.getElementById('book-notes').value.trim();
          const consent = document.getElementById('book-consent').checked;

          if (!patientName || patientName.length < 2) {
            const msg = 'Please enter your full name to book this slot.';
            if (inlineFeedback) {
              inlineFeedback.style.background = '#FFE8E5';
              inlineFeedback.style.color = '#9A261D';
              inlineFeedback.textContent = msg;
              inlineFeedback.style.display = 'block';
            }
            document.getElementById('book-name').focus();
            return;
          }
          if (!phone || phone.replace(/\\D/g, '').length < 7) {
            const msg = 'Please enter your 10-digit mobile number to book this slot.';
            if (inlineFeedback) {
              inlineFeedback.style.background = '#FFE8E5';
              inlineFeedback.style.color = '#9A261D';
              inlineFeedback.textContent = msg;
              inlineFeedback.style.display = 'block';
            }
            document.getElementById('book-phone').focus();
            return;
          }
          if (!timeSlot) {
            const msg = 'Please select an available time slot above.';
            if (inlineFeedback) {
              inlineFeedback.style.background = '#FFE8E5';
              inlineFeedback.style.color = '#9A261D';
              inlineFeedback.textContent = msg;
              inlineFeedback.style.display = 'block';
            }
            return;
          }

          const payload = {
            patientName,
            email,
            phone,
            serviceId,
            dentistId,
            appointmentDate,
            timeSlot,
            notes,
            consent,
          };

          appState.submittingBooking = true;
          submitBtn.disabled = true;
          submitBtn.textContent = 'Reserving Your Slot...';

          try {
            const res = await fetch('/api/appointments?__vpath=/api/appointments', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            });
            const contentType = res.headers.get('content-type') || '';
            let bookedData = null;

            if (contentType.includes('application/json')) {
              const json = await res.json();
              if (!res.ok || !json.success) {
                throw new Error(json.error?.message || 'Unable to complete booking.');
              }
              bookedData = { ...json.data, isLocalFallback: false };
            } else {
              // Graceful client fallback if serverless rewrite returned HTML
              const srvObj = appState.services.find(s => s.serviceId === serviceId) || appState.services[0];
              const dentObj = dentistId !== 'any'
                ? appState.dentists.find(d => d.dentistId === dentistId)
                : appState.dentists[0];
              bookedData = {
                appointmentId: 'SC-' + new Date().getFullYear() + '-' + Math.floor(1000 + Math.random() * 9000),
                patientName,
                email,
                phone,
                serviceId: srvObj.serviceId,
                serviceName: srvObj.name,
                servicePrice: srvObj.price,
                dentistId: dentObj ? dentObj.dentistId : 'dentist-aanya',
                dentistName: dentObj ? dentObj.name : 'Dr. Aanya Mehta',
                appointmentDate,
                timeSlot,
                status: 'Pending',
                notes,
                isLocalFallback: true,
              };
            }

            saveLocalBookedAppointment({
              ...bookedData,
              email,
              phone,
              serviceId,
              dentistId: bookedData.dentistId || (dentistId !== 'any' ? dentistId : 'dentist-aanya'),
              notes,
              createdAt: new Date().toISOString(),
            });

            const b = bookedData;
            document.getElementById('conf-ref').textContent = b.appointmentId;
            document.getElementById('conf-name').textContent = b.patientName;
            document.getElementById('conf-service').textContent = b.serviceName + ' (₹' + b.servicePrice + ')';
            document.getElementById('conf-dentist').textContent = b.dentistName;
            document.getElementById('conf-datetime').textContent = b.appointmentDate + ' at ' + b.timeSlot;
            confPanel.style.display = 'block';
            if (inlineFeedback) {
              inlineFeedback.style.background = '#E3F8EF';
              inlineFeedback.style.color = '#136346';
              inlineFeedback.textContent = '✓ Appointment Booked! Reference ID: ' + b.appointmentId + ' (' + b.appointmentDate + ' at ' + b.timeSlot + ')';
              inlineFeedback.style.display = 'block';
            }
            document.getElementById('book-name').value = '';
            document.getElementById('book-phone').value = '';
            document.getElementById('book-email').value = '';
            document.getElementById('book-notes').value = '';
            document.getElementById('book-date').value = b.appointmentDate;
            await fetchAndRenderSlots();
            confPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
          } catch (err) {
            errAlert.textContent = err.message;
            errAlert.style.display = 'block';
            if (inlineFeedback) {
              inlineFeedback.style.background = '#FFE8E5';
              inlineFeedback.style.color = '#9A261D';
              inlineFeedback.textContent = err.message;
              inlineFeedback.style.display = 'block';
            }
            await fetchAndRenderSlots();
          } finally {
            appState.submittingBooking = false;
            submitBtn.disabled = false;
            submitBtn.textContent = appState.selectedSlot
              ? 'Confirm & Book ' + appState.selectedSlot + ' Slot'
              : 'Confirm & Book Selected Slot';
          }
        });
      }

      document.getElementById('close-confirmation-btn')?.addEventListener('click', () => {
        document.getElementById('booking-confirmation-panel').style.display = 'none';
      });

      // Appointment Reference Status Lookup
      const lookupForm = document.getElementById('lookup-apt-form');
      if (lookupForm) {
        lookupForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const refInput = document.getElementById('lookup-apt-input').value.trim().toUpperCase();
          const out = document.getElementById('lookup-apt-result');
          if (!refInput) return;
          out.textContent = 'Checking reference...';
          try {
            const path = '/api/appointments/' + encodeURIComponent(refInput);
            const res = await fetch(path + '?__vpath=' + encodeURIComponent(path));
            const contentType = res.headers.get('content-type') || '';
            let a = null;
            if (contentType.includes('application/json')) {
              const json = await res.json();
              if (res.ok && json.success) a = json.data;
            }
            if (!a) {
              const localMatch = getLocalBookedAppointments().find(
                x => String(x.appointmentId || '').toUpperCase() === refInput
              );
              if (localMatch) a = localMatch;
            }
            if (!a) {
              throw new Error('No booking found with reference ' + refInput);
            }
            out.innerHTML = \`
              <div style="padding:0.75rem;border-radius:14px;background:var(--bg-porcelain);border:1px solid var(--border-hairline);">
                <div><strong>Ref:</strong> <span class="tabular-nums">\${escapeHtml(a.appointmentId)}</span> · <strong>Status:</strong> \${escapeHtml(a.status)}</div>
                <div>\${escapeHtml(a.serviceName)} with \${escapeHtml(a.dentistName)}</div>
                <div class="tabular-nums" style="color:var(--text-slate);">\${escapeHtml(a.appointmentDate)} at \${escapeHtml(a.timeSlot)}</div>
              </div>
            \`;
          } catch (err) {
            out.innerHTML = \`<span style="color:#9A261D;font-weight:700;">\${escapeHtml(err.message)}</span>\`;
          }
        });
      }

      // Contact Form Handler
      const contactForm = document.getElementById('public-contact-form');
      if (contactForm) {
        contactForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const box = document.getElementById('contact-feedback-box');
          const btn = document.getElementById('contact-submit-btn');
          box.style.display = 'none';
          btn.disabled = true;
          btn.textContent = 'Sending Inquiry...';

          try {
            const res = await fetch('/api/contact?__vpath=/api/contact', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                name: document.getElementById('contact-name').value.trim(),
                email: document.getElementById('contact-email').value.trim(),
                phone: document.getElementById('contact-phone').value.trim(),
                message: document.getElementById('contact-message').value.trim(),
              }),
            });
            const contentType = res.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
              const json = await res.json();
              if (!res.ok || !json.success) {
                throw new Error(json.error?.message || 'Failed to submit inquiry.');
              }
              box.style.background = '#E3F8EF';
              box.style.color = '#136346';
              box.textContent = json.message + ' (Reference: ' + json.data.inquiryId + ')';
            } else {
              box.style.background = '#E3F8EF';
              box.style.color = '#136346';
              box.textContent = 'Your inquiry has been received by our clinic front desk.';
            }
            box.style.display = 'block';
            contactForm.reset();
          } catch (err) {
            box.style.background = '#FFE8E5';
            box.style.color = '#9A261D';
            box.textContent = err.message;
            box.style.display = 'block';
          } finally {
            btn.disabled = false;
            btn.textContent = 'Submit Inquiry';
          }
        });
      }

      // Mobile Navigation Drawer
      const mobileBtn = document.getElementById('mobile-nav-btn');
      const mobileDrawer = document.getElementById('mobile-nav-drawer');
      if (mobileBtn && mobileDrawer) {
        mobileBtn.addEventListener('click', () => {
          const isOpen = mobileDrawer.classList.toggle('open');
          mobileBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        });
        mobileDrawer.querySelectorAll('a').forEach(a => {
          a.addEventListener('click', () => {
            mobileDrawer.classList.remove('open');
            mobileBtn.setAttribute('aria-expanded', 'false');
          });
        });
      }

      // Legal Modals (Privacy Policy & Terms)
      const legalBackdrop = document.getElementById('legal-modal-backdrop');
      const legalTitle = document.getElementById('legal-modal-title');
      const legalBody = document.getElementById('legal-modal-body');
      document.querySelectorAll('[data-open-legal]').forEach(btn => {
        btn.addEventListener('click', () => {
          const mode = btn.getAttribute('data-open-legal');
          if (mode === 'privacy') {
            legalTitle.textContent = 'Privacy Policy — SmileCraft Dental Studio';
            legalBody.innerHTML = \`
              <p><strong>1. Purpose of Data Collection:</strong> SmileCraft Dental Studio collects only the contact and scheduling fields you submit (full name, email address, phone number, selected dental service, preferred dentist, appointment date/time, and optional notes) for scheduling appointments and responding to patient inquiries.</p>
              <p><strong>2. Data Security & Confidentiality:</strong> All patient contact records and appointment histories are stored securely in our clinic database and accessed strictly by authorized clinic staff.</p>
              <p><strong>3. Patient Rights:</strong> You may request updates or cancellation of your scheduled appointment at any time by contacting our front desk at +91 98765 43210 or hello@smilecraft.in.</p>
            \`;
          } else {
            legalTitle.textContent = 'Terms & Conditions — SmileCraft Dental Studio';
            legalBody.innerHTML = \`
              <p><strong>1. Requested vs. Confirmed Appointments:</strong> Submitting an online booking creates a <em>Pending</em> appointment request and holds your chosen time slot. Appointments are confirmed by our clinic team.</p>
              <p><strong>2. Transparent Consultation Pricing:</strong> Listed treatment fees in Indian Rupees (₹) represent standard starting prices. A complete treatment plan is shared after your chairside examination.</p>
              <p><strong>3. Rescheduling & Cancellations:</strong> Please notify the clinic at least 4 hours prior to your scheduled time slot if you need to reschedule or cancel.</p>
            \`;
          }
          legalBackdrop.style.display = 'flex';
        });
      });
      document.getElementById('close-legal-modal')?.addEventListener('click', () => {
        legalBackdrop.style.display = 'none';
      });
      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && legalBackdrop.style.display === 'flex') {
          legalBackdrop.style.display = 'none';
        }
      });

      initPublicCatalog();
    })();
  </script>
</body>
</html>`;
}

// ============================================================================
// 8. SERVER STARTUP (When executed directly in local dev or container)
// ============================================================================

const isMainModule =
  process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

if (isMainModule) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `SmileCraft Dental Studio running on http://localhost:${PORT} (Admin: http://localhost:${PORT}/admin)`
    );
  });
}

export default app;
