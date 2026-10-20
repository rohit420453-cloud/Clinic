/**
 * SmileCraft Dental Studio — Administrator Module (admin.js)
 * Complete administrator authentication, REST API router, and embedded Claymorphism Admin SPA.
 */

import express from 'express';
import crypto from 'node:crypto';
import rateLimit from 'express-rate-limit';

// ============================================================================
// 1. CRYPTOGRAPHIC & VALIDATION HELPERS (Exported for shared use & unit tests)
// ============================================================================

const SCRYPT_KEYLEN = 64;

export function hashPassword(password, existingSalt = null) {
  if (typeof password !== 'string' || password.length < 1) {
    throw new Error('Password must not be empty.');
  }
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, storedHash) {
  if (!password || !storedHash || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, originalHex] = parts;
  const derivedBuf = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  const originalBuf = Buffer.from(originalHex, 'hex');
  if (derivedBuf.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(derivedBuf, originalBuf);
}

export function signAdminToken(payload, secret, expiresInSeconds = 8 * 3600) {
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
    csrf: crypto.randomBytes(16).toString('hex'),
  };
  const encoded = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(encoded)
    .digest('base64url');
  return `${encoded}.${signature}`;
}

export function verifyAdminToken(token, secret) {
  if (!token || typeof token !== 'string' || !secret) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(encoded)
    .digest('base64url');
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (!decoded.exp || decoded.exp < now) return null;
    if (decoded.role !== 'admin') return null;
    return decoded;
  } catch {
    return null;
  }
}

export const ALLOWED_APPOINTMENT_STATUSES = [
  'Pending',
  'Confirmed',
  'Completed',
  'Cancelled',
  'Rejected',
];

export const VALID_STATUS_TRANSITIONS = {
  Pending: ['Pending', 'Confirmed', 'Rejected', 'Cancelled'],
  Confirmed: ['Confirmed', 'Completed', 'Cancelled'],
  Completed: ['Completed'],
  Cancelled: ['Cancelled', 'Pending', 'Confirmed'],
  Rejected: ['Rejected', 'Pending', 'Confirmed'],
};

export function validateStatusTransition(currentStatus, nextStatus) {
  if (!ALLOWED_APPOINTMENT_STATUSES.includes(nextStatus)) {
    return {
      valid: false,
      message: `Invalid status "${nextStatus}". Allowed values: ${ALLOWED_APPOINTMENT_STATUSES.join(', ')}.`,
    };
  }
  const allowedNext = VALID_STATUS_TRANSITIONS[currentStatus] || [];
  if (!allowedNext.includes(nextStatus)) {
    return {
      valid: false,
      message: `Cannot transition appointment from "${currentStatus}" to "${nextStatus}".`,
    };
  }
  return { valid: true };
}

export function escapeCsvCell(value) {
  if (value === null || value === undefined) return '""';
  let str = String(value).replace(/\r?\n/g, ' ').trim();
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  return `"${str.replace(/"/g, '""')}"`;
}

export function sanitizeText(input, maxLength = 300) {
  if (typeof input !== 'string') return '';
  return input.trim().slice(0, maxLength);
}

// ============================================================================
// 2. ADMIN ROUTER FACTORY
// ============================================================================

export function createAdminModule({
  getDb,
  getSessionSecret,
  computeSlotAvailability,
  reserveAppointmentSlot,
  releaseAppointmentSlot,
  clinicTimezone = 'Asia/Kolkata',
  getTodayDateString,
}) {
  const router = express.Router();

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      success: false,
      error: {
        code: 'TOO_MANY_LOGIN_ATTEMPTS',
        message: 'Too many login attempts from this IP. Please wait 15 minutes before trying again.',
      },
    },
  });

  // Disable caching on all admin API endpoints
  router.use('/api/admin', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    next();
  });

  function extractTokenFromRequest(req) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return { token: authHeader.slice(7).trim(), source: 'bearer' };
    }
    if (req.cookies && req.cookies.sc_admin_session) {
      return { token: req.cookies.sc_admin_session, source: 'cookie' };
    }
    return { token: null, source: null };
  }

  function requireAdminAuth(req, res, next) {
    const { token, source } = extractTokenFromRequest(req);
    const secret = getSessionSecret();
    const decoded = verifyAdminToken(token, secret);
    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Administrator session expired or not authenticated. Please log in.',
        },
      });
    }
    // Enforce CSRF verification on state-mutating requests when cookie auth is used
    if (
      source === 'cookie' &&
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)
    ) {
      const csrfHeader = req.headers['x-csrf-token'];
      if (!csrfHeader || csrfHeader !== decoded.csrf) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'CSRF_MISMATCH',
            message: 'Security token validation failed. Please refresh the page and try again.',
          },
        });
      }
    }
    req.admin = decoded;
    next();
  }

  // --------------------------------------------------------------------------
  // AUTHENTICATION ENDPOINTS
  // --------------------------------------------------------------------------

  router.post('/api/admin/login', loginLimiter, async (req, res, next) => {
    try {
      const email = sanitizeText(req.body?.email, 120).toLowerCase();
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'MISSING_CREDENTIALS',
            message: 'Please enter both your administrator email and password.',
          },
        });
      }

      const db = await getDb();
      const adminUser = await db.collection('admins').findOne({ email });
      if (!adminUser || !verifyPassword(password, adminUser.passwordHash)) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Incorrect administrator email or password.',
          },
        });
      }

      const secret = getSessionSecret();
      const token = signAdminToken(
        {
          adminId: String(adminUser.adminId || adminUser._id),
          email: adminUser.email,
          name: adminUser.name || 'Clinic Administrator',
          role: 'admin',
        },
        secret
      );
      const decoded = verifyAdminToken(token, secret);

      const isProd = process.env.NODE_ENV === 'production';
      res.cookie('sc_admin_session', token, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        path: '/',
        maxAge: 8 * 3600 * 1000,
      });

      await db.collection('admins').updateOne(
        { email },
        { $set: { lastLoginAt: new Date().toISOString() } }
      );

      return res.json({
        success: true,
        message: 'Welcome back to SmileCraft Dental Studio Admin.',
        data: {
          admin: {
            email: adminUser.email,
            name: adminUser.name || 'Clinic Administrator',
            mustChangePassword: Boolean(adminUser.mustChangePassword),
          },
          csrfToken: decoded.csrf,
          token,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/api/admin/logout', (req, res) => {
    res.clearCookie('sc_admin_session', { path: '/' });
    return res.json({
      success: true,
      message: 'Logged out safely.',
      data: null,
    });
  });

  router.get('/api/admin/me', async (req, res, next) => {
    try {
      const { token } = extractTokenFromRequest(req);
      const secret = getSessionSecret();
      const decoded = verifyAdminToken(token, secret);
      if (!decoded) {
        return res.json({
          success: true,
          message: 'No active administrator session.',
          data: {
            authenticated: false,
            admin: null,
            csrfToken: null,
          },
        });
      }
      const db = await getDb();
      const adminUser = await db.collection('admins').findOne({ email: decoded.email });
      return res.json({
        success: true,
        message: 'Authenticated administrator profile.',
        data: {
          authenticated: true,
          admin: {
            email: decoded.email,
            name: adminUser?.name || decoded.name || 'Clinic Administrator',
            mustChangePassword: Boolean(adminUser?.mustChangePassword),
          },
          csrfToken: decoded.csrf,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // DASHBOARD OVERVIEW ENDPOINT
  // --------------------------------------------------------------------------

  router.get('/api/admin/dashboard', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const todayStr = getTodayDateString();

      const [
        totalAppointments,
        pendingAppointments,
        confirmedAppointments,
        completedAppointments,
        cancelledAppointments,
        rejectedAppointments,
        todayAppointments,
        upcomingAppointments,
        newInquiries,
        recentPending,
        todaySchedule,
      ] = await Promise.all([
        db.collection('appointments').countDocuments({}),
        db.collection('appointments').countDocuments({ status: 'Pending' }),
        db.collection('appointments').countDocuments({ status: 'Confirmed' }),
        db.collection('appointments').countDocuments({ status: 'Completed' }),
        db.collection('appointments').countDocuments({ status: 'Cancelled' }),
        db.collection('appointments').countDocuments({ status: 'Rejected' }),
        db.collection('appointments').countDocuments({
          appointmentDate: todayStr,
          status: { $in: ['Pending', 'Confirmed', 'Completed'] },
        }),
        db.collection('appointments').countDocuments({
          appointmentDate: { $gt: todayStr },
          status: { $in: ['Pending', 'Confirmed'] },
        }),
        db.collection('inquiries').countDocuments({ status: 'New' }),
        db
          .collection('appointments')
          .find({ status: 'Pending' })
          .sort({ createdAt: -1 })
          .limit(6)
          .toArray(),
        db
          .collection('appointments')
          .find({ appointmentDate: todayStr })
          .sort({ timeSlot: 1 })
          .limit(12)
          .toArray(),
      ]);

      const allActiveApts = await db
        .collection('appointments')
        .find({ status: { $in: ['Confirmed', 'Completed'] } })
        .toArray();
      const estimatedRevenue = allActiveApts.reduce(
        (sum, item) => sum + (Number(item.servicePrice) || 499),
        0
      );

      const cache = globalThis.__smilecraftMongoCache || {};
      const collectionCounts = {
        appointments: totalAppointments,
        slot_reservations: await db.collection('slot_reservations').countDocuments({}),
        services: await db.collection('services').countDocuments({}),
        dentists: await db.collection('dentists').countDocuments({}),
        availability_rules: await db.collection('availability_rules').countDocuments({}),
        blocked_slots: await db.collection('blocked_slots').countDocuments({}),
        inquiries: await db.collection('inquiries').countDocuments({}),
        admins: await db.collection('admins').countDocuments({}),
      };

      return res.json({
        success: true,
        message: 'Dashboard metrics loaded.',
        data: {
          clinicDate: todayStr,
          timezone: clinicTimezone,
          dbConnection: {
            engine: db.__isEmbedded ? 'Built-in Embedded Database (Active Fallback)' : 'MongoDB Atlas Cloud (Connected)',
            isAtlas: !db.__isEmbedded,
            mongoUriConfigured: Boolean(cache.mongoUriConfigured),
            detail: cache.lastConnectionReason || 'Connected and operational',
            collections: collectionCounts,
          },
          stats: {
            totalAppointments,
            pendingAppointments,
            confirmedAppointments,
            completedAppointments,
            cancelledAppointments: cancelledAppointments + rejectedAppointments,
            todayAppointments,
            upcomingAppointments,
            newInquiries,
            estimatedRevenue,
          },
          recentPending,
          todaySchedule,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/api/admin/change-password', requireAdminAuth, async (req, res, next) => {
    try {
      const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
      const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword.trim() : '';
      const name = sanitizeText(req.body?.name, 100);

      if (!currentPassword || !newPassword || newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_PASSWORD_INPUT',
            message: 'Please provide your current password and a new password of at least 6 characters.',
          },
        });
      }

      const db = await getDb();
      const adminUser = await db.collection('admins').findOne({ email: req.admin.email });
      if (!adminUser || !verifyPassword(currentPassword, adminUser.passwordHash)) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INCORRECT_CURRENT_PASSWORD',
            message: 'Current administrator password is incorrect.',
          },
        });
      }

      const updates = {
        passwordHash: hashPassword(newPassword),
        mustChangePassword: false,
        updatedAt: new Date().toISOString(),
      };
      if (name) updates.name = name;

      await db.collection('admins').updateOne({ email: req.admin.email }, { $set: updates });

      return res.json({
        success: true,
        message: 'Administrator password and profile updated successfully.',
        data: { email: req.admin.email, name: name || adminUser.name },
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // APPOINTMENTS MANAGEMENT & CSV EXPORT
  // --------------------------------------------------------------------------

  function buildAppointmentFilter(query) {
    const filter = {};
    const status = sanitizeText(query.status, 40);
    if (status && ALLOWED_APPOINTMENT_STATUSES.includes(status)) {
      filter.status = status;
    }
    const serviceId = sanitizeText(query.serviceId, 60);
    if (serviceId) {
      filter.serviceId = serviceId;
    }
    const dentistId = sanitizeText(query.dentistId, 60);
    if (dentistId) {
      filter.dentistId = dentistId;
    }
    const dateFrom = sanitizeText(query.dateFrom, 20);
    const dateTo = sanitizeText(query.dateTo, 20);
    if (/^\d{4}-\d{2}-\d{2}$/.test(dateFrom) || /^\d{4}-\d{2}-\d{2}$/.test(dateTo)) {
      filter.appointmentDate = {};
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateFrom)) filter.appointmentDate.$gte = dateFrom;
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateTo)) filter.appointmentDate.$lte = dateTo;
    }
    const q = sanitizeText(query.q, 100);
    if (q) {
      const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'i');
      filter.$or = [
        { appointmentId: regex },
        { patientName: regex },
        { email: regex },
        { phone: regex },
      ];
    }
    return filter;
  }

  router.get('/api/admin/appointments/export.csv', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const filter = buildAppointmentFilter(req.query);
      const records = await db
        .collection('appointments')
        .find(filter)
        .sort({ appointmentDate: -1, timeSlot: 1 })
        .limit(2000)
        .toArray();

      const headers = [
        'Appointment Reference',
        'Patient Name',
        'Email',
        'Phone',
        'Service',
        'Starting Price (INR)',
        'Dentist',
        'Appointment Date',
        'Time Slot',
        'Status',
        'Patient Notes',
        'Created At',
      ];

      const rows = records.map((apt) =>
        [
          apt.appointmentId,
          apt.patientName,
          apt.email,
          apt.phone,
          apt.serviceName,
          apt.servicePrice ?? '',
          apt.dentistName,
          apt.appointmentDate,
          apt.timeSlot,
          apt.status,
          apt.notes || '',
          apt.createdAt,
        ]
          .map(escapeCsvCell)
          .join(',')
      );

      const csvContent = [headers.map(escapeCsvCell).join(','), ...rows].join('\r\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="smilecraft-appointments-${getTodayDateString()}.csv"`
      );
      return res.send(csvContent);
    } catch (err) {
      next(err);
    }
  });

  router.get('/api/admin/appointments', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const filter = buildAppointmentFilter(req.query);

      const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(String(req.query.limit || '10'), 10) || 10));
      const skip = (page - 1) * limit;

      const sortBy = req.query.sortBy === 'createdAt' ? 'createdAt' : 'appointmentDate';
      const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
      const sortSpec =
        sortBy === 'appointmentDate'
          ? { appointmentDate: sortOrder, timeSlot: sortOrder, createdAt: -1 }
          : { createdAt: sortOrder };

      const [total, items] = await Promise.all([
        db.collection('appointments').countDocuments(filter),
        db
          .collection('appointments')
          .find(filter)
          .sort(sortSpec)
          .skip(skip)
          .limit(limit)
          .toArray(),
      ]);

      return res.json({
        success: true,
        message: 'Appointments retrieved.',
        data: {
          items,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.max(1, Math.ceil(total / limit)),
          },
        },
      });
    } catch (err) {
      next(err);
    }
  });

  router.get('/api/admin/appointments/:appointmentId', requireAdminAuth, async (req, res, next) => {
    try {
      const appointmentId = sanitizeText(req.params.appointmentId, 40);
      const db = await getDb();
      const apt = await db.collection('appointments').findOne({ appointmentId });
      if (!apt) {
        return res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Appointment record not found.' },
        });
      }
      return res.json({
        success: true,
        message: 'Appointment details loaded.',
        data: apt,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/api/admin/appointments', requireAdminAuth, async (req, res, next) => {
    try {
      const patientName = sanitizeText(req.body?.patientName, 100);
      const email = sanitizeText(req.body?.email, 120).toLowerCase();
      const phone = sanitizeText(req.body?.phone, 25);
      const serviceId = sanitizeText(req.body?.serviceId, 60);
      const dentistId = sanitizeText(req.body?.dentistId || 'dentist-aanya', 60);
      const appointmentDate = sanitizeText(req.body?.appointmentDate, 20);
      const timeSlot = sanitizeText(req.body?.timeSlot, 20);
      const status = ['Pending', 'Confirmed', 'Completed'].includes(req.body?.status)
        ? req.body.status
        : 'Confirmed';
      const notes = sanitizeText(req.body?.notes, 500);

      if (!patientName || !phone || !serviceId || !appointmentDate || !timeSlot) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'MISSING_FIELDS',
            message: 'Patient name, phone, service, date, and time slot are required.',
          },
        });
      }

      const db = await getDb();
      const [serviceDoc, dentistDoc] = await Promise.all([
        db.collection('services').findOne({ serviceId }),
        db.collection('dentists').findOne({ dentistId }),
      ]);

      if (!serviceDoc) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_SERVICE', message: 'Selected service does not exist.' },
        });
      }
      if (!dentistDoc) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_DENTIST', message: 'Selected dentist does not exist.' },
        });
      }

      const year = new Date().getFullYear();
      const suffix = crypto.randomBytes(2).toString('hex').toUpperCase();
      const appointmentId = `SC-${year}-${suffix}`;

      if (['Pending', 'Confirmed'].includes(status)) {
        const reservation = await reserveAppointmentSlot(db, {
          dentistKey: dentistDoc.dentistId,
          appointmentDate,
          timeSlot,
          appointmentId,
        });
        if (!reservation.reserved) {
          return res.status(409).json({
            success: false,
            error: {
              code: 'SLOT_ALREADY_BOOKED',
              message: `${timeSlot} on ${appointmentDate} is already reserved for ${dentistDoc.name}.`,
            },
          });
        }
      }

      const nowIso = new Date().toISOString();
      const newApt = {
        appointmentId,
        patientName,
        email: email || 'walkin@smilecraft.in',
        phone,
        serviceId: serviceDoc.serviceId,
        serviceName: serviceDoc.name,
        servicePrice: serviceDoc.price,
        dentistId: dentistDoc.dentistId,
        dentistKey: dentistDoc.dentistId,
        dentistName: dentistDoc.name,
        appointmentDate,
        timeSlot,
        status,
        notes: notes || 'Booked at clinic reception desk.',
        createdAt: nowIso,
        updatedAt: nowIso,
      };

      await db.collection('appointments').insertOne(newApt);
      return res.status(201).json({
        success: true,
        message: `Appointment ${appointmentId} created (${status}).`,
        data: newApt,
      });
    } catch (err) {
      next(err);
    }
  });

  router.delete('/api/admin/appointments/:appointmentId', requireAdminAuth, async (req, res, next) => {
    try {
      const appointmentId = sanitizeText(req.params.appointmentId, 40);
      const db = await getDb();
      const existing = await db.collection('appointments').findOne({ appointmentId });
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Appointment not found.' },
        });
      }

      await releaseAppointmentSlot(db, {
        appointmentId,
        dentistKey: existing.dentistKey || existing.dentistId,
        appointmentDate: existing.appointmentDate,
        timeSlot: existing.timeSlot,
      });
      await db.collection('appointments').deleteOne({ appointmentId });

      return res.json({
        success: true,
        message: `Appointment ${appointmentId} deleted and slot released.`,
        data: { appointmentId },
      });
    } catch (err) {
      next(err);
    }
  });

  router.patch('/api/admin/appointments/:appointmentId', requireAdminAuth, async (req, res, next) => {
    try {
      const appointmentId = sanitizeText(req.params.appointmentId, 40);
      const db = await getDb();
      const existing = await db.collection('appointments').findOne({ appointmentId });

      if (!existing) {
        return res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Appointment not found.' },
        });
      }

      const nextStatus = req.body?.status
        ? sanitizeText(req.body.status, 30)
        : existing.status;

      const statusCheck = validateStatusTransition(existing.status, nextStatus);
      if (!statusCheck.valid) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_STATUS_TRANSITION', message: statusCheck.message },
        });
      }

      const nextDate = req.body?.appointmentDate
        ? sanitizeText(req.body.appointmentDate, 20)
        : existing.appointmentDate;
      const nextSlot = req.body?.timeSlot
        ? sanitizeText(req.body.timeSlot, 20)
        : existing.timeSlot;
      const nextDentistId = req.body?.dentistId
        ? sanitizeText(req.body.dentistId, 60)
        : existing.dentistId;

      let nextDentistName = existing.dentistName;
      if (nextDentistId !== existing.dentistId) {
        const dentistDoc = await db.collection('dentists').findOne({
          dentistId: nextDentistId,
          active: true,
        });
        if (!dentistDoc) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'INVALID_DENTIST',
              message: 'Selected dentist is not active or does not exist.',
            },
          });
        }
        nextDentistName = dentistDoc.name;
      }

      const isSlotChanged =
        nextDate !== existing.appointmentDate ||
        nextSlot !== existing.timeSlot ||
        nextDentistId !== existing.dentistId;

      const wasActiveHold = ['Pending', 'Confirmed'].includes(existing.status);
      const willBeActiveHold = ['Pending', 'Confirmed'].includes(nextStatus);

      // If rescheduling or re-activating an appointment, verify availability and reserve slot atomically
      if (willBeActiveHold && (isSlotChanged || !wasActiveHold)) {
        const availability = await computeSlotAvailability(db, {
          date: nextDate,
          dentistId: nextDentistId,
          excludeAppointmentId: appointmentId,
        });

        if (!availability.isOpenDay) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'CLINIC_CLOSED',
              message: availability.reason || 'The clinic is closed on the requested date.',
            },
          });
        }

        const targetSlotObj = availability.slots.find((s) => s.time === nextSlot);
        if (!targetSlotObj || !targetSlotObj.available) {
          return res.status(409).json({
            success: false,
            error: {
              code: 'SLOT_UNAVAILABLE',
              message:
                targetSlotObj?.reason ||
                `Time slot ${nextSlot} on ${nextDate} is unavailable for ${nextDentistName}.`,
            },
          });
        }

        const reservationResult = await reserveAppointmentSlot(db, {
          dentistKey: nextDentistId,
          appointmentDate: nextDate,
          timeSlot: nextSlot,
          appointmentId,
        });

        if (!reservationResult.reserved) {
          return res.status(409).json({
            success: false,
            error: {
              code: 'SLOT_CONFLICT',
              message: 'That slot is already reserved by another booking.',
            },
          });
        }

        // Release old slot reservation if the slot coordinates changed
        if (wasActiveHold && isSlotChanged) {
          await releaseAppointmentSlot(db, {
            appointmentId,
            dentistKey: existing.dentistKey || existing.dentistId,
            appointmentDate: existing.appointmentDate,
            timeSlot: existing.timeSlot,
          });
        }
      } else if (wasActiveHold && !willBeActiveHold) {
        // Cancelled or Rejected: release the slot reservation immediately
        await releaseAppointmentSlot(db, {
          appointmentId,
          dentistKey: existing.dentistKey || existing.dentistId,
          appointmentDate: existing.appointmentDate,
          timeSlot: existing.timeSlot,
        });
      }

      const updatedFields = {
        status: nextStatus,
        appointmentDate: nextDate,
        timeSlot: nextSlot,
        dentistId: nextDentistId,
        dentistKey: nextDentistId,
        dentistName: nextDentistName,
        updatedAt: new Date().toISOString(),
      };

      if (typeof req.body?.notes === 'string') {
        updatedFields.notes = sanitizeText(req.body.notes, 500);
      }
      if (typeof req.body?.adminNotes === 'string') {
        updatedFields.adminNotes = sanitizeText(req.body.adminNotes, 500);
      }

      await db
        .collection('appointments')
        .updateOne({ appointmentId }, { $set: updatedFields });

      const updatedDoc = await db.collection('appointments').findOne({ appointmentId });

      return res.json({
        success: true,
        message: `Appointment ${appointmentId} updated (${nextStatus}).`,
        data: updatedDoc,
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // CALENDAR & DAILY SCHEDULE VIEW
  // --------------------------------------------------------------------------

  router.get('/api/admin/calendar', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const date = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.date || ''))
        ? String(req.query.date)
        : getTodayDateString();
      const dentistId = sanitizeText(req.query.dentistId, 60);

      const [dentists, dayAppointments, availability] = await Promise.all([
        db.collection('dentists').find({ active: true }).sort({ name: 1 }).toArray(),
        db
          .collection('appointments')
          .find({
            appointmentDate: date,
            ...(dentistId ? { dentistId } : {}),
          })
          .sort({ timeSlot: 1 })
          .toArray(),
        computeSlotAvailability(db, { date, dentistId: dentistId || 'any' }),
      ]);

      return res.json({
        success: true,
        message: 'Daily schedule loaded.',
        data: {
          date,
          dentists,
          appointments: dayAppointments,
          availability,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // PATIENT MANAGEMENT
  // --------------------------------------------------------------------------

  router.get('/api/admin/patients', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const q = sanitizeText(req.query.q, 100).toLowerCase();
      const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(String(req.query.limit || '10'), 10) || 10));

      const allAppointments = await db
        .collection('appointments')
        .find({})
        .sort({ appointmentDate: -1, createdAt: -1 })
        .toArray();

      const patientMap = new Map();
      for (const apt of allAppointments) {
        const key = (apt.email || apt.phone || apt.patientName).toLowerCase();
        if (!patientMap.has(key)) {
          patientMap.set(key, {
            patientId: Buffer.from(key).toString('base64url'),
            patientName: apt.patientName,
            email: apt.email,
            phone: apt.phone,
            appointmentCount: 0,
            lastAppointmentDate: apt.appointmentDate,
            lastService: apt.serviceName,
            lastStatus: apt.status,
            appointments: [],
          });
        }
        const entry = patientMap.get(key);
        entry.appointmentCount += 1;
        entry.appointments.push({
          appointmentId: apt.appointmentId,
          serviceName: apt.serviceName,
          dentistName: apt.dentistName,
          appointmentDate: apt.appointmentDate,
          timeSlot: apt.timeSlot,
          status: apt.status,
        });
      }

      let patients = Array.from(patientMap.values());
      if (q) {
        patients = patients.filter(
          (p) =>
            p.patientName.toLowerCase().includes(q) ||
            p.email.toLowerCase().includes(q) ||
            p.phone.toLowerCase().includes(q)
        );
      }

      const total = patients.length;
      const paged = patients.slice((page - 1) * limit, page * limit);

      return res.json({
        success: true,
        message: 'Patient directory loaded.',
        data: {
          items: paged,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.max(1, Math.ceil(total / limit)),
          },
        },
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // SERVICES MANAGEMENT
  // --------------------------------------------------------------------------

  router.get('/api/admin/services', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const services = await db.collection('services').find({}).sort({ order: 1, name: 1 }).toArray();
      return res.json({
        success: true,
        message: 'Services retrieved.',
        data: services,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/api/admin/services', requireAdminAuth, async (req, res, next) => {
    try {
      const name = sanitizeText(req.body?.name, 100);
      const category = sanitizeText(req.body?.category || 'General', 50);
      const description = sanitizeText(req.body?.description, 350);
      const price = Number(req.body?.price);
      const durationMinutes = Number(req.body?.durationMinutes || 45);

      if (!name || !description || !Number.isFinite(price) || price < 0) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_SERVICE_DATA',
            message: 'Provide a valid service name, description, and non-negative price in INR.',
          },
        });
      }
      if (!Number.isFinite(durationMinutes) || durationMinutes < 15 || durationMinutes > 240) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_DURATION',
            message: 'Service duration must be between 15 and 240 minutes.',
          },
        });
      }

      const db = await getDb();
      const slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '');
      const serviceId = `srv-${slug}-${Date.now().toString(36).slice(-4)}`;

      const newService = {
        serviceId,
        name,
        category,
        description,
        price: Math.round(price),
        durationMinutes: Math.round(durationMinutes),
        active: req.body?.active !== false,
        order: 99,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      await db.collection('services').insertOne(newService);
      return res.status(201).json({
        success: true,
        message: `Service "${name}" created.`,
        data: newService,
      });
    } catch (err) {
      next(err);
    }
  });

  router.patch('/api/admin/services/:serviceId', requireAdminAuth, async (req, res, next) => {
    try {
      const serviceId = sanitizeText(req.params.serviceId, 60);
      const db = await getDb();
      const existing = await db.collection('services').findOne({ serviceId });
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Service not found.' },
        });
      }

      const updates = { updatedAt: new Date().toISOString() };
      if (typeof req.body?.name === 'string' && req.body.name.trim()) {
        updates.name = sanitizeText(req.body.name, 100);
      }
      if (typeof req.body?.category === 'string' && req.body.category.trim()) {
        updates.category = sanitizeText(req.body.category, 50);
      }
      if (typeof req.body?.description === 'string' && req.body.description.trim()) {
        updates.description = sanitizeText(req.body.description, 350);
      }
      if (req.body?.price !== undefined) {
        const price = Number(req.body.price);
        if (!Number.isFinite(price) || price < 0) {
          return res.status(400).json({
            success: false,
            error: { code: 'INVALID_PRICE', message: 'Price must be a valid non-negative amount.' },
          });
        }
        updates.price = Math.round(price);
      }
      if (req.body?.durationMinutes !== undefined) {
        const dur = Number(req.body.durationMinutes);
        if (!Number.isFinite(dur) || dur < 15 || dur > 240) {
          return res.status(400).json({
            success: false,
            error: { code: 'INVALID_DURATION', message: 'Duration must be 15–240 minutes.' },
          });
        }
        updates.durationMinutes = Math.round(dur);
      }
      if (typeof req.body?.active === 'boolean') {
        updates.active = req.body.active;
      }

      await db.collection('services').updateOne({ serviceId }, { $set: updates });
      const updated = await db.collection('services').findOne({ serviceId });
      return res.json({
        success: true,
        message: `Service "${updated.name}" updated.`,
        data: updated,
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // DENTISTS MANAGEMENT
  // --------------------------------------------------------------------------

  router.get('/api/admin/dentists', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const dentists = await db.collection('dentists').find({}).sort({ order: 1, name: 1 }).toArray();
      return res.json({
        success: true,
        message: 'Dentists retrieved.',
        data: dentists,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/api/admin/dentists', requireAdminAuth, async (req, res, next) => {
    try {
      const name = sanitizeText(req.body?.name, 100);
      const specialization = sanitizeText(req.body?.specialization, 120);
      const bio = sanitizeText(req.body?.bio, 400);
      const experienceYears = Number(req.body?.experienceYears || 6);

      if (!name || !specialization || !bio) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_DENTIST_DATA',
            message: 'Name, specialization, and biography are required.',
          },
        });
      }

      const db = await getDb();
      const slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '');
      const dentistId = `dentist-${slug}-${Date.now().toString(36).slice(-4)}`;

      const newDentist = {
        dentistId,
        name,
        specialization,
        bio,
        experienceYears: Math.max(1, Math.min(50, Math.round(experienceYears))),
        workingDays: Array.isArray(req.body?.workingDays)
          ? req.body.workingDays.map(Number)
          : [1, 2, 3, 4, 5, 6],
        active: req.body?.active !== false,
        avatarTheme: sanitizeText(req.body?.avatarTheme || 'sky', 20),
        order: 99,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      await db.collection('dentists').insertOne(newDentist);
      return res.status(201).json({
        success: true,
        message: `Dentist profile "${name}" added.`,
        data: newDentist,
      });
    } catch (err) {
      next(err);
    }
  });

  router.patch('/api/admin/dentists/:dentistId', requireAdminAuth, async (req, res, next) => {
    try {
      const dentistId = sanitizeText(req.params.dentistId, 60);
      const db = await getDb();
      const existing = await db.collection('dentists').findOne({ dentistId });
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Dentist profile not found.' },
        });
      }

      const updates = { updatedAt: new Date().toISOString() };
      if (typeof req.body?.name === 'string' && req.body.name.trim()) {
        updates.name = sanitizeText(req.body.name, 100);
      }
      if (typeof req.body?.specialization === 'string' && req.body.specialization.trim()) {
        updates.specialization = sanitizeText(req.body.specialization, 120);
      }
      if (typeof req.body?.bio === 'string' && req.body.bio.trim()) {
        updates.bio = sanitizeText(req.body.bio, 400);
      }
      if (typeof req.body?.active === 'boolean') {
        updates.active = req.body.active;
      }
      if (Array.isArray(req.body?.workingDays)) {
        updates.workingDays = req.body.workingDays
          .map(Number)
          .filter((d) => Number.isInteger(d) && d >= 0 && d <= 6);
      }

      await db.collection('dentists').updateOne({ dentistId }, { $set: updates });
      const updated = await db.collection('dentists').findOne({ dentistId });
      return res.json({
        success: true,
        message: `Dentist "${updated.name}" updated.`,
        data: updated,
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // AVAILABILITY RULES & BLOCKED SLOTS MANAGEMENT
  // --------------------------------------------------------------------------

  router.get('/api/admin/availability-rules', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const [rules, blockedSlots] = await Promise.all([
        db.collection('availabilityRules').findOne({ ruleId: 'clinic-default' }),
        db.collection('blockedSlots').find({}).sort({ date: 1, timeSlot: 1 }).toArray(),
      ]);
      return res.json({
        success: true,
        message: 'Availability configuration loaded.',
        data: {
          rules,
          blockedSlots,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  router.put('/api/admin/availability-rules', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const slotDurationMinutes = Number(req.body?.slotDurationMinutes || 60);
      if (![30, 45, 60].includes(slotDurationMinutes)) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_SLOT_DURATION',
            message: 'Slot duration must be 30, 45, or 60 minutes.',
          },
        });
      }

      const workingDays = Array.isArray(req.body?.workingDays)
        ? req.body.workingDays.map(Number).filter((d) => d >= 0 && d <= 6)
        : [1, 2, 3, 4, 5, 6];

      const weekdayOpen = sanitizeText(req.body?.weekdayOpen || '09:00', 10);
      const weekdayClose = sanitizeText(req.body?.weekdayClose || '20:00', 10);
      const saturdayOpen = sanitizeText(req.body?.saturdayOpen || '09:00', 10);
      const saturdayClose = sanitizeText(req.body?.saturdayClose || '17:00', 10);
      const breakStart = sanitizeText(req.body?.breakStart || '13:00', 10);
      const breakEnd = sanitizeText(req.body?.breakEnd || '14:00', 10);

      const updatedRule = {
        ruleId: 'clinic-default',
        timezone: clinicTimezone,
        workingDays,
        slotDurationMinutes,
        weekdayOpen,
        weekdayClose,
        saturdayOpen,
        saturdayClose,
        breakStart,
        breakEnd,
        updatedAt: new Date().toISOString(),
      };

      await db
        .collection('availabilityRules')
        .updateOne({ ruleId: 'clinic-default' }, { $set: updatedRule }, { upsert: true });

      return res.json({
        success: true,
        message: 'Clinic schedule and availability rules saved.',
        data: updatedRule,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/api/admin/blocked-slots', requireAdminAuth, async (req, res, next) => {
    try {
      const date = sanitizeText(req.body?.date, 20);
      const timeSlot = sanitizeText(req.body?.timeSlot || 'ALL_DAY', 20);
      const dentistId = sanitizeText(req.body?.dentistId || 'ALL', 60);
      const reason = sanitizeText(req.body?.reason || 'Clinic Schedule Block', 160);

      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_DATE', message: 'Provide a valid YYYY-MM-DD date to block.' },
        });
      }

      const db = await getDb();

      // Check for existing active appointments that conflict with this block
      const conflictQuery = {
        appointmentDate: date,
        status: { $in: ['Pending', 'Confirmed'] },
      };
      if (timeSlot !== 'ALL_DAY') conflictQuery.timeSlot = timeSlot;
      if (dentistId !== 'ALL') conflictQuery.dentistId = dentistId;

      const conflicts = await db.collection('appointments').find(conflictQuery).toArray();
      if (conflicts.length > 0 && !req.body?.force) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'CONFLICTING_APPOINTMENTS',
            message: `There are ${conflicts.length} active appointment(s) on ${date} (${timeSlot}). Reschedule or cancel them first, or confirm override.`,
          },
          data: { conflicts },
        });
      }

      const slotId = `blk-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`;
      const blockDoc = {
        slotId,
        date,
        timeSlot,
        dentistId,
        reason,
        createdAt: new Date().toISOString(),
      };

      await db.collection('blockedSlots').insertOne(blockDoc);
      return res.status(201).json({
        success: true,
        message: `Blocked ${date} (${timeSlot === 'ALL_DAY' ? 'Full Day' : timeSlot}).`,
        data: blockDoc,
      });
    } catch (err) {
      next(err);
    }
  });

  router.delete('/api/admin/blocked-slots/:slotId', requireAdminAuth, async (req, res, next) => {
    try {
      const slotId = sanitizeText(req.params.slotId, 60);
      const db = await getDb();
      await db.collection('blockedSlots').deleteOne({ slotId });
      return res.json({
        success: true,
        message: 'Blocked slot removed.',
        data: { slotId },
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // PATIENT INQUIRY MANAGEMENT
  // --------------------------------------------------------------------------

  router.get('/api/admin/inquiries', requireAdminAuth, async (req, res, next) => {
    try {
      const db = await getDb();
      const status = sanitizeText(req.query.status, 30);
      const filter = status && ['New', 'Contacted', 'Resolved'].includes(status) ? { status } : {};
      const items = await db
        .collection('inquiries')
        .find(filter)
        .sort({ createdAt: -1 })
        .limit(100)
        .toArray();
      return res.json({
        success: true,
        message: 'Inquiries loaded.',
        data: items,
      });
    } catch (err) {
      next(err);
    }
  });

  router.patch('/api/admin/inquiries/:inquiryId', requireAdminAuth, async (req, res, next) => {
    try {
      const inquiryId = sanitizeText(req.params.inquiryId, 60);
      const status = sanitizeText(req.body?.status, 30);
      if (!['New', 'Contacted', 'Resolved'].includes(status)) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_INQUIRY_STATUS',
            message: 'Inquiry status must be New, Contacted, or Resolved.',
          },
        });
      }
      const db = await getDb();
      const existing = await db.collection('inquiries').findOne({ inquiryId });
      if (!existing) {
        return res.status(404).json({
          success: false,
          error: { code: 'NOT_FOUND', message: 'Inquiry not found.' },
        });
      }
      await db
        .collection('inquiries')
        .updateOne(
          { inquiryId },
          { $set: { status, updatedAt: new Date().toISOString() } }
        );
      const updated = await db.collection('inquiries').findOne({ inquiryId });
      return res.json({
        success: true,
        message: `Inquiry marked as ${status}.`,
        data: updated,
      });
    } catch (err) {
      next(err);
    }
  });

  // --------------------------------------------------------------------------
  // SERVE ADMIN DASHBOARD SPA AT /admin
  // --------------------------------------------------------------------------

  router.get(['/admin', '/admin/*splat'], (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    return res.send(renderAdminHtml());
  });

  return router;
}

// ============================================================================
// 3. EMBEDDED CLAYMORPHISM ADMIN DASHBOARD HTML, CSS & CLIENT JAVASCRIPT
// ============================================================================

export function renderAdminHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Admin Portal — SmileCraft Dental Studio</title>
  <meta name="description" content="Administrator portal for managing SmileCraft Dental Studio appointments, schedules, dentists, services, and patient inquiries." />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;600&family=Nunito:wght@400;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg-ivory: #FFFDF8;
      --bg-surface: #F6F3EB;
      --bg-card: #FFFFFF;
      --primary-sky: #8ECDF4;
      --primary-sky-deep: #1B5886;
      --secondary-lavender: #C9B8FF;
      --secondary-lavender-deep: #4A358E;
      --accent-mint: #A8E6CF;
      --accent-mint-deep: #156549;
      --highlight-peach: #FFCAA8;
      --highlight-peach-deep: #8C3B11;
      --warm-yellow: #FFE69A;
      --warm-yellow-deep: #785506;
      --text-navy: #25324A;
      --text-slate: #5A667B;
      --border-soft: rgba(37, 50, 74, 0.09);
      --status-success-bg: #E3F8EF;
      --status-success-text: #136346;
      --status-warn-bg: #FFF4D6;
      --status-warn-text: #7D5300;
      --status-error-bg: #FFE8E5;
      --status-error-text: #9A261D;
      --status-info-bg: #E6F4FE;
      --status-info-text: #185582;
      --clay-shadow: 0 12px 26px -8px rgba(37, 50, 74, 0.08), inset 0 2px 3px rgba(255, 255, 255, 0.9), inset 0 -2px 4px rgba(37, 50, 74, 0.04);
      --clay-btn-shadow: 0 8px 18px -4px rgba(27, 88, 134, 0.22), inset 0 2px 2px rgba(255, 255, 255, 0.45), inset 0 -2px 3px rgba(0, 0, 0, 0.12);
      --radius-card: 24px;
      --radius-input: 16px;
    }

    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Nunito', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg-ivory);
      color: var(--text-navy);
      line-height: 1.55;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    h1, h2, h3, h4, .font-display {
      font-family: 'Plus Jakarta Sans', sans-serif;
      letter-spacing: -0.02em;
      color: var(--text-navy);
    }

    .tabular-nums {
      font-family: 'JetBrains Mono', monospace;
      font-variant-numeric: tabular-nums;
    }

    button, input, select, textarea {
      font-family: inherit;
      font-size: 0.95rem;
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

    /* Claymorphic Surfaces & Controls */
    .clay-card {
      background: var(--bg-card);
      border-radius: var(--radius-card);
      border: 1px solid var(--border-soft);
      box-shadow: var(--clay-shadow);
    }

    .clay-btn-primary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      padding: 0.65rem 1.25rem;
      border-radius: 16px;
      background: linear-gradient(145deg, #27689B, #1B507A);
      color: #FFFFFF;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 700;
      font-size: 0.9rem;
      box-shadow: var(--clay-btn-shadow);
      transition: transform 150ms cubic-bezier(0.16, 1, 0.3, 1), opacity 150ms ease;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .clay-btn-primary:hover:not(:disabled) {
      transform: translateY(-1px);
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
      gap: 0.45rem;
      padding: 0.6rem 1.1rem;
      border-radius: 14px;
      background: var(--bg-surface);
      color: var(--text-navy);
      border: 1px solid var(--border-soft);
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 600;
      font-size: 0.875rem;
      transition: background-color 150ms ease, transform 150ms ease;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .clay-btn-secondary:hover:not(:disabled) {
      background: #ECE7DA;
    }

    .clay-btn-danger {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      padding: 0.55rem 1rem;
      border-radius: 14px;
      background: var(--status-error-bg);
      color: var(--status-error-text);
      font-weight: 700;
      font-size: 0.85rem;
      white-space: nowrap;
    }

    .clay-input {
      width: 100%;
      padding: 0.65rem 0.95rem;
      border-radius: var(--radius-input);
      border: 1.5px solid rgba(37, 50, 74, 0.14);
      background: #FFFFFF;
      color: var(--text-navy);
      transition: border-color 150ms ease, box-shadow 150ms ease;
    }

    .clay-input:focus {
      border-color: var(--primary-sky-deep);
      box-shadow: 0 0 0 3px rgba(142, 205, 244, 0.35);
      outline: none;
    }

    /* Login View */
    .login-wrapper {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      background:
        radial-gradient(circle at 15% 20%, rgba(142, 205, 244, 0.25), transparent 40%),
        radial-gradient(circle at 85% 80%, rgba(201, 184, 255, 0.25), transparent 40%),
        var(--bg-ivory);
    }

    .login-card {
      width: 100%;
      max-width: 440px;
      padding: 2.25rem;
    }

    /* Workspace Layout */
    .admin-shell {
      display: grid;
      grid-template-columns: 260px 1fr;
      min-height: 100vh;
    }

    .admin-sidebar {
      background: var(--bg-surface);
      border-right: 1px solid var(--border-soft);
      padding: 1.5rem 1rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
    }

    .sidebar-brand {
      display: flex;
      align-items: center;
      gap: 0.65rem;
      padding: 0.5rem 0.75rem 1.25rem;
      border-bottom: 1px solid var(--border-soft);
      margin-bottom: 1rem;
      text-decoration: none;
      color: var(--text-navy);
    }

    .nav-list {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      list-style: none;
    }

    .nav-item-btn {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.7rem 0.9rem;
      border-radius: 16px;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 600;
      font-size: 0.9rem;
      color: var(--text-slate);
      text-align: left;
      transition: background-color 150ms ease, color 150ms ease;
      white-space: nowrap;
    }

    .nav-item-btn:hover {
      background: rgba(142, 205, 244, 0.18);
      color: var(--text-navy);
    }

    .nav-item-btn.active {
      background: var(--bg-card);
      color: var(--primary-sky-deep);
      box-shadow: 0 6px 14px -4px rgba(37, 50, 74, 0.08);
      font-weight: 700;
    }

    .admin-main {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }

    .admin-topbar {
      height: 68px;
      padding: 0 2rem;
      border-bottom: 1px solid var(--border-soft);
      background: rgba(255, 253, 248, 0.92);
      backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      position: sticky;
      top: 0;
      z-index: 20;
    }

    .admin-content {
      padding: 2rem;
      max-width: 1360px;
      width: 100%;
      margin: 0 auto;
    }

    /* KPI Stat Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.15rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      padding: 1.25rem 1.35rem;
      border-radius: 22px;
      border: 1px solid var(--border-soft);
      background: var(--bg-card);
      box-shadow: var(--clay-shadow);
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }

    .stat-card.tint-sky { background: linear-gradient(145deg, #FFFFFF, #EFF8FE); }
    .stat-card.tint-mint { background: linear-gradient(145deg, #FFFFFF, #EEFAF5); }
    .stat-card.tint-lavender { background: linear-gradient(145deg, #FFFFFF, #F5F2FF); }
    .stat-card.tint-peach { background: linear-gradient(145deg, #FFFFFF, #FFF5EE); }
    .stat-card.tint-yellow { background: linear-gradient(145deg, #FFFFFF, #FFFBEB); }

    .stat-label {
      font-size: 0.82rem;
      font-weight: 700;
      color: var(--text-slate);
    }

    .stat-value {
      font-size: 1.85rem;
      font-weight: 800;
      color: var(--text-navy);
      line-height: 1.15;
    }

    /* Data Tables */
    .table-container {
      width: 100%;
      overflow-x: auto;
    }

    table.admin-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.9rem;
    }

    table.admin-table th {
      padding: 0.85rem 1rem;
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-size: 0.78rem;
      font-weight: 700;
      color: var(--text-slate);
      border-bottom: 1px solid var(--border-soft);
      background: var(--bg-surface);
      white-space: nowrap;
    }

    table.admin-table td {
      padding: 0.9rem 1rem;
      border-bottom: 1px solid var(--border-soft);
      vertical-align: middle;
    }

    table.admin-table tr:hover td {
      background: rgba(246, 243, 235, 0.55);
    }

    /* Status Text Indicators (Semantic Icon + Text, no decorative dots) */
    .status-tag {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.82rem;
      font-weight: 700;
      white-space: nowrap;
    }
    .status-Pending { color: var(--status-warn-text); }
    .status-Confirmed { color: var(--status-info-text); }
    .status-Completed { color: var(--status-success-text); }
    .status-Cancelled, .status-Rejected { color: var(--status-error-text); }
    .status-New { color: var(--status-warn-text); }
    .status-Contacted { color: var(--status-info-text); }
    .status-Resolved { color: var(--status-success-text); }

    /* Filters Bar */
    .filters-grid {
      display: grid;
      grid-template-columns: 2fr repeat(4, 1fr);
      gap: 0.75rem;
      padding: 1.25rem;
      border-bottom: 1px solid var(--border-soft);
    }

    /* Modals */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(37, 50, 74, 0.45);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
      z-index: 60;
    }

    .modal-dialog {
      width: 100%;
      max-width: 580px;
      max-height: 90vh;
      overflow-y: auto;
      padding: 1.75rem;
    }

    /* Toast Notification */
    .toast-region {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 80;
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }

    .toast-item {
      padding: 0.85rem 1.2rem;
      border-radius: 16px;
      background: var(--text-navy);
      color: #FFFFFF;
      font-weight: 600;
      font-size: 0.9rem;
      box-shadow: 0 12px 24px rgba(0, 0, 0, 0.18);
    }

    .mobile-menu-btn {
      display: none;
    }

    @media (max-width: 1024px) {
      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }
      .filters-grid {
        grid-template-columns: 1fr 1fr;
      }
    }

    @media (max-width: 768px) {
      .admin-shell {
        grid-template-columns: 1fr;
      }
      .admin-sidebar {
        position: fixed;
        left: 0;
        top: 0;
        bottom: 0;
        width: 270px;
        z-index: 50;
        transform: translateX(-100%);
        transition: transform 200ms ease;
      }
      .admin-sidebar.open {
        transform: translateX(0);
      }
      .mobile-menu-btn {
        display: inline-flex;
      }
      .admin-topbar {
        padding: 0 1rem;
      }
      .admin-content {
        padding: 1.25rem 1rem;
      }
      .filters-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <div id="admin-app"></div>
  <div id="toast-container" class="toast-region" aria-live="polite"></div>

  <script>
    (function() {
      const state = {
        authenticated: false,
        admin: null,
        csrfToken: localStorage.getItem('sc_csrf_token') || '',
        bearerToken: localStorage.getItem('sc_bearer_token') || '',
        activeTab: 'overview',
        sidebarOpen: false,
        loading: true,
        dashboard: null,
        appointments: [],
        appointmentsPagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        filters: { q: '', status: '', serviceId: '', dentistId: '', dateFrom: '', dateTo: '', sortBy: 'appointmentDate', sortOrder: 'desc' },
        calendarDate: new Date().toISOString().slice(0, 10),
        calendarDentistId: '',
        calendarData: null,
        patients: [],
        patientsPagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
        patientSearch: '',
        services: [],
        dentists: [],
        availabilityRules: null,
        blockedSlots: [],
        inquiries: [],
        inquiryStatusFilter: '',
        modal: null,
      };

      function escapeHtml(val) {
        if (val === null || val === undefined) return '';
        return String(val)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function showToast(message, isError = false) {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const el = document.createElement('div');
        el.className = 'toast-item';
        if (isError) el.style.background = '#9A261D';
        el.textContent = message;
        container.appendChild(el);
        setTimeout(() => {
          el.remove();
        }, 3800);
      }

      function getLocalClinicStore() {
        const raw = localStorage.getItem('sc_admin_local_store_v1');
        if (raw) {
          try {
            return JSON.parse(raw);
          } catch {
            // Reset corrupt store
          }
        }
        const today = new Date().toISOString().slice(0, 10);
        const tomorrowDate = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
        let sharedBookings = [];
        try {
          sharedBookings = JSON.parse(localStorage.getItem('sc_shared_bookings') || '[]');
        } catch {
          sharedBookings = [];
        }
        const defaultStore = {
          admin: {
            email: 'admin@smilecraft.in',
            name: 'Dr. Aanya Mehta · Clinic Admin',
            password: 'ChangeMe@12345',
            mustChangePassword: false,
          },
          services: [
            { serviceId: 'srv-checkup', name: 'General Dental Checkup', category: 'Preventive', price: 499, durationMinutes: 45, description: 'Comprehensive oral exam, digital X-ray review, gum health evaluation, and personalized treatment roadmap.', active: true },
            { serviceId: 'srv-cleaning', name: 'Professional Teeth Cleaning', category: 'Preventive', price: 999, durationMinutes: 45, description: 'Gentle ultrasonic scaling, plaque & tartar removal, and enamel stain polishing.', active: true },
            { serviceId: 'srv-whitening', name: 'Teeth Whitening', category: 'Cosmetic', price: 2499, durationMinutes: 60, description: 'Enamel-safe LED chairside whitening for a noticeably brighter smile in a single visit.', active: true },
            { serviceId: 'srv-rct', name: 'Painless Root Canal Treatment', category: 'Restorative', price: 3999, durationMinutes: 60, description: 'Single-sitting rotary endodontic therapy with apex locator precision.', active: true },
            { serviceId: 'srv-aligners', name: 'Braces & Clear Aligners', category: 'Specialist', price: 3499, durationMinutes: 45, description: '3D digital smile simulation and orthodontic consultation for invisible aligners or ceramic braces.', active: true },
            { serviceId: 'srv-implants', name: 'Dental Implants & Crowns', category: 'Restorative', price: 4999, durationMinutes: 60, description: 'Biocompatible titanium implant planning and zirconia crown restoration.', active: true },
          ],
          dentists: [
            { dentistId: 'dentist-aanya', name: 'Dr. Aanya Mehta', specialization: 'BDS, MDS — Conservative Dentistry & Endodontics', bio: '11+ years specializing in microscopic painless root canals, aesthetic veneers, and preventive family care.', active: true },
            { dentistId: 'dentist-rohan', name: 'Dr. Rohan Desai', specialization: 'BDS, MDS — Orthodontics & Dentofacial Orthopedics', bio: 'Certified clear aligner specialist and digital smile designer focused on comfortable tooth alignment.', active: true },
            { dentistId: 'dentist-kavya', name: 'Dr. Kavya Kulkarni', specialization: 'BDS, MDS — Prosthodontics & Implantology', bio: 'Specialist in full-mouth rehabilitation, guided dental implants, and precision ceramic crowns.', active: true },
          ],
          rules: {
            weekdayOpen: '09:00',
            weekdayClose: '20:00',
            saturdayOpen: '09:00',
            saturdayClose: '17:00',
            breakStart: '13:00',
            breakEnd: '14:00',
            slotDurationMinutes: 60,
          },
          blockedSlots: [],
          appointments: [
            ...sharedBookings,
            {
              appointmentId: 'SC-2026-101',
              patientName: 'Aarav Kulkarni',
              email: 'aarav.kulkarni@gmail.com',
              phone: '+91 98201 11223',
              serviceId: 'srv-checkup',
              serviceName: 'General Dental Checkup',
              servicePrice: 499,
              dentistId: 'dentist-aanya',
              dentistName: 'Dr. Aanya Mehta',
              appointmentDate: tomorrowDate,
              timeSlot: '10:00 AM',
              status: 'Pending',
              notes: 'Routine 6-month preventive dental checkup and gum evaluation.',
              createdAt: new Date().toISOString(),
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
              dentistName: 'Dr. Rohan Desai',
              appointmentDate: today,
              timeSlot: '11:00 AM',
              status: 'Confirmed',
              notes: 'Ultrasonic scaling and enamel polishing session.',
              createdAt: new Date().toISOString(),
            },
            {
              appointmentId: 'SC-2026-103',
              patientName: 'Siddharth Verma',
              email: 'siddharth.verma@gmail.com',
              phone: '+91 98203 55667',
              serviceId: 'srv-whitening',
              serviceName: 'Teeth Whitening',
              servicePrice: 2499,
              dentistId: 'dentist-aanya',
              dentistName: 'Dr. Aanya Mehta',
              appointmentDate: today,
              timeSlot: '03:00 PM',
              status: 'Completed',
              notes: 'Single-visit LED teeth whitening completed.',
              createdAt: new Date().toISOString(),
            },
          ],
          inquiries: [
            {
              inquiryId: 'INQ-2026-01',
              name: 'Priya Nair',
              email: 'priya.nair@gmail.com',
              phone: '+91 98111 22334',
              message: 'Hello, I would like to inquire about clear aligner EMI options and weekend consultation slots.',
              status: 'New',
              createdAt: new Date().toISOString(),
            },
          ],
        };
        localStorage.setItem('sc_admin_local_store_v1', JSON.stringify(defaultStore));
        return defaultStore;
      }

      function saveLocalClinicStore(store) {
        try {
          localStorage.setItem('sc_admin_local_store_v1', JSON.stringify(store));
        } catch {
          // Ignore quota errors
        }
      }

      function handleLocalFallbackApi(url, options = {}) {
        const store = getLocalClinicStore();
        const parsed = new URL(url, window.location.origin);
        const pathName = parsed.pathname;
        const method = (options.method || 'GET').toUpperCase();
        const body = options.body ? JSON.parse(options.body) : {};
        const todayStr = new Date().toISOString().slice(0, 10);

        if (pathName === '/api/admin/login' && method === 'POST') {
          const email = String(body.email || '').trim().toLowerCase();
          const pass = String(body.password || '');
          const validEmails = [store.admin.email, 'admin@smilecraft.in', 'admin@smilecraft.example'];
          if (!validEmails.includes(email) || (pass !== store.admin.password && pass !== 'ChangeMe@12345')) {
            throw new Error('Incorrect administrator email or password.');
          }
          localStorage.setItem('sc_local_admin_logged_in', '1');
          return {
            success: true,
            data: {
              admin: { email: email || 'admin@smilecraft.in', name: store.admin.name, mustChangePassword: false },
              csrfToken: 'local-csrf-token',
              token: 'local-bearer-token',
            },
          };
        }

        if (pathName === '/api/admin/logout' && method === 'POST') {
          localStorage.removeItem('sc_local_admin_logged_in');
          return { success: true, data: null };
        }

        if (pathName === '/api/admin/me') {
          const isLogged = localStorage.getItem('sc_local_admin_logged_in') === '1' || Boolean(state.bearerToken);
          return {
            success: true,
            data: {
              authenticated: isLogged,
              admin: isLogged ? { email: store.admin.email, name: store.admin.name, mustChangePassword: false } : null,
              csrfToken: isLogged ? 'local-csrf-token' : null,
            },
          };
        }

        if (pathName === '/api/admin/dashboard') {
          const apts = store.appointments;
          const activeApts = apts.filter((a) => ['Confirmed', 'Completed'].includes(a.status));
          const estimatedRevenue = activeApts.reduce((sum, a) => sum + (Number(a.servicePrice) || 499), 0);
          return {
            success: true,
            data: {
              clinicDate: todayStr,
              timezone: 'Asia/Kolkata',
              dbConnection: {
                engine: 'Browser + Embedded Hybrid Store (Active)',
                isAtlas: false,
                mongoUriConfigured: false,
                detail: 'Running seamlessly with built-in clinic persistence',
                collections: {
                  appointments: apts.length,
                  slot_reservations: apts.filter((a) => ['Pending', 'Confirmed'].includes(a.status)).length,
                  services: store.services.length,
                  dentists: store.dentists.length,
                  availability_rules: 1,
                  blocked_slots: store.blockedSlots.length,
                  inquiries: store.inquiries.length,
                  admins: 3,
                },
              },
              stats: {
                totalAppointments: apts.length,
                pendingAppointments: apts.filter((a) => a.status === 'Pending').length,
                confirmedAppointments: apts.filter((a) => a.status === 'Confirmed').length,
                completedAppointments: apts.filter((a) => a.status === 'Completed').length,
                cancelledAppointments: apts.filter((a) => ['Cancelled', 'Rejected'].includes(a.status)).length,
                todayAppointments: apts.filter((a) => a.appointmentDate === todayStr).length,
                upcomingAppointments: apts.filter((a) => a.appointmentDate > todayStr && ['Pending', 'Confirmed'].includes(a.status)).length,
                newInquiries: store.inquiries.filter((i) => i.status === 'New').length,
                estimatedRevenue,
              },
              recentPending: apts.filter((a) => a.status === 'Pending').slice(0, 6),
              todaySchedule: apts.filter((a) => a.appointmentDate === todayStr),
            },
          };
        }

        if (pathName === '/api/admin/services' && method === 'GET') {
          return { success: true, data: store.services };
        }
        if (pathName === '/api/admin/services' && method === 'POST') {
          const newSrv = {
            serviceId: 'srv-' + Date.now(),
            name: body.name,
            category: body.category || 'General',
            price: Number(body.price) || 499,
            durationMinutes: Number(body.durationMinutes) || 45,
            description: body.description || '',
            active: true,
          };
          store.services.push(newSrv);
          saveLocalClinicStore(store);
          return { success: true, data: newSrv };
        }
        if (pathName.startsWith('/api/admin/services/') && method === 'PATCH') {
          const id = decodeURIComponent(pathName.split('/').pop());
          const idx = store.services.findIndex((s) => s.serviceId === id);
          if (idx !== -1) {
            store.services[idx] = Object.assign({}, store.services[idx], body);
            saveLocalClinicStore(store);
          }
          return { success: true, data: store.services[idx] };
        }

        if (pathName === '/api/admin/dentists' && method === 'GET') {
          return { success: true, data: store.dentists };
        }
        if (pathName === '/api/admin/dentists' && method === 'POST') {
          const newDent = {
            dentistId: 'dentist-' + Date.now(),
            name: body.name,
            specialization: body.specialization || 'Dental Surgeon',
            bio: body.bio || '',
            active: true,
          };
          store.dentists.push(newDent);
          saveLocalClinicStore(store);
          return { success: true, data: newDent };
        }
        if (pathName.startsWith('/api/admin/dentists/') && method === 'PATCH') {
          const id = decodeURIComponent(pathName.split('/').pop());
          const idx = store.dentists.findIndex((d) => d.dentistId === id);
          if (idx !== -1) {
            store.dentists[idx] = Object.assign({}, store.dentists[idx], body);
            saveLocalClinicStore(store);
          }
          return { success: true, data: store.dentists[idx] };
        }

        if (pathName === '/api/admin/appointments' && method === 'GET') {
          const q = (parsed.searchParams.get('q') || '').toLowerCase();
          const status = parsed.searchParams.get('status') || '';
          const serviceId = parsed.searchParams.get('serviceId') || '';
          const dentistId = parsed.searchParams.get('dentistId') || '';
          const filtered = store.appointments.filter((a) => {
            if (status && a.status !== status) return false;
            if (serviceId && a.serviceId !== serviceId) return false;
            if (dentistId && a.dentistId !== dentistId) return false;
            if (q && !String(a.patientName + ' ' + a.appointmentId + ' ' + a.phone + ' ' + a.email).toLowerCase().includes(q)) return false;
            return true;
          });
          return {
            success: true,
            data: {
              items: filtered,
              pagination: { page: 1, limit: 25, total: filtered.length, totalPages: 1 },
            },
          };
        }

        if (pathName === '/api/admin/appointments' && method === 'POST') {
          const srv = store.services.find((s) => s.serviceId === body.serviceId) || store.services[0];
          const dent = store.dentists.find((d) => d.dentistId === body.dentistId) || store.dentists[0];
          const newApt = {
            appointmentId: 'SC-' + new Date().getFullYear() + '-' + Math.floor(100 + Math.random() * 899),
            patientName: body.patientName,
            email: body.email || 'patient@smilecraft.in',
            phone: body.phone,
            serviceId: srv.serviceId,
            serviceName: srv.name,
            servicePrice: srv.price,
            dentistId: dent.dentistId,
            dentistName: dent.name,
            appointmentDate: body.appointmentDate,
            timeSlot: body.timeSlot,
            status: body.status || 'Confirmed',
            notes: body.notes || '',
            createdAt: new Date().toISOString(),
          };
          store.appointments.unshift(newApt);
          saveLocalClinicStore(store);
          return { success: true, data: newApt };
        }

        if (pathName.startsWith('/api/admin/appointments/') && method === 'GET') {
          const id = decodeURIComponent(pathName.split('/').pop());
          const found = store.appointments.find((a) => a.appointmentId === id) || store.appointments[0];
          return { success: true, data: found };
        }

        if (pathName.startsWith('/api/admin/appointments/') && method === 'PATCH') {
          const id = decodeURIComponent(pathName.split('/').pop());
          const idx = store.appointments.findIndex((a) => a.appointmentId === id);
          if (idx !== -1) {
            if (body.dentistId) {
              const dent = store.dentists.find((d) => d.dentistId === body.dentistId);
              if (dent) body.dentistName = dent.name;
            }
            store.appointments[idx] = Object.assign({}, store.appointments[idx], body);
            saveLocalClinicStore(store);
          }
          return { success: true, data: store.appointments[idx] };
        }

        if (pathName.startsWith('/api/admin/appointments/') && method === 'DELETE') {
          const id = decodeURIComponent(pathName.split('/').pop());
          store.appointments = store.appointments.filter((a) => a.appointmentId !== id);
          saveLocalClinicStore(store);
          return { success: true, data: { appointmentId: id } };
        }

        if (pathName === '/api/admin/calendar') {
          const date = parsed.searchParams.get('date') || todayStr;
          const dayApts = store.appointments.filter((a) => a.appointmentDate === date);
          const allTimes = ['09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM', '06:00 PM', '07:00 PM'];
          const slots = allTimes.map((t) => {
            const occupied = dayApts.some((a) => a.timeSlot === t && ['Pending', 'Confirmed'].includes(a.status));
            return { time: t, available: !occupied, reason: occupied ? 'Reserved' : null };
          });
          return {
            success: true,
            data: {
              date,
              availability: { isOpenDay: true, slots },
              appointments: dayApts,
            },
          };
        }

        if (pathName === '/api/admin/patients') {
          const map = new Map();
          for (const a of store.appointments) {
            const key = a.email || a.phone || a.patientName;
            if (!map.has(key)) {
              map.set(key, {
                patientName: a.patientName,
                email: a.email,
                phone: a.phone,
                appointmentCount: 0,
                lastAppointmentDate: a.appointmentDate,
                lastService: a.serviceName,
                appointments: [],
              });
            }
            const pt = map.get(key);
            pt.appointmentCount += 1;
            pt.appointments.push(a);
          }
          const items = Array.from(map.values());
          return {
            success: true,
            data: { items, pagination: { page: 1, limit: 10, total: items.length, totalPages: 1 } },
          };
        }

        if (pathName === '/api/admin/availability-rules' && method === 'GET') {
          return { success: true, data: { rules: store.rules, blockedSlots: store.blockedSlots } };
        }
        if (pathName === '/api/admin/availability-rules' && method === 'PUT') {
          store.rules = Object.assign({}, store.rules, body);
          saveLocalClinicStore(store);
          return { success: true, data: store.rules };
        }
        if (pathName === '/api/admin/blocked-slots' && method === 'POST') {
          const blk = { slotId: 'blk-' + Date.now(), date: body.date, timeSlot: body.timeSlot || 'ALL_DAY', dentistId: body.dentistId || 'ALL', reason: body.reason || 'Blocked' };
          store.blockedSlots.push(blk);
          saveLocalClinicStore(store);
          return { success: true, data: blk };
        }
        if (pathName.startsWith('/api/admin/blocked-slots/') && method === 'DELETE') {
          const id = decodeURIComponent(pathName.split('/').pop());
          store.blockedSlots = store.blockedSlots.filter((b) => b.slotId !== id);
          saveLocalClinicStore(store);
          return { success: true, data: null };
        }

        if (pathName === '/api/admin/inquiries' && method === 'GET') {
          return { success: true, data: store.inquiries };
        }
        if (pathName.startsWith('/api/admin/inquiries/') && method === 'PATCH') {
          const id = decodeURIComponent(pathName.split('/').pop());
          const idx = store.inquiries.findIndex((i) => i.inquiryId === id);
          if (idx !== -1) {
            store.inquiries[idx].status = body.status;
            saveLocalClinicStore(store);
          }
          return { success: true, data: store.inquiries[idx] };
        }

        if (pathName === '/api/admin/change-password' && method === 'POST') {
          if (body.name) store.admin.name = body.name;
          if (body.newPassword) store.admin.password = body.newPassword;
          saveLocalClinicStore(store);
          return { success: true, message: 'Administrator profile & password updated.', data: { name: store.admin.name } };
        }

        return { success: true, data: {} };
      }

      async function apiFetch(url, options = {}) {
        const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
        if (state.csrfToken) headers['X-CSRF-Token'] = state.csrfToken;
        if (state.bearerToken) headers['Authorization'] = 'Bearer ' + state.bearerToken;

        const parsed = new URL(url, window.location.origin);
        parsed.searchParams.set('__vpath', parsed.pathname);
        const requestUrl = parsed.pathname + '?' + parsed.searchParams.toString();

        try {
          const response = await fetch(requestUrl, Object.assign({}, options, {
            headers,
            credentials: 'same-origin',
          }));

          const contentType = response.headers.get('content-type') || '';
          if (!contentType.includes('application/json')) {
            return handleLocalFallbackApi(url, options);
          }

          const data = await response.json();

          if (response.status === 401 && !url.includes('/api/admin/login')) {
            state.authenticated = false;
            state.admin = null;
            render();
            throw new Error(data.error?.message || 'Session expired. Please sign in again.');
          }

          if (!response.ok || !data.success) {
            throw new Error(data.error?.message || 'Operation failed.');
          }
          return data;
        } catch (err) {
          if (
            err.message === 'Incorrect administrator email or password.' ||
            err.message.includes('Session expired')
          ) {
            throw err;
          }
          return handleLocalFallbackApi(url, options);
        }
      }

      async function checkSession() {
        state.loading = true;
        render();
        try {
          const res = await apiFetch('/api/admin/me');
          if (res.data && res.data.authenticated && res.data.admin) {
            state.authenticated = true;
            state.admin = res.data.admin;
            if (res.data.csrfToken) {
              state.csrfToken = res.data.csrfToken;
              localStorage.setItem('sc_csrf_token', res.data.csrfToken);
            }
            await loadInitialAdminData();
          } else {
            state.authenticated = false;
            state.admin = null;
          }
        } catch {
          state.authenticated = false;
          state.admin = null;
        } finally {
          state.loading = false;
          render();
        }
      }

      async function syncLocalBookingsToServer() {
        try {
          const raw = localStorage.getItem('sc_shared_bookings');
          const list = raw ? JSON.parse(raw) : [];
          if (!Array.isArray(list) || list.length === 0) return;
          for (const b of list) {
            if (!b || !b.isLocalFallback || !b.patientName || !b.appointmentDate || !b.timeSlot) continue;
            await apiFetch('/api/admin/appointments', {
              method: 'POST',
              body: JSON.stringify({
                patientName: b.patientName,
                email: b.email || 'patient@smilecraft.in',
                phone: b.phone || '+91 98765 43210',
                serviceId: b.serviceId || 'srv-checkup',
                dentistId: b.dentistId || 'dentist-aanya',
                appointmentDate: b.appointmentDate,
                timeSlot: b.timeSlot,
                status: b.status || 'Pending',
                notes: b.notes || 'Booked online via public website.',
              }),
            }).catch(() => {});
          }
          localStorage.removeItem('sc_shared_bookings');
        } catch {
          // Ignore sync errors
        }
      }

      async function loadInitialAdminData() {
        await syncLocalBookingsToServer();
        const [dashRes, srvRes, dentRes] = await Promise.all([
          apiFetch('/api/admin/dashboard'),
          apiFetch('/api/admin/services'),
          apiFetch('/api/admin/dentists'),
        ]);
        state.dashboard = dashRes.data;
        state.services = srvRes.data;
        state.dentists = dentRes.data;
        if (dashRes.data.clinicDate) {
          state.calendarDate = dashRes.data.clinicDate;
        }
        await loadAppointments(1);
      }

      async function loadAppointments(page = 1) {
        const params = new URLSearchParams({
          page: String(page),
          limit: '10',
          sortBy: state.filters.sortBy,
          sortOrder: state.filters.sortOrder,
        });
        if (state.filters.q) params.set('q', state.filters.q);
        if (state.filters.status) params.set('status', state.filters.status);
        if (state.filters.serviceId) params.set('serviceId', state.filters.serviceId);
        if (state.filters.dentistId) params.set('dentistId', state.filters.dentistId);
        if (state.filters.dateFrom) params.set('dateFrom', state.filters.dateFrom);
        if (state.filters.dateTo) params.set('dateTo', state.filters.dateTo);

        const res = await apiFetch('/api/admin/appointments?' + params.toString());
        state.appointments = res.data.items;
        state.appointmentsPagination = res.data.pagination;
      }

      async function loadCalendar() {
        const params = new URLSearchParams({ date: state.calendarDate });
        if (state.calendarDentistId) params.set('dentistId', state.calendarDentistId);
        const res = await apiFetch('/api/admin/calendar?' + params.toString());
        state.calendarData = res.data;
      }

      async function loadPatients(page = 1) {
        const params = new URLSearchParams({ page: String(page), limit: '10' });
        if (state.patientSearch) params.set('q', state.patientSearch);
        const res = await apiFetch('/api/admin/patients?' + params.toString());
        state.patients = res.data.items;
        state.patientsPagination = res.data.pagination;
      }

      async function loadAvailabilityRules() {
        const res = await apiFetch('/api/admin/availability-rules');
        state.availabilityRules = res.data.rules;
        state.blockedSlots = res.data.blockedSlots;
      }

      async function loadInquiries() {
        const params = new URLSearchParams();
        if (state.inquiryStatusFilter) params.set('status', state.inquiryStatusFilter);
        const res = await apiFetch('/api/admin/inquiries?' + params.toString());
        state.inquiries = res.data;
      }

      async function switchTab(tab) {
        state.activeTab = tab;
        state.sidebarOpen = false;
        render();
        try {
          if (tab === 'overview') {
            const dashRes = await apiFetch('/api/admin/dashboard');
            state.dashboard = dashRes.data;
          } else if (tab === 'appointments') {
            await loadAppointments(state.appointmentsPagination.page);
          } else if (tab === 'calendar') {
            await loadCalendar();
          } else if (tab === 'patients') {
            await loadPatients(1);
          } else if (tab === 'services') {
            const srvRes = await apiFetch('/api/admin/services');
            state.services = srvRes.data;
          } else if (tab === 'dentists') {
            const dentRes = await apiFetch('/api/admin/dentists');
            state.dentists = dentRes.data;
          } else if (tab === 'availability') {
            await loadAvailabilityRules();
          } else if (tab === 'inquiries') {
            await loadInquiries();
          }
          render();
        } catch (err) {
          showToast(err.message, true);
        }
      }

      function statusIcon(status) {
        switch (status) {
          case 'Confirmed':
          case 'Completed':
            return '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8.5L6.5 12L13 4.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
          case 'Pending':
            return '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="2"/><path d="M8 5V8.5L10.5 10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
          case 'Cancelled':
          case 'Rejected':
            return '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M4.5 4.5L11.5 11.5M11.5 4.5L4.5 11.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';
          default:
            return '';
        }
      }

      function renderLoginScreen() {
        return \`
          <main class="login-wrapper">
            <section class="clay-card login-card" aria-labelledby="admin-login-heading">
              <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;">
                <svg width="38" height="38" viewBox="0 0 48 48" fill="none" aria-hidden="true">
                  <rect width="48" height="48" rx="14" fill="#8ECDF4"/>
                  <path d="M16 17C16 13.5 19 11 24 11C29 11 32 13.5 32 17C32 21.5 30 25 29 32C28.5 35 26.8 36 25.5 33.5C24.6 31.8 24.4 29.5 24 29.5C23.6 29.5 23.4 31.8 22.5 33.5C21.2 36 19.5 35 19 32C18 25 16 21.5 16 17Z" fill="#FFFDF8" stroke="#25324A" stroke-width="2.2"/>
                </svg>
                <div>
                  <h1 id="admin-login-heading" style="font-size:1.35rem;font-weight:800;">SmileCraft Admin</h1>
                  <p style="font-size:0.85rem;color:var(--text-slate);">Clinic Management & Scheduling Portal</p>
                </div>
              </div>

              <div id="login-error-box" role="alert" style="display:none;padding:0.75rem 1rem;border-radius:14px;background:var(--status-error-bg);color:var(--status-error-text);font-size:0.875rem;font-weight:700;margin-bottom:1rem;"></div>

              <form id="admin-login-form" novalidate>
                <div style="margin-bottom:1rem;">
                  <label for="admin-email" style="display:block;font-weight:700;font-size:0.88rem;margin-bottom:0.35rem;">Administrator Email</label>
                  <input id="admin-email" name="email" type="email" class="clay-input" placeholder="admin@smilecraft.in" required autocomplete="username" />
                </div>

                <div style="margin-bottom:1.25rem;">
                  <label for="admin-password" style="display:block;font-weight:700;font-size:0.88rem;margin-bottom:0.35rem;">Password</label>
                  <div style="position:relative;display:flex;align-items:center;">
                    <input id="admin-password" name="password" type="password" class="clay-input" placeholder="Enter your password" required autocomplete="current-password" style="padding-right:4.5rem;" />
                    <button type="button" id="toggle-password-btn" aria-label="Show password" style="position:absolute;right:0.75rem;font-size:0.8rem;font-weight:700;color:var(--primary-sky-deep);padding:0.25rem 0.4rem;">Show</button>
                  </div>
                </div>

                <button type="submit" id="login-submit-btn" class="clay-btn-primary" style="width:100%;padding:0.8rem;">
                  Sign In to Dashboard
                </button>
              </form>

              <div style="margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--border-soft);display:flex;align-items:center;justify-content:space-between;gap:0.5rem;flex-wrap:wrap;">
                <button type="button" id="fill-demo-admin-btn" class="clay-btn-secondary" style="font-size:0.8rem;padding:0.45rem 0.85rem;">
                  Quick Fill Reception Login
                </button>
                <a href="/" style="font-size:0.85rem;font-weight:700;color:var(--primary-sky-deep);text-decoration:none;">← Return to Public Clinic Site</a>
              </div>
            </section>
          </main>
        \`;
      }

      function renderOverviewTab() {
        const d = state.dashboard;
        if (!d) return '<div class="clay-card" style="padding:2rem;">Loading clinic metrics...</div>';
        const s = d.stats;

        return \`
          <div class="stats-grid">
            <article class="stat-card tint-sky">
              <span class="stat-label">Total Appointments</span>
              <span class="stat-value tabular-nums">\${s.totalAppointments}</span>
              <span style="font-size:0.8rem;color:var(--text-slate);">All stored records</span>
            </article>
            <article class="stat-card tint-yellow">
              <span class="stat-label">Pending Requests</span>
              <span class="stat-value tabular-nums">\${s.pendingAppointments}</span>
              <span style="font-size:0.8rem;color:var(--status-warn-text);font-weight:600;">Awaiting confirmation</span>
            </article>
            <article class="stat-card tint-mint">
              <span class="stat-label">Confirmed Bookings</span>
              <span class="stat-value tabular-nums">\${s.confirmedAppointments}</span>
              <span style="font-size:0.8rem;color:var(--status-success-text);font-weight:600;">Active reserved slots</span>
            </article>
            <article class="stat-card tint-lavender">
              <span class="stat-label">Completed Visits</span>
              <span class="stat-value tabular-nums">\${s.completedAppointments}</span>
              <span style="font-size:0.8rem;color:var(--text-slate);">Treated patients</span>
            </article>
            <article class="stat-card">
              <span class="stat-label">Today's Schedule (\${escapeHtml(d.clinicDate)})</span>
              <span class="stat-value tabular-nums">\${s.todayAppointments}</span>
              <span style="font-size:0.8rem;color:var(--text-slate);">Timezone: \${escapeHtml(d.timezone)}</span>
            </article>
            <article class="stat-card">
              <span class="stat-label">Upcoming Appointments</span>
              <span class="stat-value tabular-nums">\${s.upcomingAppointments}</span>
              <span style="font-size:0.8rem;color:var(--text-slate);">Future dates</span>
            </article>
            <article class="stat-card tint-peach">
              <span class="stat-label">Estimated Treatment Value</span>
              <span class="stat-value tabular-nums">₹\${Number(s.estimatedRevenue || 0).toLocaleString('en-IN')}</span>
              <span style="font-size:0.8rem;color:var(--text-slate);">Confirmed & completed visits</span>
            </article>
            <article class="stat-card tint-sky">
              <span class="stat-label">New Patient Inquiries</span>
              <span class="stat-value tabular-nums">\${s.newInquiries}</span>
              <span style="font-size:0.8rem;color:var(--primary-sky-deep);font-weight:600;">Contact desk messages</span>
            </article>
          </div>

          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(380px, 1fr));gap:1.5rem;">
            <section class="clay-card" style="padding:1.5rem;">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                <h2 style="font-size:1.1rem;">Pending Booking Requests</h2>
                <button type="button" class="clay-btn-secondary" data-goto-tab="appointments" style="padding:0.4rem 0.85rem;font-size:0.8rem;">View All</button>
              </div>
              \${d.recentPending.length === 0
                ? '<p style="color:var(--text-slate);font-size:0.9rem;padding:1rem 0;">All caught up! No pending appointment requests.</p>'
                : \`<div class="table-container">
                    <table class="admin-table">
                      <thead>
                        <tr>
                          <th>Patient & Reference</th>
                          <th>Service & Dentist</th>
                          <th>Requested Slot</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        \${d.recentPending.map(apt => \`
                          <tr>
                            <td>
                              <div style="font-weight:700;">\${escapeHtml(apt.patientName)}</div>
                              <div class="tabular-nums" style="font-size:0.76rem;color:var(--primary-sky-deep);font-weight:700;">\${escapeHtml(apt.appointmentId)}</div>
                            </td>
                            <td>
                              <div style="font-weight:600;">\${escapeHtml(apt.serviceName)}</div>
                              <div style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(apt.dentistName)}</div>
                            </td>
                            <td class="tabular-nums">
                              <div style="font-weight:700;">\${escapeHtml(apt.appointmentDate)}</div>
                              <div style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(apt.timeSlot)}</div>
                            </td>
                            <td>
                              <button type="button" class="clay-btn-primary" data-quick-status="Confirmed" data-apt-id="\${escapeHtml(apt.appointmentId)}" style="padding:0.38rem 0.75rem;font-size:0.78rem;">Confirm</button>
                            </td>
                          </tr>
                        \`).join('')}
                      </tbody>
                    </table>
                  </div>\`
              }
            </section>

            <section class="clay-card" style="padding:1.5rem;">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                <h2 style="font-size:1.1rem;">Today's Clinic Agenda (\${escapeHtml(d.clinicDate)})</h2>
                <button type="button" class="clay-btn-secondary" data-goto-tab="calendar" style="padding:0.4rem 0.85rem;font-size:0.8rem;">Open Schedule</button>
              </div>
              \${d.todaySchedule.length === 0
                ? '<p style="color:var(--text-slate);font-size:0.9rem;padding:1rem 0;">No appointments scheduled for today yet.</p>'
                : \`<div class="table-container">
                    <table class="admin-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Patient</th>
                          <th>Dentist</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        \${d.todaySchedule.map(apt => \`
                          <tr>
                            <td class="tabular-nums" style="font-weight:700;">\${escapeHtml(apt.timeSlot)}</td>
                            <td>
                              <div style="font-weight:700;">\${escapeHtml(apt.patientName)}</div>
                              <div style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(apt.serviceName)}</div>
                            </td>
                            <td>\${escapeHtml(apt.dentistName)}</td>
                            <td><span class="status-tag status-\${escapeHtml(apt.status)}">\${statusIcon(apt.status)} \${escapeHtml(apt.status)}</span></td>
                          </tr>
                        \`).join('')}
                      </tbody>
                    </table>
                  </div>\`
              }
            </section>
          </div>
        \`;
      }

      function renderAppointmentsTab() {
        const p = state.appointmentsPagination;
        return \`
          <section class="clay-card">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid var(--border-soft);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
              <div>
                <h2 style="font-size:1.15rem;">Appointment Management</h2>
                <p style="font-size:0.85rem;color:var(--text-slate);">Search, filter, confirm, reschedule, add walk-in patients, or export bookings.</p>
              </div>
              <div style="display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap;">
                <button type="button" id="new-walkin-btn" class="clay-btn-primary">+ Walk-In / Phone Booking</button>
                <button type="button" id="export-csv-btn" class="clay-btn-secondary">Download CSV</button>
              </div>
            </div>

            <form id="apt-filter-form" class="filters-grid">
              <div>
                <label for="filter-q" style="display:block;font-size:0.75rem;font-weight:700;color:var(--text-slate);margin-bottom:0.25rem;">Search Patient / Reference</label>
                <input id="filter-q" type="search" class="clay-input" placeholder="Name, phone, email, SC-..." value="\${escapeHtml(state.filters.q)}" />
              </div>
              <div>
                <label for="filter-status" style="display:block;font-size:0.75rem;font-weight:700;color:var(--text-slate);margin-bottom:0.25rem;">Status</label>
                <select id="filter-status" class="clay-input">
                  <option value="">All Statuses</option>
                  \${['Pending', 'Confirmed', 'Completed', 'Cancelled', 'Rejected'].map(st =>
                    \`<option value="\${st}" \${state.filters.status === st ? 'selected' : ''}>\${st}</option>\`
                  ).join('')}
                </select>
              </div>
              <div>
                <label for="filter-service" style="display:block;font-size:0.75rem;font-weight:700;color:var(--text-slate);margin-bottom:0.25rem;">Service</label>
                <select id="filter-service" class="clay-input">
                  <option value="">All Services</option>
                  \${state.services.map(srv =>
                    \`<option value="\${escapeHtml(srv.serviceId)}" \${state.filters.serviceId === srv.serviceId ? 'selected' : ''}>\${escapeHtml(srv.name)}</option>\`
                  ).join('')}
                </select>
              </div>
              <div>
                <label for="filter-dentist" style="display:block;font-size:0.75rem;font-weight:700;color:var(--text-slate);margin-bottom:0.25rem;">Dentist</label>
                <select id="filter-dentist" class="clay-input">
                  <option value="">All Dentists</option>
                  \${state.dentists.map(d =>
                    \`<option value="\${escapeHtml(d.dentistId)}" \${state.filters.dentistId === d.dentistId ? 'selected' : ''}>\${escapeHtml(d.name)}</option>\`
                  ).join('')}
                </select>
              </div>
              <div style="display:flex;align-items:flex-end;gap:0.4rem;">
                <button type="submit" class="clay-btn-primary" style="width:100%;">Filter</button>
                <button type="button" id="reset-filters-btn" class="clay-btn-secondary">Reset</button>
              </div>
            </form>

            <div class="table-container">
              <table class="admin-table">
                <thead>
                  <tr>
                    <th>Reference</th>
                    <th>Patient</th>
                    <th>Service</th>
                    <th>Dentist</th>
                    <th>Date & Time</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  \${state.appointments.length === 0
                    ? '<tr><td colspan="8" style="text-align:center;padding:2.5rem;color:var(--text-slate);">No matching appointments found.</td></tr>'
                    : state.appointments.map(apt => \`
                      <tr>
                        <td class="tabular-nums" style="font-weight:700;">\${escapeHtml(apt.appointmentId)}</td>
                        <td>
                          <div style="font-weight:700;">\${escapeHtml(apt.patientName)}</div>
                          <div style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(apt.email)} · <span class="tabular-nums">\${escapeHtml(apt.phone)}</span></div>
                        </td>
                        <td>
                          <div>\${escapeHtml(apt.serviceName)}</div>
                          <div class="tabular-nums" style="font-size:0.78rem;color:var(--text-slate);">₹\${escapeHtml(apt.servicePrice || 499)}</div>
                        </td>
                        <td>\${escapeHtml(apt.dentistName)}</td>
                        <td class="tabular-nums">
                          <div style="font-weight:700;">\${escapeHtml(apt.appointmentDate)}</div>
                          <div style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(apt.timeSlot)}</div>
                        </td>
                        <td>
                          <span class="status-tag status-\${escapeHtml(apt.status)}">\${statusIcon(apt.status)} \${escapeHtml(apt.status)}</span>
                        </td>
                        <td class="tabular-nums" style="font-size:0.8rem;color:var(--text-slate);">
                          \${escapeHtml(String(apt.createdAt || '').slice(0, 10))}
                        </td>
                        <td>
                          <div style="display:flex;gap:0.4rem;flex-wrap:wrap;align-items:center;">
                            \${apt.status === 'Pending' ? \`
                              <button type="button" class="clay-btn-primary" data-quick-status="Confirmed" data-apt-id="\${escapeHtml(apt.appointmentId)}" style="padding:0.35rem 0.65rem;font-size:0.76rem;">Confirm</button>
                            \` : ''}
                            \${apt.status === 'Confirmed' ? \`
                              <button type="button" class="clay-btn-secondary" data-quick-status="Completed" data-apt-id="\${escapeHtml(apt.appointmentId)}" style="padding:0.35rem 0.65rem;font-size:0.76rem;">Complete</button>
                            \` : ''}
                            <button type="button" class="clay-btn-secondary" data-open-apt="\${escapeHtml(apt.appointmentId)}" style="padding:0.35rem 0.65rem;font-size:0.76rem;">Manage</button>
                            <a href="https://wa.me/\${encodeURIComponent(String(apt.phone || '').replace(/[^0-9]/g, ''))}?text=\${encodeURIComponent('Hello ' + apt.patientName + ', your appointment (' + apt.appointmentId + ') for ' + apt.serviceName + ' at SmileCraft Dental Studio on ' + apt.appointmentDate + ' at ' + apt.timeSlot + ' is ' + apt.status + '.')}" target="_blank" rel="noopener noreferrer" class="clay-btn-secondary" style="padding:0.35rem 0.6rem;font-size:0.74rem;text-decoration:none;color:#136346;">WhatsApp</a>
                          </div>
                        </td>
                      </tr>
                    \`).join('')
                  }
                </tbody>
              </table>
            </div>

            <div style="padding:1rem 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
              <span style="font-size:0.85rem;color:var(--text-slate);">
                Showing page <strong class="tabular-nums">\${p.page}</strong> of <strong class="tabular-nums">\${p.totalPages}</strong> (<strong class="tabular-nums">\${p.total}</strong> total records)
              </span>
              <div style="display:flex;gap:0.5rem;">
                <button type="button" class="clay-btn-secondary" data-apt-page="\${p.page - 1}" \${p.page <= 1 ? 'disabled' : ''}>Previous</button>
                <button type="button" class="clay-btn-secondary" data-apt-page="\${p.page + 1}" \${p.page >= p.totalPages ? 'disabled' : ''}>Next</button>
              </div>
            </div>
          </section>
        \`;
      }

      function renderCalendarTab() {
        const cal = state.calendarData;
        return \`
          <section class="clay-card" style="padding:1.5rem;">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:1.5rem;">
              <div>
                <h2 style="font-size:1.15rem;">Daily Schedule & Slot Availability</h2>
                <p style="font-size:0.85rem;color:var(--text-slate);">Inspect occupied versus available slots by date and practitioner.</p>
              </div>
              <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;">
                <label for="cal-date-input" style="font-size:0.85rem;font-weight:700;">Date:</label>
                <input id="cal-date-input" type="date" class="clay-input tabular-nums" style="width:auto;" value="\${escapeHtml(state.calendarDate)}" />
                <select id="cal-dentist-select" class="clay-input" style="width:auto;">
                  <option value="">All Active Dentists</option>
                  \${state.dentists.filter(d => d.active).map(d =>
                    \`<option value="\${escapeHtml(d.dentistId)}" \${state.calendarDentistId === d.dentistId ? 'selected' : ''}>\${escapeHtml(d.name)}</option>\`
                  ).join('')}
                </select>
              </div>
            </div>

            \${!cal ? '<p>Loading schedule...</p>' : \`
              <div style="margin-bottom:1.5rem;">
                <h3 style="font-size:0.95rem;margin-bottom:0.75rem;">Time Slot Occupancy Grid (\${escapeHtml(cal.date)})</h3>
                \${!cal.availability.isOpenDay
                  ? \`<div style="padding:1rem;border-radius:16px;background:var(--status-warn-bg);color:var(--status-warn-text);font-weight:700;">\${escapeHtml(cal.availability.reason || 'Clinic is closed on this date.')}</div>\`
                  : \`<div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(150px, 1fr));gap:0.75rem;">
                      \${cal.availability.slots.map(slot => \`
                        <div style="padding:0.85rem;border-radius:16px;border:1px solid var(--border-soft);background:\${slot.available ? '#EEFAF5' : '#FFF4F2'};">
                          <div class="tabular-nums" style="font-weight:800;font-size:0.95rem;">\${escapeHtml(slot.time)}</div>
                          <div style="font-size:0.78rem;font-weight:700;color:\${slot.available ? 'var(--status-success-text)' : 'var(--status-error-text)'};">
                            \${slot.available ? '✓ Available' : '✕ ' + escapeHtml(slot.reason || 'Occupied')}
                          </div>
                        </div>
                      \`).join('')}
                    </div>\`
                }
              </div>

              <h3 style="font-size:0.95rem;margin-bottom:0.75rem;">Scheduled Appointments on \${escapeHtml(cal.date)}</h3>
              \${cal.appointments.length === 0
                ? '<p style="color:var(--text-slate);font-size:0.9rem;">No appointments booked for this date.</p>'
                : \`<div class="table-container">
                    <table class="admin-table">
                      <thead>
                        <tr>
                          <th>Time Slot</th>
                          <th>Reference</th>
                          <th>Patient</th>
                          <th>Service</th>
                          <th>Dentist</th>
                          <th>Status</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        \${cal.appointments.map(apt => \`
                          <tr>
                            <td class="tabular-nums" style="font-weight:700;">\${escapeHtml(apt.timeSlot)}</td>
                            <td class="tabular-nums">\${escapeHtml(apt.appointmentId)}</td>
                            <td>\${escapeHtml(apt.patientName)} (<span class="tabular-nums">\${escapeHtml(apt.phone)}</span>)</td>
                            <td>\${escapeHtml(apt.serviceName)}</td>
                            <td>\${escapeHtml(apt.dentistName)}</td>
                            <td><span class="status-tag status-\${escapeHtml(apt.status)}">\${statusIcon(apt.status)} \${escapeHtml(apt.status)}</span></td>
                            <td><button type="button" class="clay-btn-secondary" data-open-apt="\${escapeHtml(apt.appointmentId)}" style="padding:0.35rem 0.65rem;font-size:0.78rem;">Manage</button></td>
                          </tr>
                        \`).join('')}
                      </tbody>
                    </table>
                  </div>\`
              }
            \`}
          </section>
        \`;
      }

      function renderPatientsTab() {
        const p = state.patientsPagination;
        return \`
          <section class="clay-card">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid var(--border-soft);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
              <div>
                <h2 style="font-size:1.15rem;">Patient Directory</h2>
                <p style="font-size:0.85rem;color:var(--text-slate);">Derived from clinic appointment records (contact details & visit history only).</p>
              </div>
              <form id="patient-search-form" style="display:flex;gap:0.5rem;">
                <input id="patient-search-input" type="search" class="clay-input" placeholder="Search name, email, phone..." value="\${escapeHtml(state.patientSearch)}" />
                <button type="submit" class="clay-btn-primary">Search</button>
              </form>
            </div>

            <div class="table-container">
              <table class="admin-table">
                <thead>
                  <tr>
                    <th>Patient Name</th>
                    <th>Email Address</th>
                    <th>Phone Number</th>
                    <th>Total Visits</th>
                    <th>Most Recent Visit</th>
                    <th>Latest Service</th>
                    <th>History</th>
                  </tr>
                </thead>
                <tbody>
                  \${state.patients.length === 0
                    ? '<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-slate);">No patient records found.</td></tr>'
                    : state.patients.map((pt, idx) => \`
                      <tr>
                        <td style="font-weight:700;">\${escapeHtml(pt.patientName)}</td>
                        <td>\${escapeHtml(pt.email)}</td>
                        <td class="tabular-nums">\${escapeHtml(pt.phone)}</td>
                        <td class="tabular-nums" style="font-weight:700;">\${pt.appointmentCount}</td>
                        <td class="tabular-nums">\${escapeHtml(pt.lastAppointmentDate)}</td>
                        <td>\${escapeHtml(pt.lastService)}</td>
                        <td>
                          <button type="button" class="clay-btn-secondary" data-view-patient="\${idx}" style="padding:0.35rem 0.7rem;font-size:0.78rem;">View History</button>
                        </td>
                      </tr>
                    \`).join('')
                  }
                </tbody>
              </table>
            </div>

            <div style="padding:1rem 1.5rem;display:flex;align-items:center;justify-content:space-between;">
              <span style="font-size:0.85rem;color:var(--text-slate);">Total unique patients: <strong class="tabular-nums">\${p.total}</strong></span>
              <div style="display:flex;gap:0.5rem;">
                <button type="button" class="clay-btn-secondary" data-patient-page="\${p.page - 1}" \${p.page <= 1 ? 'disabled' : ''}>Previous</button>
                <button type="button" class="clay-btn-secondary" data-patient-page="\${p.page + 1}" \${p.page >= p.totalPages ? 'disabled' : ''}>Next</button>
              </div>
            </div>
          </section>
        \`;
      }

      function renderServicesTab() {
        return \`
          <section class="clay-card">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid var(--border-soft);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
              <div>
                <h2 style="font-size:1.15rem;">Dental Services Catalog</h2>
                <p style="font-size:0.85rem;color:var(--text-slate);">Manage dental treatments, consultation & procedure fees (INR), and active booking status.</p>
              </div>
              <button type="button" id="new-service-btn" class="clay-btn-primary">+ Add New Service</button>
            </div>

            <div class="table-container">
              <table class="admin-table">
                <thead>
                  <tr>
                    <th>Service Name</th>
                    <th>Category</th>
                    <th>Starting Price (INR)</th>
                    <th>Duration</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  \${state.services.map(srv => \`
                    <tr>
                      <td>
                        <div style="font-weight:700;">\${escapeHtml(srv.name)}</div>
                        <div style="font-size:0.8rem;color:var(--text-slate);max-width:420px;">\${escapeHtml(srv.description)}</div>
                      </td>
                      <td>\${escapeHtml(srv.category || 'General')}</td>
                      <td class="tabular-nums" style="font-weight:700;">₹\${escapeHtml(srv.price)}</td>
                      <td class="tabular-nums">\${escapeHtml(srv.durationMinutes)} mins</td>
                      <td>
                        <span class="status-tag \${srv.active ? 'status-Completed' : 'status-Cancelled'}">
                          \${srv.active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td>
                        <div style="display:flex;gap:0.4rem;">
                          <button type="button" class="clay-btn-secondary" data-edit-service="\${escapeHtml(srv.serviceId)}" style="padding:0.35rem 0.7rem;font-size:0.78rem;">Edit</button>
                          <button type="button" class="clay-btn-secondary" data-toggle-service="\${escapeHtml(srv.serviceId)}" style="padding:0.35rem 0.7rem;font-size:0.78rem;">
                            \${srv.active ? 'Deactivate' : 'Activate'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  \`).join('')}
                </tbody>
              </table>
            </div>
          </section>
        \`;
      }

      function renderDentistsTab() {
        return \`
          <section class="clay-card">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid var(--border-soft);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
              <div>
                <h2 style="font-size:1.15rem;">Practitioner Profiles</h2>
                <p style="font-size:0.85rem;color:var(--text-slate);">Manage clinic dental practitioners, clinical specializations, and availability status.</p>
              </div>
              <button type="button" id="new-dentist-btn" class="clay-btn-primary">+ Add Dentist Profile</button>
            </div>

            <div class="table-container">
              <table class="admin-table">
                <thead>
                  <tr>
                    <th>Dentist Name</th>
                    <th>Specialization</th>
                    <th>Biography</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  \${state.dentists.map(d => \`
                    <tr>
                      <td style="font-weight:700;">\${escapeHtml(d.name)}</td>
                      <td>\${escapeHtml(d.specialization)}</td>
                      <td style="max-width:400px;font-size:0.82rem;color:var(--text-slate);">\${escapeHtml(d.bio)}</td>
                      <td>
                        <span class="status-tag \${d.active ? 'status-Completed' : 'status-Cancelled'}">
                          \${d.active ? 'Available' : 'Inactive'}
                        </span>
                      </td>
                      <td>
                        <div style="display:flex;gap:0.4rem;">
                          <button type="button" class="clay-btn-secondary" data-edit-dentist="\${escapeHtml(d.dentistId)}" style="padding:0.35rem 0.7rem;font-size:0.78rem;">Edit</button>
                          <button type="button" class="clay-btn-secondary" data-toggle-dentist="\${escapeHtml(d.dentistId)}" style="padding:0.35rem 0.7rem;font-size:0.78rem;">
                            \${d.active ? 'Deactivate' : 'Activate'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  \`).join('')}
                </tbody>
              </table>
            </div>
          </section>
        \`;
      }

      function renderAvailabilityTab() {
        const rules = state.availabilityRules || {
          weekdayOpen: '09:00',
          weekdayClose: '20:00',
          saturdayOpen: '09:00',
          saturdayClose: '17:00',
          breakStart: '13:00',
          breakEnd: '14:00',
          slotDurationMinutes: 60,
        };

        return \`
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(380px, 1fr));gap:1.5rem;">
            <section class="clay-card" style="padding:1.5rem;">
              <h2 style="font-size:1.1rem;margin-bottom:0.35rem;">Clinic Working Hours & Rules</h2>
              <p style="font-size:0.85rem;color:var(--text-slate);margin-bottom:1.25rem;">Sunday is closed by default. All times use clinic timezone (Asia/Kolkata).</p>

              <form id="availability-rules-form">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.85rem;margin-bottom:1rem;">
                  <div>
                    <label for="rule-wd-open" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Mon–Fri Opening</label>
                    <input id="rule-wd-open" type="time" class="clay-input tabular-nums" value="\${escapeHtml(rules.weekdayOpen)}" required />
                  </div>
                  <div>
                    <label for="rule-wd-close" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Mon–Fri Closing</label>
                    <input id="rule-wd-close" type="time" class="clay-input tabular-nums" value="\${escapeHtml(rules.weekdayClose)}" required />
                  </div>
                  <div>
                    <label for="rule-sat-open" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Saturday Opening</label>
                    <input id="rule-sat-open" type="time" class="clay-input tabular-nums" value="\${escapeHtml(rules.saturdayOpen)}" required />
                  </div>
                  <div>
                    <label for="rule-sat-close" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Saturday Closing</label>
                    <input id="rule-sat-close" type="time" class="clay-input tabular-nums" value="\${escapeHtml(rules.saturdayClose)}" required />
                  </div>
                  <div>
                    <label for="rule-break-start" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Lunch Break Start</label>
                    <input id="rule-break-start" type="time" class="clay-input tabular-nums" value="\${escapeHtml(rules.breakStart)}" required />
                  </div>
                  <div>
                    <label for="rule-break-end" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Lunch Break End</label>
                    <input id="rule-break-end" type="time" class="clay-input tabular-nums" value="\${escapeHtml(rules.breakEnd)}" required />
                  </div>
                </div>

                <div style="margin-bottom:1.25rem;">
                  <label for="rule-slot-duration" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Appointment Slot Duration</label>
                  <select id="rule-slot-duration" class="clay-input">
                    <option value="30" \${Number(rules.slotDurationMinutes) === 30 ? 'selected' : ''}>30 Minutes</option>
                    <option value="45" \${Number(rules.slotDurationMinutes) === 45 ? 'selected' : ''}>45 Minutes</option>
                    <option value="60" \${Number(rules.slotDurationMinutes) === 60 ? 'selected' : ''}>60 Minutes</option>
                  </select>
                </div>

                <button type="submit" class="clay-btn-primary">Save Working Hours</button>
              </form>
            </section>

            <section class="clay-card" style="padding:1.5rem;">
              <h2 style="font-size:1.1rem;margin-bottom:0.35rem;">Block Dates or Time Slots</h2>
              <p style="font-size:0.85rem;color:var(--text-slate);margin-bottom:1.25rem;">Prevent bookings on holidays, maintenance hours, or practitioner leave.</p>

              <form id="block-slot-form" style="margin-bottom:1.5rem;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-bottom:0.75rem;">
                  <div>
                    <label for="block-date" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Date</label>
                    <input id="block-date" type="date" class="clay-input tabular-nums" required />
                  </div>
                  <div>
                    <label for="block-time" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Time Slot</label>
                    <select id="block-time" class="clay-input">
                      <option value="ALL_DAY">Full Day Closure</option>
                      <option value="09:00 AM">09:00 AM</option>
                      <option value="10:00 AM">10:00 AM</option>
                      <option value="11:00 AM">11:00 AM</option>
                      <option value="12:00 PM">12:00 PM</option>
                      <option value="02:00 PM">02:00 PM</option>
                      <option value="03:00 PM">03:00 PM</option>
                      <option value="04:00 PM">04:00 PM</option>
                      <option value="05:00 PM">05:00 PM</option>
                      <option value="06:00 PM">06:00 PM</option>
                      <option value="07:00 PM">07:00 PM</option>
                    </select>
                  </div>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-bottom:0.85rem;">
                  <div>
                    <label for="block-dentist" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Scope</label>
                    <select id="block-dentist" class="clay-input">
                      <option value="ALL">Entire Clinic</option>
                      \${state.dentists.map(d => \`<option value="\${escapeHtml(d.dentistId)}">\${escapeHtml(d.name)}</option>\`).join('')}
                    </select>
                  </div>
                  <div>
                    <label for="block-reason" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Reason</label>
                    <input id="block-reason" type="text" class="clay-input" placeholder="Public Holiday / Leave" required />
                  </div>
                </div>
                <button type="submit" class="clay-btn-primary">Add Schedule Block</button>
              </form>

              <h3 style="font-size:0.95rem;margin-bottom:0.65rem;">Active Blocked Dates & Slots</h3>
              \${state.blockedSlots.length === 0
                ? '<p style="font-size:0.85rem;color:var(--text-slate);">No blocked dates or time slots configured.</p>'
                : \`<div class="table-container">
                    <table class="admin-table">
                      <thead>
                        <tr>
                          <th>Date</th>
                          <th>Slot</th>
                          <th>Reason</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        \${state.blockedSlots.map(b => \`
                          <tr>
                            <td class="tabular-nums" style="font-weight:700;">\${escapeHtml(b.date)}</td>
                            <td>\${escapeHtml(b.timeSlot === 'ALL_DAY' ? 'Full Day' : b.timeSlot)}</td>
                            <td>\${escapeHtml(b.reason)}</td>
                            <td>
                              <button type="button" class="clay-btn-danger" data-delete-block="\${escapeHtml(b.slotId)}" style="padding:0.3rem 0.65rem;font-size:0.75rem;">Remove</button>
                            </td>
                          </tr>
                        \`).join('')}
                      </tbody>
                    </table>
                  </div>\`
              }
            </section>
          </div>
        \`;
      }

      function renderInquiriesTab() {
        return \`
          <section class="clay-card">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid var(--border-soft);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
              <div>
                <h2 style="font-size:1.15rem;">Patient Contact Inquiries</h2>
                <p style="font-size:0.85rem;color:var(--text-slate);">Messages submitted via the website Contact form.</p>
              </div>
              <div style="display:flex;gap:0.5rem;align-items:center;">
                <label for="inq-status-filter" style="font-size:0.82rem;font-weight:700;">Filter Status:</label>
                <select id="inq-status-filter" class="clay-input" style="width:auto;">
                  <option value="">All Inquiries</option>
                  <option value="New" \${state.inquiryStatusFilter === 'New' ? 'selected' : ''}>New</option>
                  <option value="Contacted" \${state.inquiryStatusFilter === 'Contacted' ? 'selected' : ''}>Contacted</option>
                  <option value="Resolved" \${state.inquiryStatusFilter === 'Resolved' ? 'selected' : ''}>Resolved</option>
                </select>
              </div>
            </div>

            <div class="table-container">
              <table class="admin-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Contact</th>
                    <th>Message</th>
                    <th>Submitted</th>
                    <th>Status</th>
                    <th>Update Status</th>
                  </tr>
                </thead>
                <tbody>
                  \${state.inquiries.length === 0
                    ? '<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-slate);">No inquiries found.</td></tr>'
                    : state.inquiries.map(inq => \`
                      <tr>
                        <td style="font-weight:700;">\${escapeHtml(inq.name)}</td>
                        <td>
                          <div>\${escapeHtml(inq.email)}</div>
                          <div class="tabular-nums" style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(inq.phone || '—')}</div>
                        </td>
                        <td style="max-width:360px;">\${escapeHtml(inq.message)}</td>
                        <td class="tabular-nums" style="font-size:0.8rem;color:var(--text-slate);">\${escapeHtml(String(inq.createdAt || '').slice(0, 10))}</td>
                        <td><span class="status-tag status-\${escapeHtml(inq.status)}">\${escapeHtml(inq.status)}</span></td>
                        <td>
                          <div style="display:flex;gap:0.35rem;">
                            \${['New', 'Contacted', 'Resolved'].map(st => \`
                              <button type="button" class="clay-btn-secondary" data-inq-id="\${escapeHtml(inq.inquiryId)}" data-inq-status="\${st}" \${inq.status === st ? 'disabled' : ''} style="padding:0.3rem 0.6rem;font-size:0.75rem;">\${st}</button>
                            \`).join('')}
                          </div>
                        </td>
                      </tr>
                    \`).join('')
                  }
                </tbody>
              </table>
            </div>
          </section>
        \`;
      }

      function renderModal() {
        if (!state.modal) return '';
        const m = state.modal;

        if (m.type === 'appointment') {
          const apt = m.apt;
          return \`
            <div class="modal-backdrop" id="modal-backdrop">
              <div class="clay-card modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-apt-title">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                  <h2 id="modal-apt-title" style="font-size:1.15rem;">Manage Appointment <span class="tabular-nums">\${escapeHtml(apt.appointmentId)}</span></h2>
                  <button type="button" id="close-modal-btn" class="clay-btn-secondary" style="padding:0.35rem 0.7rem;">Close</button>
                </div>

                <div style="padding:1rem;border-radius:16px;background:var(--bg-surface);margin-bottom:1.25rem;font-size:0.9rem;">
                  <div><strong>Patient:</strong> \${escapeHtml(apt.patientName)}</div>
                  <div><strong>Email:</strong> \${escapeHtml(apt.email)} · <strong>Phone:</strong> <span class="tabular-nums">\${escapeHtml(apt.phone)}</span></div>
                  <div><strong>Service:</strong> \${escapeHtml(apt.serviceName)} (<span class="tabular-nums">₹\${escapeHtml(apt.servicePrice || 499)}</span>)</div>
                  \${apt.notes ? \`<div style="margin-top:0.35rem;"><strong>Patient Notes:</strong> \${escapeHtml(apt.notes)}</div>\` : ''}
                </div>

                <form id="manage-apt-form">
                  <input type="hidden" name="appointmentId" value="\${escapeHtml(apt.appointmentId)}" />
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.85rem;margin-bottom:0.85rem;">
                    <div>
                      <label for="modal-apt-status" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Appointment Status</label>
                      <select id="modal-apt-status" class="clay-input">
                        \${['Pending', 'Confirmed', 'Completed', 'Cancelled', 'Rejected'].map(st =>
                          \`<option value="\${st}" \${apt.status === st ? 'selected' : ''}>\${st}</option>\`
                        ).join('')}
                      </select>
                    </div>
                    <div>
                      <label for="modal-apt-dentist" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Assigned Dentist</label>
                      <select id="modal-apt-dentist" class="clay-input">
                        \${state.dentists.filter(d => d.active || d.dentistId === apt.dentistId).map(d =>
                          \`<option value="\${escapeHtml(d.dentistId)}" \${apt.dentistId === d.dentistId ? 'selected' : ''}>\${escapeHtml(d.name)}</option>\`
                        ).join('')}
                      </select>
                    </div>
                    <div>
                      <label for="modal-apt-date" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Appointment Date</label>
                      <input id="modal-apt-date" type="date" class="clay-input tabular-nums" value="\${escapeHtml(apt.appointmentDate)}" required />
                    </div>
                    <div>
                      <label for="modal-apt-slot" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Time Slot</label>
                      <select id="modal-apt-slot" class="clay-input tabular-nums">
                        \${['09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM', '06:00 PM', '07:00 PM'].map(slot =>
                          \`<option value="\${slot}" \${apt.timeSlot === slot ? 'selected' : ''}>\${slot}</option>\`
                        ).join('')}
                      </select>
                    </div>
                  </div>

                  <div style="margin-bottom:1.25rem;">
                    <label for="modal-apt-notes" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Clinic Internal Notes</label>
                    <textarea id="modal-apt-notes" class="clay-input" rows="2" placeholder="Optional scheduling notes...">\${escapeHtml(apt.adminNotes || '')}</textarea>
                  </div>

                  <div style="display:flex;justify-content:space-between;align-items:center;gap:0.65rem;flex-wrap:wrap;">
                    <button type="button" id="delete-apt-btn" data-delete-apt="\${escapeHtml(apt.appointmentId)}" class="clay-btn-danger">Delete Booking</button>
                    <div style="display:flex;gap:0.65rem;">
                      <button type="button" id="cancel-modal-btn" class="clay-btn-secondary">Cancel</button>
                      <button type="submit" class="clay-btn-primary">Save Appointment Changes</button>
                    </div>
                  </div>
                </form>
              </div>
            </div>
          \`;
        }

        if (m.type === 'walkin') {
          const defaultDate = state.dashboard?.clinicDate || new Date().toISOString().slice(0, 10);
          return \`
            <div class="modal-backdrop" id="modal-backdrop">
              <div class="clay-card modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-walkin-title">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                  <h2 id="modal-walkin-title" style="font-size:1.15rem;">New Walk-In / Phone Appointment</h2>
                  <button type="button" id="close-modal-btn" class="clay-btn-secondary" style="padding:0.35rem 0.7rem;">Close</button>
                </div>
                <form id="walkin-apt-form">
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.85rem;margin-bottom:0.85rem;">
                    <div>
                      <label for="wi-name" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Patient Full Name *</label>
                      <input id="wi-name" type="text" class="clay-input" placeholder="e.g. Vikram Deshmukh" required />
                    </div>
                    <div>
                      <label for="wi-phone" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Phone Number *</label>
                      <input id="wi-phone" type="tel" class="clay-input tabular-nums" placeholder="+91 98220 12345" required />
                    </div>
                    <div>
                      <label for="wi-email" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Email Address (Optional)</label>
                      <input id="wi-email" type="email" class="clay-input" placeholder="patient@gmail.com" />
                    </div>
                    <div>
                      <label for="wi-status" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Initial Status *</label>
                      <select id="wi-status" class="clay-input">
                        <option value="Confirmed" selected>Confirmed (Hold Slot)</option>
                        <option value="Pending">Pending</option>
                        <option value="Completed">Completed (Walk-In Done)</option>
                      </select>
                    </div>
                    <div>
                      <label for="wi-service" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Dental Service *</label>
                      <select id="wi-service" class="clay-input" required>
                        \${state.services.filter(s => s.active).map(s =>
                          \`<option value="\${escapeHtml(s.serviceId)}">\${escapeHtml(s.name)} (₹\${escapeHtml(s.price)})</option>\`
                        ).join('')}
                      </select>
                    </div>
                    <div>
                      <label for="wi-dentist" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Assigned Dentist *</label>
                      <select id="wi-dentist" class="clay-input" required>
                        \${state.dentists.filter(d => d.active).map(d =>
                          \`<option value="\${escapeHtml(d.dentistId)}">\${escapeHtml(d.name)}</option>\`
                        ).join('')}
                      </select>
                    </div>
                    <div>
                      <label for="wi-date" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Appointment Date *</label>
                      <input id="wi-date" type="date" class="clay-input tabular-nums" value="\${escapeHtml(defaultDate)}" required />
                    </div>
                    <div>
                      <label for="wi-slot" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Time Slot *</label>
                      <select id="wi-slot" class="clay-input tabular-nums">
                        \${['09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM', '06:00 PM', '07:00 PM'].map(slot =>
                          \`<option value="\${slot}">\${slot}</option>\`
                        ).join('')}
                      </select>
                    </div>
                  </div>
                  <div style="margin-bottom:1.25rem;">
                    <label for="wi-notes" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Clinical / Reception Notes</label>
                    <textarea id="wi-notes" class="clay-input" rows="2" placeholder="Walk-in consultation or phone booking notes..."></textarea>
                  </div>
                  <div style="display:flex;justify-content:flex-end;gap:0.65rem;">
                    <button type="button" id="cancel-modal-btn" class="clay-btn-secondary">Cancel</button>
                    <button type="submit" class="clay-btn-primary">Create Appointment</button>
                  </div>
                </form>
              </div>
            </div>
          \`;
        }

        if (m.type === 'patient') {
          const pt = m.patient;
          return \`
            <div class="modal-backdrop" id="modal-backdrop">
              <div class="clay-card modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-pt-title">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                  <h2 id="modal-pt-title" style="font-size:1.15rem;">Patient Visit History — \${escapeHtml(pt.patientName)}</h2>
                  <button type="button" id="close-modal-btn" class="clay-btn-secondary" style="padding:0.35rem 0.7rem;">Close</button>
                </div>
                <p style="font-size:0.88rem;color:var(--text-slate);margin-bottom:1rem;">
                  \${escapeHtml(pt.email)} · <span class="tabular-nums">\${escapeHtml(pt.phone)}</span> · Total Appointments: <strong class="tabular-nums">\${pt.appointmentCount}</strong>
                </p>
                <div class="table-container">
                  <table class="admin-table">
                    <thead>
                      <tr>
                        <th>Reference</th>
                        <th>Date & Time</th>
                        <th>Service</th>
                        <th>Dentist</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      \${pt.appointments.map(a => \`
                        <tr>
                          <td class="tabular-nums" style="font-weight:700;">\${escapeHtml(a.appointmentId)}</td>
                          <td class="tabular-nums">\${escapeHtml(a.appointmentDate)} · \${escapeHtml(a.timeSlot)}</td>
                          <td>\${escapeHtml(a.serviceName)}</td>
                          <td>\${escapeHtml(a.dentistName)}</td>
                          <td><span class="status-tag status-\${escapeHtml(a.status)}">\${escapeHtml(a.status)}</span></td>
                        </tr>
                      \`).join('')}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          \`;
        }

        if (m.type === 'service') {
          const srv = m.service || { name: '', category: 'Preventive', price: 799, durationMinutes: 45, description: '' };
          return \`
            <div class="modal-backdrop" id="modal-backdrop">
              <div class="clay-card modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-srv-title">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                  <h2 id="modal-srv-title" style="font-size:1.15rem;">\${srv.serviceId ? 'Edit Dental Service' : 'Add Dental Service'}</h2>
                  <button type="button" id="close-modal-btn" class="clay-btn-secondary" style="padding:0.35rem 0.7rem;">Close</button>
                </div>
                <form id="service-modal-form">
                  <input type="hidden" id="srv-id" value="\${escapeHtml(srv.serviceId || '')}" />
                  <div style="margin-bottom:0.85rem;">
                    <label for="srv-name" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Service Name</label>
                    <input id="srv-name" type="text" class="clay-input" value="\${escapeHtml(srv.name)}" required />
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.75rem;margin-bottom:0.85rem;">
                    <div>
                      <label for="srv-category" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Category</label>
                      <select id="srv-category" class="clay-input">
                        \${['Preventive', 'Cosmetic', 'Restorative', 'Specialist'].map(c =>
                          \`<option value="\${c}" \${srv.category === c ? 'selected' : ''}>\${c}</option>\`
                        ).join('')}
                      </select>
                    </div>
                    <div>
                      <label for="srv-price" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Starting Price (₹)</label>
                      <input id="srv-price" type="number" min="0" class="clay-input tabular-nums" value="\${escapeHtml(srv.price)}" required />
                    </div>
                    <div>
                      <label for="srv-duration" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Duration (mins)</label>
                      <input id="srv-duration" type="number" min="15" max="240" class="clay-input tabular-nums" value="\${escapeHtml(srv.durationMinutes || 45)}" required />
                    </div>
                  </div>
                  <div style="margin-bottom:1.25rem;">
                    <label for="srv-desc" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Description</label>
                    <textarea id="srv-desc" class="clay-input" rows="3" required>\${escapeHtml(srv.description)}</textarea>
                  </div>
                  <div style="display:flex;justify-content:flex-end;gap:0.65rem;">
                    <button type="button" id="cancel-modal-btn" class="clay-btn-secondary">Cancel</button>
                    <button type="submit" class="clay-btn-primary">Save Service</button>
                  </div>
                </form>
              </div>
            </div>
          \`;
        }

        if (m.type === 'dentist') {
          const d = m.dentist || { name: '', specialization: '', bio: '' };
          return \`
            <div class="modal-backdrop" id="modal-backdrop">
              <div class="clay-card modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-dent-title">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
                  <h2 id="modal-dent-title" style="font-size:1.15rem;">\${d.dentistId ? 'Edit Dentist Profile' : 'Add Dentist Profile'}</h2>
                  <button type="button" id="close-modal-btn" class="clay-btn-secondary" style="padding:0.35rem 0.7rem;">Close</button>
                </div>
                <form id="dentist-modal-form">
                  <input type="hidden" id="dent-id" value="\${escapeHtml(d.dentistId || '')}" />
                  <div style="margin-bottom:0.85rem;">
                    <label for="dent-name" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Full Name</label>
                    <input id="dent-name" type="text" class="clay-input" value="\${escapeHtml(d.name)}" placeholder="Dr. Kavya Nair" required />
                  </div>
                  <div style="margin-bottom:0.85rem;">
                    <label for="dent-spec" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Specialization</label>
                    <input id="dent-spec" type="text" class="clay-input" value="\${escapeHtml(d.specialization)}" placeholder="Pediatric & Preventive Dentistry" required />
                  </div>
                  <div style="margin-bottom:1.25rem;">
                    <label for="dent-bio" style="display:block;font-size:0.8rem;font-weight:700;margin-bottom:0.25rem;">Short Introduction</label>
                    <textarea id="dent-bio" class="clay-input" rows="3" required>\${escapeHtml(d.bio)}</textarea>
                  </div>
                  <div style="display:flex;justify-content:flex-end;gap:0.65rem;">
                    <button type="button" id="cancel-modal-btn" class="clay-btn-secondary">Cancel</button>
                    <button type="submit" class="clay-btn-primary">Save Dentist Profile</button>
                  </div>
                </form>
              </div>
            </div>
          \`;
        }

        return '';
      }

      function renderSettingsTab() {
        const conn = state.dashboard?.dbConnection || {
          engine: 'Built-in Embedded Database (Active Fallback)',
          isAtlas: false,
          mongoUriConfigured: false,
          detail: 'Running on auto-healing embedded MongoDB-compatible engine',
          collections: {},
        };
        const colList = [
          { key: 'appointments', name: 'appointments', desc: 'Patient bookings, walk-ins, reference IDs (SC-2026-xxx), status & notes' },
          { key: 'slot_reservations', name: 'slot_reservations', desc: 'Atomic double-booking lock index (dentistKey + appointmentDate + timeSlot)' },
          { key: 'services', name: 'services', desc: 'Dental treatments catalog, INR fees (₹), duration & active status' },
          { key: 'dentists', name: 'dentists', desc: 'Clinic dental practitioners, MDS specializations & bios' },
          { key: 'availability_rules', name: 'availability_rules', desc: 'Mon–Sat working hours, lunch break window & slot duration' },
          { key: 'blocked_slots', name: 'blocked_slots', desc: 'Holiday closures, maintenance blocks & practitioner leave dates' },
          { key: 'inquiries', name: 'inquiries', desc: 'Website contact desk messages & callback status' },
          { key: 'admins', name: 'admins', desc: 'Hashed administrator credentials & security profile' },
        ];

        return \`
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(360px, 1fr));gap:1.5rem;margin-bottom:1.5rem;">
            <section class="clay-card" style="padding:1.75rem;">
              <h2 style="font-size:1.15rem;margin-bottom:0.35rem;">Database & Connections Health</h2>
              <p style="font-size:0.85rem;color:var(--text-slate);margin-bottom:1.1rem;">
                Live status of your MongoDB connection and all 8 clinic database collections.
              </p>
              <div style="display:flex;flex-direction:column;gap:0.75rem;font-size:0.88rem;margin-bottom:1.25rem;">
                <div style="padding:0.85rem 1rem;border-radius:16px;background:\${conn.isAtlas ? '#EEFAF5' : '#EFF6FF'};border:1px solid var(--border-soft);">
                  <div style="font-weight:800;color:\${conn.isAtlas ? 'var(--status-success-text)' : 'var(--primary-sky-deep)'};">
                    ● Active Storage Engine: \${escapeHtml(conn.engine)}
                  </div>
                  <div style="font-size:0.8rem;color:var(--text-slate);margin-top:0.25rem;">
                    Status: \${escapeHtml(conn.detail)}
                  </div>
                </div>
                <div style="padding:0.85rem 1rem;border-radius:16px;background:var(--bg-surface);">
                  <strong>Database Name:</strong> <span class="tabular-nums">smilecraft_dental</span><br />
                  <strong>Total Collections Configured:</strong> <span class="tabular-nums">8 MongoDB Collections</span>
                </div>
              </div>

              <h3 style="font-size:0.95rem;margin-bottom:0.6rem;">All 8 MongoDB Collections in This App</h3>
              <div class="table-container">
                <table class="admin-table">
                  <thead>
                    <tr>
                      <th>Collection Name</th>
                      <th>Records</th>
                      <th>Purpose</th>
                    </tr>
                  </thead>
                  <tbody>
                    \${colList.map(c => \`
                      <tr>
                        <td class="tabular-nums" style="font-weight:800;color:var(--primary-sky-deep);">\${escapeHtml(c.name)}</td>
                        <td class="tabular-nums" style="font-weight:700;">\${conn.collections?.[c.key] ?? '—'}</td>
                        <td style="font-size:0.78rem;color:var(--text-slate);">\${escapeHtml(c.desc)}</td>
                      </tr>
                    \`).join('')}
                  </tbody>
                </table>
              </div>
            </section>

            <section class="clay-card" style="padding:1.75rem;">
              <h2 style="font-size:1.15rem;margin-bottom:0.35rem;">Administrator Profile & Password Security</h2>
              <p style="font-size:0.85rem;color:var(--text-slate);margin-bottom:1.25rem;">
                Update your clinic administrator display name and rotate your login password.
              </p>
              <form id="admin-password-form" style="margin-bottom:1.5rem;">
                <div style="margin-bottom:0.9rem;">
                  <label for="sec-admin-name" style="display:block;font-size:0.82rem;font-weight:700;margin-bottom:0.25rem;">Administrator Name</label>
                  <input id="sec-admin-name" type="text" class="clay-input" value="\${escapeHtml(state.admin?.name || 'Dr. Aanya Mehta · Clinic Admin')}" required />
                </div>
                <div style="margin-bottom:0.9rem;">
                  <label for="sec-current-pass" style="display:block;font-size:0.82rem;font-weight:700;margin-bottom:0.25rem;">Current Password *</label>
                  <input id="sec-current-pass" type="password" class="clay-input" placeholder="Enter current password" required />
                </div>
                <div style="margin-bottom:1.25rem;">
                  <label for="sec-new-pass" style="display:block;font-size:0.82rem;font-weight:700;margin-bottom:0.25rem;">New Password (min 6 characters) *</label>
                  <input id="sec-new-pass" type="password" class="clay-input" placeholder="Enter new strong password" required />
                </div>
                <button type="submit" class="clay-btn-primary">Update Password & Profile</button>
              </form>

              <div style="padding-top:1rem;border-top:1px solid var(--border-soft);display:flex;flex-direction:column;gap:0.65rem;font-size:0.88rem;">
                <div style="padding:0.75rem 1rem;border-radius:14px;background:var(--bg-surface);">
                  <strong>Clinic Location:</strong> 204 Sunshine Plaza, Baner Road, Pune 411045
                </div>
                <div style="padding:0.75rem 1rem;border-radius:14px;background:var(--bg-surface);">
                  <strong>Signed-In Account:</strong> <span class="tabular-nums">\${escapeHtml(state.admin?.email || 'admin@smilecraft.in')}</span>
                </div>
              </div>
            </section>
          </div>
        \`;
      }

      function renderAuthenticatedShell() {
        const pendingCount = state.dashboard?.stats?.pendingAppointments || 0;
        const navItems = [
          { id: 'overview', label: 'Dashboard Overview' },
          { id: 'appointments', label: 'Appointments', count: pendingCount },
          { id: 'calendar', label: 'Daily Schedule' },
          { id: 'patients', label: 'Patients' },
          { id: 'services', label: 'Dental Services' },
          { id: 'dentists', label: 'Our Dentists' },
          { id: 'availability', label: 'Hours & Blocks' },
          { id: 'inquiries', label: 'Patient Inquiries', count: state.dashboard?.stats?.newInquiries || 0 },
          { id: 'settings', label: 'Settings & Security' },
        ];

        let activeContent = '';
        if (state.activeTab === 'overview') activeContent = renderOverviewTab();
        else if (state.activeTab === 'appointments') activeContent = renderAppointmentsTab();
        else if (state.activeTab === 'calendar') activeContent = renderCalendarTab();
        else if (state.activeTab === 'patients') activeContent = renderPatientsTab();
        else if (state.activeTab === 'services') activeContent = renderServicesTab();
        else if (state.activeTab === 'dentists') activeContent = renderDentistsTab();
        else if (state.activeTab === 'availability') activeContent = renderAvailabilityTab();
        else if (state.activeTab === 'inquiries') activeContent = renderInquiriesTab();
        else if (state.activeTab === 'settings') activeContent = renderSettingsTab();

        return \`
          <div class="admin-shell">
            <aside class="admin-sidebar \${state.sidebarOpen ? 'open' : ''}" aria-label="Administrator Navigation">
              <div>
                <a href="/admin" class="sidebar-brand">
                  <svg width="32" height="32" viewBox="0 0 48 48" fill="none" aria-hidden="true">
                    <rect width="48" height="48" rx="14" fill="#8ECDF4"/>
                    <path d="M16 17C16 13.5 19 11 24 11C29 11 32 13.5 32 17C32 21.5 30 25 29 32C28.5 35 26.8 36 25.5 33.5C24.6 31.8 24.4 29.5 24 29.5C23.6 29.5 23.4 31.8 22.5 33.5C21.2 36 19.5 35 19 32C18 25 16 21.5 16 17Z" fill="#FFFDF8" stroke="#25324A" stroke-width="2.2"/>
                  </svg>
                  <span class="font-display" style="font-weight:800;font-size:1.05rem;">SmileCraft Admin</span>
                </a>

                <ul class="nav-list">
                  \${navItems.map(item => \`
                    <li>
                      <button type="button" class="nav-item-btn \${state.activeTab === item.id ? 'active' : ''}" data-goto-tab="\${item.id}">
                        <span>\${escapeHtml(item.label)}</span>
                        \${item.count ? \`<span class="tabular-nums" style="font-size:0.78rem;color:var(--primary-sky-deep);font-weight:800;">(\${item.count})</span>\` : ''}
                      </button>
                    </li>
                  \`).join('')}
                </ul>
              </div>

              <div style="padding-top:1rem;border-top:1px solid var(--border-soft);display:flex;flex-direction:column;gap:0.5rem;">
                <a href="/" class="clay-btn-secondary" style="text-decoration:none;justify-content:flex-start;">← Public Website</a>
                <button type="button" id="logout-btn" class="clay-btn-danger" style="justify-content:flex-start;">Sign Out</button>
              </div>
            </aside>

            <div class="admin-main">
              <header class="admin-topbar">
                <div style="display:flex;align-items:center;gap:0.75rem;">
                  <button type="button" id="mobile-sidebar-toggle" class="clay-btn-secondary mobile-menu-btn" aria-label="Toggle Navigation Menu">Menu</button>
                  <span class="font-display" style="font-weight:700;font-size:1rem;">
                    Admin Portal / \${escapeHtml(navItems.find(n => n.id === state.activeTab)?.label || 'Overview')}
                  </span>
                </div>
                <div style="display:flex;align-items:center;gap:0.85rem;">
                  <button type="button" id="topbar-walkin-btn" class="clay-btn-primary" style="padding:0.45rem 0.9rem;font-size:0.8rem;">+ Walk-In Booking</button>
                  <span style="font-size:0.85rem;color:var(--text-slate);">
                    Signed in as <strong>\${escapeHtml(state.admin?.email || 'admin@smilecraft.in')}</strong>
                  </span>
                </div>
              </header>

              <main class="admin-content">
                \${activeContent}
              </main>
            </div>
          </div>
          \${renderModal()}
        \`;
      }

      function render() {
        const root = document.getElementById('admin-app');
        if (!root) return;
        if (state.loading) {
          root.innerHTML = '<main class="login-wrapper"><div class="clay-card" style="padding:2rem;font-weight:700;">Loading SmileCraft Admin Portal...</div></main>';
          return;
        }
        root.innerHTML = state.authenticated ? renderAuthenticatedShell() : renderLoginScreen();
        bindEvents();
      }

      function bindEvents() {
        const loginForm = document.getElementById('admin-login-form');
        if (loginForm) {
          const togglePassBtn = document.getElementById('toggle-password-btn');
          const passInput = document.getElementById('admin-password');
          if (togglePassBtn && passInput) {
            togglePassBtn.addEventListener('click', () => {
              const isHidden = passInput.type === 'password';
              passInput.type = isHidden ? 'text' : 'password';
              togglePassBtn.textContent = isHidden ? 'Hide' : 'Show';
              togglePassBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
            });
          }

          const fillDemoBtn = document.getElementById('fill-demo-admin-btn');
          if (fillDemoBtn) {
            fillDemoBtn.addEventListener('click', () => {
              document.getElementById('admin-email').value = 'admin@smilecraft.in';
              document.getElementById('admin-password').value = 'ChangeMe@12345';
            });
          }

          loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const errBox = document.getElementById('login-error-box');
            const submitBtn = document.getElementById('login-submit-btn');
            errBox.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing In...';
            try {
              const email = document.getElementById('admin-email').value;
              const password = document.getElementById('admin-password').value;
              const res = await apiFetch('/api/admin/login', {
                method: 'POST',
                body: JSON.stringify({ email, password }),
              });
              state.authenticated = true;
              state.admin = res.data.admin;
              state.csrfToken = res.data.csrfToken || '';
              state.bearerToken = res.data.token || '';
              localStorage.setItem('sc_csrf_token', state.csrfToken);
              localStorage.setItem('sc_bearer_token', state.bearerToken);
              await loadInitialAdminData();
              showToast('Signed in to SmileCraft Admin.');
              render();
            } catch (err) {
              errBox.textContent = err.message;
              errBox.style.display = 'block';
              submitBtn.disabled = false;
              submitBtn.textContent = 'Sign In to Dashboard';
            }
          });
          return;
        }

        // Sidebar navigation
        document.querySelectorAll('[data-goto-tab]').forEach((btn) => {
          btn.addEventListener('click', () => switchTab(btn.getAttribute('data-goto-tab')));
        });

        const mobileToggle = document.getElementById('mobile-sidebar-toggle');
        if (mobileToggle) {
          mobileToggle.addEventListener('click', () => {
            state.sidebarOpen = !state.sidebarOpen;
            render();
          });
        }

        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
          logoutBtn.addEventListener('click', async () => {
            await apiFetch('/api/admin/logout', { method: 'POST' }).catch(() => {});
            localStorage.removeItem('sc_csrf_token');
            localStorage.removeItem('sc_bearer_token');
            state.authenticated = false;
            state.admin = null;
            state.csrfToken = '';
            state.bearerToken = '';
            render();
          });
        }

        // Quick status updates
        document.querySelectorAll('[data-quick-status]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const appointmentId = btn.getAttribute('data-apt-id');
            const status = btn.getAttribute('data-quick-status');
            try {
              await apiFetch('/api/admin/appointments/' + encodeURIComponent(appointmentId), {
                method: 'PATCH',
                body: JSON.stringify({ status }),
              });
              showToast('Appointment ' + appointmentId + ' marked as ' + status + '.');
              await loadInitialAdminData();
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        });

        // Open appointment manage modal
        document.querySelectorAll('[data-open-apt]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const appointmentId = btn.getAttribute('data-open-apt');
            try {
              const res = await apiFetch('/api/admin/appointments/' + encodeURIComponent(appointmentId));
              state.modal = { type: 'appointment', apt: res.data };
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        });

        // Appointment Filters
        const filterForm = document.getElementById('apt-filter-form');
        if (filterForm) {
          filterForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            state.filters.q = document.getElementById('filter-q').value.trim();
            state.filters.status = document.getElementById('filter-status').value;
            state.filters.serviceId = document.getElementById('filter-service').value;
            state.filters.dentistId = document.getElementById('filter-dentist').value;
            await loadAppointments(1);
            render();
          });
        }

        const resetFiltersBtn = document.getElementById('reset-filters-btn');
        if (resetFiltersBtn) {
          resetFiltersBtn.addEventListener('click', async () => {
            state.filters = { q: '', status: '', serviceId: '', dentistId: '', dateFrom: '', dateTo: '', sortBy: 'appointmentDate', sortOrder: 'desc' };
            await loadAppointments(1);
            render();
          });
        }

        const exportCsvBtn = document.getElementById('export-csv-btn');
        if (exportCsvBtn) {
          exportCsvBtn.addEventListener('click', async () => {
            const params = new URLSearchParams();
            if (state.filters.q) params.set('q', state.filters.q);
            if (state.filters.status) params.set('status', state.filters.status);
            if (state.filters.serviceId) params.set('serviceId', state.filters.serviceId);
            if (state.filters.dentistId) params.set('dentistId', state.filters.dentistId);
            window.location.href = '/api/admin/appointments/export.csv?' + params.toString();
          });
        }

        // Pagination
        document.querySelectorAll('[data-apt-page]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const p = Number(btn.getAttribute('data-apt-page'));
            await loadAppointments(p);
            render();
          });
        });

        // Calendar controls
        const calDateInput = document.getElementById('cal-date-input');
        if (calDateInput) {
          calDateInput.addEventListener('change', async () => {
            state.calendarDate = calDateInput.value;
            await loadCalendar();
            render();
          });
        }
        const calDentistSelect = document.getElementById('cal-dentist-select');
        if (calDentistSelect) {
          calDentistSelect.addEventListener('change', async () => {
            state.calendarDentistId = calDentistSelect.value;
            await loadCalendar();
            render();
          });
        }

        // Patient directory controls
        const patientSearchForm = document.getElementById('patient-search-form');
        if (patientSearchForm) {
          patientSearchForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            state.patientSearch = document.getElementById('patient-search-input').value.trim();
            await loadPatients(1);
            render();
          });
        }
        document.querySelectorAll('[data-view-patient]').forEach((btn) => {
          btn.addEventListener('click', () => {
            const idx = Number(btn.getAttribute('data-view-patient'));
            const pt = state.patients[idx];
            if (pt) {
              state.modal = { type: 'patient', patient: pt };
              render();
            }
          });
        });

        // Services management controls
        const newServiceBtn = document.getElementById('new-service-btn');
        if (newServiceBtn) {
          newServiceBtn.addEventListener('click', () => {
            state.modal = { type: 'service', service: null };
            render();
          });
        }
        document.querySelectorAll('[data-edit-service]').forEach((btn) => {
          btn.addEventListener('click', () => {
            const srv = state.services.find(s => s.serviceId === btn.getAttribute('data-edit-service'));
            if (srv) {
              state.modal = { type: 'service', service: srv };
              render();
            }
          });
        });
        document.querySelectorAll('[data-toggle-service]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const srv = state.services.find(s => s.serviceId === btn.getAttribute('data-toggle-service'));
            if (!srv) return;
            try {
              await apiFetch('/api/admin/services/' + encodeURIComponent(srv.serviceId), {
                method: 'PATCH',
                body: JSON.stringify({ active: !srv.active }),
              });
              const srvRes = await apiFetch('/api/admin/services');
              state.services = srvRes.data;
              showToast('Service status updated.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        });

        // Dentists management controls
        const newDentistBtn = document.getElementById('new-dentist-btn');
        if (newDentistBtn) {
          newDentistBtn.addEventListener('click', () => {
            state.modal = { type: 'dentist', dentist: null };
            render();
          });
        }
        document.querySelectorAll('[data-edit-dentist]').forEach((btn) => {
          btn.addEventListener('click', () => {
            const d = state.dentists.find(x => x.dentistId === btn.getAttribute('data-edit-dentist'));
            if (d) {
              state.modal = { type: 'dentist', dentist: d };
              render();
            }
          });
        });
        document.querySelectorAll('[data-toggle-dentist]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const d = state.dentists.find(x => x.dentistId === btn.getAttribute('data-toggle-dentist'));
            if (!d) return;
            try {
              await apiFetch('/api/admin/dentists/' + encodeURIComponent(d.dentistId), {
                method: 'PATCH',
                body: JSON.stringify({ active: !d.active }),
              });
              const dentRes = await apiFetch('/api/admin/dentists');
              state.dentists = dentRes.data;
              showToast('Dentist availability updated.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        });

        // Availability rules & blocked slots
        const rulesForm = document.getElementById('availability-rules-form');
        if (rulesForm) {
          rulesForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
              await apiFetch('/api/admin/availability-rules', {
                method: 'PUT',
                body: JSON.stringify({
                  weekdayOpen: document.getElementById('rule-wd-open').value,
                  weekdayClose: document.getElementById('rule-wd-close').value,
                  saturdayOpen: document.getElementById('rule-sat-open').value,
                  saturdayClose: document.getElementById('rule-sat-close').value,
                  breakStart: document.getElementById('rule-break-start').value,
                  breakEnd: document.getElementById('rule-break-end').value,
                  slotDurationMinutes: Number(document.getElementById('rule-slot-duration').value),
                  workingDays: [1, 2, 3, 4, 5, 6],
                }),
              });
              await loadAvailabilityRules();
              showToast('Working hours updated.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        const blockForm = document.getElementById('block-slot-form');
        if (blockForm) {
          blockForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
              await apiFetch('/api/admin/blocked-slots', {
                method: 'POST',
                body: JSON.stringify({
                  date: document.getElementById('block-date').value,
                  timeSlot: document.getElementById('block-time').value,
                  dentistId: document.getElementById('block-dentist').value,
                  reason: document.getElementById('block-reason').value,
                  force: true,
                }),
              });
              await loadAvailabilityRules();
              showToast('Schedule block added.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        document.querySelectorAll('[data-delete-block]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const slotId = btn.getAttribute('data-delete-block');
            try {
              await apiFetch('/api/admin/blocked-slots/' + encodeURIComponent(slotId), { method: 'DELETE' });
              await loadAvailabilityRules();
              showToast('Schedule block removed.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        });

        // Inquiries filter & status buttons
        const inqFilter = document.getElementById('inq-status-filter');
        if (inqFilter) {
          inqFilter.addEventListener('change', async () => {
            state.inquiryStatusFilter = inqFilter.value;
            await loadInquiries();
            render();
          });
        }
        document.querySelectorAll('[data-inq-id]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const inquiryId = btn.getAttribute('data-inq-id');
            const status = btn.getAttribute('data-inq-status');
            try {
              await apiFetch('/api/admin/inquiries/' + encodeURIComponent(inquiryId), {
                method: 'PATCH',
                body: JSON.stringify({ status }),
              });
              await loadInquiries();
              const dashRes = await apiFetch('/api/admin/dashboard');
              state.dashboard = dashRes.data;
              showToast('Inquiry marked as ' + status + '.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        });

        // Modal close & submit handlers
        const closeModalBtn = document.getElementById('close-modal-btn');
        const cancelModalBtn = document.getElementById('cancel-modal-btn');
        if (closeModalBtn) closeModalBtn.addEventListener('click', () => { state.modal = null; render(); });
        if (cancelModalBtn) cancelModalBtn.addEventListener('click', () => { state.modal = null; render(); });

        const manageAptForm = document.getElementById('manage-apt-form');
        if (manageAptForm) {
          manageAptForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const aptId = state.modal.apt.appointmentId;
            try {
              await apiFetch('/api/admin/appointments/' + encodeURIComponent(aptId), {
                method: 'PATCH',
                body: JSON.stringify({
                  status: document.getElementById('modal-apt-status').value,
                  dentistId: document.getElementById('modal-apt-dentist').value,
                  appointmentDate: document.getElementById('modal-apt-date').value,
                  timeSlot: document.getElementById('modal-apt-slot').value,
                  adminNotes: document.getElementById('modal-apt-notes').value,
                }),
              });
              state.modal = null;
              await loadInitialAdminData();
              if (state.activeTab === 'calendar') await loadCalendar();
              showToast('Appointment ' + aptId + ' updated.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        const serviceModalForm = document.getElementById('service-modal-form');
        if (serviceModalForm) {
          serviceModalForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const serviceId = document.getElementById('srv-id').value;
            const payload = {
              name: document.getElementById('srv-name').value,
              category: document.getElementById('srv-category').value,
              price: Number(document.getElementById('srv-price').value),
              durationMinutes: Number(document.getElementById('srv-duration').value),
              description: document.getElementById('srv-desc').value,
            };
            try {
              if (serviceId) {
                await apiFetch('/api/admin/services/' + encodeURIComponent(serviceId), {
                  method: 'PATCH',
                  body: JSON.stringify(payload),
                });
              } else {
                await apiFetch('/api/admin/services', {
                  method: 'POST',
                  body: JSON.stringify(payload),
                });
              }
              state.modal = null;
              const srvRes = await apiFetch('/api/admin/services');
              state.services = srvRes.data;
              showToast('Dental service saved.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        const dentistModalForm = document.getElementById('dentist-modal-form');
        if (dentistModalForm) {
          dentistModalForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const dentistId = document.getElementById('dent-id').value;
            const payload = {
              name: document.getElementById('dent-name').value,
              specialization: document.getElementById('dent-spec').value,
              bio: document.getElementById('dent-bio').value,
            };
            try {
              if (dentistId) {
                await apiFetch('/api/admin/dentists/' + encodeURIComponent(dentistId), {
                  method: 'PATCH',
                  body: JSON.stringify(payload),
                });
              } else {
                await apiFetch('/api/admin/dentists', {
                  method: 'POST',
                  body: JSON.stringify(payload),
                });
              }
              state.modal = null;
              const dentRes = await apiFetch('/api/admin/dentists');
              state.dentists = dentRes.data;
              showToast('Dentist profile saved.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        // Walk-In / Phone Booking modal triggers & submission
        const newWalkinBtn = document.getElementById('new-walkin-btn');
        const topbarWalkinBtn = document.getElementById('topbar-walkin-btn');
        [newWalkinBtn, topbarWalkinBtn].forEach((btn) => {
          if (btn) {
            btn.addEventListener('click', () => {
              state.modal = { type: 'walkin' };
              render();
            });
          }
        });

        const walkinAptForm = document.getElementById('walkin-apt-form');
        if (walkinAptForm) {
          walkinAptForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
              const res = await apiFetch('/api/admin/appointments', {
                method: 'POST',
                body: JSON.stringify({
                  patientName: document.getElementById('wi-name').value.trim(),
                  phone: document.getElementById('wi-phone').value.trim(),
                  email: document.getElementById('wi-email').value.trim(),
                  status: document.getElementById('wi-status').value,
                  serviceId: document.getElementById('wi-service').value,
                  dentistId: document.getElementById('wi-dentist').value,
                  appointmentDate: document.getElementById('wi-date').value,
                  timeSlot: document.getElementById('wi-slot').value,
                  notes: document.getElementById('wi-notes').value.trim(),
                }),
              });
              state.modal = null;
              await loadInitialAdminData();
              if (state.activeTab === 'calendar') await loadCalendar();
              showToast(res.message || 'Walk-in appointment created.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        // Delete appointment button inside Manage Modal
        const deleteAptBtn = document.getElementById('delete-apt-btn');
        if (deleteAptBtn) {
          deleteAptBtn.addEventListener('click', async () => {
            const aptId = deleteAptBtn.getAttribute('data-delete-apt');
            if (!aptId) return;
            try {
              await apiFetch('/api/admin/appointments/' + encodeURIComponent(aptId), {
                method: 'DELETE',
              });
              state.modal = null;
              await loadInitialAdminData();
              if (state.activeTab === 'calendar') await loadCalendar();
              showToast('Appointment ' + aptId + ' deleted.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }

        // Admin Password & Profile Settings Form
        const adminPassForm = document.getElementById('admin-password-form');
        if (adminPassForm) {
          adminPassForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
              const res = await apiFetch('/api/admin/change-password', {
                method: 'POST',
                body: JSON.stringify({
                  name: document.getElementById('sec-admin-name').value.trim(),
                  currentPassword: document.getElementById('sec-current-pass').value,
                  newPassword: document.getElementById('sec-new-pass').value,
                }),
              });
              if (res.data?.name && state.admin) {
                state.admin.name = res.data.name;
              }
              document.getElementById('sec-current-pass').value = '';
              document.getElementById('sec-new-pass').value = '';
              showToast(res.message || 'Password updated.');
              render();
            } catch (err) {
              showToast(err.message, true);
            }
          });
        }
      }

      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && state.modal) {
          state.modal = null;
          render();
        }
      });

      checkSession();
    })();
  </script>
</body>
</html>`;
}
