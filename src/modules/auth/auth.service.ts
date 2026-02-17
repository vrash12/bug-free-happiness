// src/modules/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { randomInt, timingSafeEqual, createHash } from 'crypto';
import { DateTime } from 'luxon';

import { PrismaService } from '../../database/prisma/prisma.service';
import { EmailService } from '../../integrations/email/email.service';

const LOGIN_MFA_ROLES = new Set(['commuter', 'pao', 'manager', 'teller']);

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
    private email: EmailService,
  ) {}

  // -----------------------
  // Config helpers
  // -----------------------
  private get OTP_TTL_MINUTES() {
    return Number(this.config.get('OTP_TTL_MINUTES') ?? 10);
  }
  private get OTP_MAX_ATTEMPTS() {
    return Number(this.config.get('OTP_MAX_ATTEMPTS') ?? 5);
  }
  private get OTP_RESEND_COOLDOWN_SEC() {
    return Number(this.config.get('OTP_RESEND_COOLDOWN_SEC') ?? 60);
  }
  private get OTP_PEPPER() {
    return String(this.config.get('OTP_PEPPER') ?? 'change-me');
  }
  private get OTP_DEV_MODE() {
    const v = String(this.config.get('OTP_DEV_MODE') ?? '0').trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(v);
  }
  private get FIRST_USER_ID_NO_OTP() {
    return Number(this.config.get('FIRST_USER_ID_NO_OTP') ?? 1);
  }

  private nowUtc(): Date {
    return new Date();
  }

  private genOtpCode(): string {
    return String(randomInt(0, 1_000_000)).padStart(6, '0');
  }

  private hashCode(code: string): string {
    return createHash('sha256').update(this.OTP_PEPPER + code, 'utf8').digest('hex');
  }

  private otpExpiry(): Date {
    return DateTime.utc().plus({ minutes: this.OTP_TTL_MINUTES }).toJSDate();
  }

  private toLowerRole(role: any): string {
    return String(role ?? '').toLowerCase();
  }

  private issueJwt(user: any) {
    const roleLower = this.toLowerRole(user.role);
    // 24h expiry
    return this.jwt.sign(
      { user_id: user.id, username: user.username, role: roleLower },
      { expiresIn: '24h' },
    );
  }

  // -----------------------
  // Bus assignment helpers
  // -----------------------
  // Mimics _today_bus_for_pao using Asia/Manila day bounds
  async todayBusForPao(userId: number): Promise<number | null> {
    const mnl = DateTime.now().setZone('Asia/Manila');
    const startUtc = mnl.startOf('day').toUTC().toJSDate();
    const endUtc = mnl.plus({ days: 1 }).startOf('day').toUTC().toJSDate();

    const row = await this.prisma.pao_assignments.findFirst({
  where: {
    user_id: userId,
    service_date: { gte: startUtc, lt: endUtc },
  },
  select: { bus_id: true },
  orderBy: { id: 'desc' },
});


    return row?.bus_id ?? null;
  }

  // Mimics resolve_pao_bus_for_today
  async resolvePaoBusForToday(userId: number): Promise<{ busId: number | null; source: string }> {
    const todayMnl = DateTime.now().setZone('Asia/Manila').toISODate(); // "YYYY-MM-DD"
    // If your column is DATE (not DATETIME), use equals: new Date(todayMnl)
    // If DATETIME, use bounds as in todayBusForPao. We'll do bounds to be safe.
    const mnl = DateTime.fromISO(todayMnl, { zone: 'Asia/Manila' });
    const startUtc = mnl.startOf('day').toUTC().toJSDate();
    const endUtc = mnl.plus({ days: 1 }).startOf('day').toUTC().toJSDate();

  const pa = await this.prisma.pao_assignments.findFirst({
  where: { user_id: userId, service_date: { gte: startUtc, lt: endUtc } },
  select: { bus_id: true },
  orderBy: { id: 'desc' },
});

    if (pa?.bus_id) return { busId: pa.bus_id, source: 'pao_assignments' };

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { assigned_bus_id: true },
    });

    if (user?.assigned_bus_id) return { busId: user.assigned_bus_id, source: 'static' };

    return { busId: null, source: 'none' };
  }

  // -----------------------
  // Device token register (same logic as Flask)
  // -----------------------
  async upsertDeviceToken(args: { userId: number; token: string; platform?: string }) {
    if (!args.token) return;

    const existing = await this.prisma.deviceToken.findFirst({
      where: { token: args.token },
      select: { id: true, user_id: true, platform: true },
    });

    if (existing) {
      const changed =
        existing.user_id !== args.userId || (!!args.platform && existing.platform !== args.platform);

      if (changed) {
        await this.prisma.deviceToken.update({
          where: { id: existing.id },
          data: { user_id: args.userId, platform: args.platform ?? existing.platform },
        });
      }
    } else {
      await this.prisma.deviceToken.create({
        data: { user_id: args.userId, token: args.token, platform: args.platform ?? '' },
      });
    }
  }

  // -----------------------
  // OTP create+email (transaction-safe-ish)
  // -----------------------
  async createAndEmailOtp(user: any, purpose: 'signup' | 'login' | 'reset'): Promise<string> {
    const code = this.genOtpCode();
    const created = await this.prisma.userOtp.create({
      data: {
        user_id: user.id,
        channel: 'email',
        destination: user.email,
        purpose,
        code_hash: this.hashCode(code),
        expires_at: this.otpExpiry(),
        attempts: 0,
      },
      select: { id: true },
    });

    if (this.OTP_DEV_MODE) {
      // keep record; mimic your DEV log behavior
      // eslint-disable-next-line no-console
      console.warn('[DEV_OTP]', { userId: user.id, purpose, code });
      return code;
    }

    try {
      const subj =
        purpose === 'signup'
          ? 'Verify your email'
          : purpose === 'reset'
            ? 'Password reset code'
            : 'Your verification code';

      const heading =
        purpose === 'signup'
          ? 'Verify your email'
          : purpose === 'reset'
            ? 'Reset your password'
            : 'Verify your sign-in';

      const html = `
        <div style="font-family:system-ui,Segoe UI,Roboto,Arial">
          <h2>${heading}</h2>
          <p>Your one-time code is:</p>
          <div style="font-size:24px;font-weight:700;letter-spacing:3px">${code}</div>
          <p>This code expires in ${this.OTP_TTL_MINUTES} minutes.</p>
        </div>
      `;

      await this.email.sendEmail({
        to: user.email,
        subject: subj,
        html,
        text: `Your code is ${code}`,
      });

      return code;
    } catch (e) {
      // remove OTP row so cooldown doesn't trigger (matches your rollback intent)
      await this.prisma.userOtp.delete({ where: { id: created.id } }).catch(() => undefined);
      throw e;
    }
  }

  private safeCompareHex(a: string, b: string): boolean {
    const aa = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (aa.length !== bb.length) return false;
    return timingSafeEqual(aa, bb);
  }

  // -----------------------
  // Endpoints logic
  // -----------------------
  ping() {
    return { ok: true, ts: Date.now() / 1000 };
  }

  async meFromTokenPayload(payload: any) {
    const uid = Number(payload?.user_id);
    if (!uid) return null;

    const u = await this.prisma.user.findUnique({
      where: { id: uid },
      select: {
        id: true,
        email: true,
        first_name: true,
        last_name: true,
        role: true,
        assigned_bus_id: true,
        email_verified_at: true,
      },
    });
    if (!u) return null;

    return {
      id: u.id,
      email: u.email ?? null,
      first_name: u.first_name ?? '',
      last_name: u.last_name ?? '',
      role: u.role ?? null,
      assigned_bus_id: u.assigned_bus_id ?? null,
      emailVerified: !!u.email_verified_at,
    };
  }

  async signup(input: {
    firstName: string;
    lastName: string;
    email?: string;
    username: string;
    phoneNumber: string;
    password: string;
  }) {
    const email = (input.email ?? '').trim().toLowerCase() || null;

    // uniqueness checks like Flask (username OR phone OR email)
    const existing = await this.prisma.users.findFirst({
      where: {
        OR: [
          { username: input.username.trim() },
          { phone_number: input.phoneNumber },
          ...(email ? [{ email }] : []),
        ],
      },
      select: { id: true },
    });

    if (existing) {
      return { status: 409, body: { error: 'Username, phone or email already exists' } };
    }

    const password_hash = await bcrypt.hash(input.password, 10);

    const user = await this.prisma.user.create({
      data: {
        first_name: input.firstName.trim(),
        last_name: input.lastName.trim(),
        username: input.username.trim(),
        phone_number: input.phoneNumber,
        email,
        role: 'commuter',
        password_hash,
      },
      select: {
        id: true,
        username: true,
        first_name: true,
        last_name: true,
        phone_number: true,
        email: true,
        role: true,
        email_verified_at: true,
      },
    });

    // Create+send signup OTP if email present (non-blocking like Flask)
    if (user.email) {
      this.createAndEmailOtp(user, 'signup').catch((err) => {
        // eslint-disable-next-line no-console
        console.error('Failed to send/create signup OTP', err);
      });
    }

    return {
      status: 201,
      body: {
        message: user.email ? 'User registered successfully. Verification code sent.' : 'User registered successfully',
        userId: user.id,
        email: user.email,
        role: user.role,
        user: {
          id: user.id,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          phoneNumber: user.phone_number,
          email: user.email,
          emailVerified: !!user.email_verified_at,
        },
      },
    };
  }

  async login(input: { username: string; password: string; expoPushToken?: string; platform?: string }) {
    const user = await this.prisma.users.findFirst({
      where: { username: input.username },
      select: {
        id: true,
        username: true,
        role: true,
        first_name: true,
        last_name: true,
        assigned_bus_id: true,
        password_hash: true,
        phone_number: true,
        email: true,
        email_verified_at: true,
      },
    });

    if (!user || !(await bcrypt.compare(input.password, user.password_hash))) {
      return { status: 401, body: { error: 'Invalid username or password' } };
    }

    const roleLower = this.toLowerRole(user.role);

    // PAO must have a bus today
    let busId: number | null = null;
    let busSource: 'none' | 'static' | 'pao_assignments' = 'none';

    const legacyBus = user.assigned_bus_id ? Number(user.assigned_bus_id) : null;

    if (roleLower === 'pao') {
      if (legacyBus) {
        busId = legacyBus;
        busSource = 'static';
      } else {
        busId = await this.todayBusForPao(users.id).catch(() => null);
        if (busId) busSource = 'pao_assignments';
      }

      if (!busId) {
        return {
          status: 403,
          body: { error: 'You are not assigned to a bus today. Please contact your manager.' },
        };
      }
    } else if (roleLower === 'driver') {
      busId = legacyBus;
      busSource = busId ? 'static' : 'none';
    }

    const token = this.issueJwt(user);

    // Optional push-token registration
    if (input.expoPushToken?.trim()) {
      await this.upsertDeviceToken({
        userId: user.id,
        token: input.expoPushToken.trim(),
        platform: input.platform?.trim(),
      });
    }

    return {
      status: 200,
      body: {
        message: 'Login successful',
        token,
        role: user.role,
        busId: roleLower === 'pao' || roleLower === 'driver' ? busId : null,
        busSource,
        user: {
          id: user.id,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          phoneNumber: user.phone_number,
          email: user.email,
          emailVerified: !!user.email_verified_at,
        },
      },
    };
  }

  async loginVerifyOtp(input: {
    username?: string;
    email?: string;
    code: string;
    expoPushToken?: string;
    platform?: string;
  }) {
    const ident = (input.username ?? '').trim() || (input.email ?? '').trim().toLowerCase();
    const code = input.code.trim();

    const user = await this.prisma.user.findFirst({
      where: { OR: [{ username: ident }, { email: ident }] },
      select: {
        id: true,
        username: true,
        role: true,
        first_name: true,
        last_name: true,
        assigned_bus_id: true,
        phone_number: true,
        email: true,
        email_verified_at: true,
      },
    });

    if (!user) return { status: 404, body: { error: 'User not found' } };

    const row = await this.prisma.userOtp.findFirst({
      where: { user_id: user.id, purpose: 'login', channel: 'email' },
      orderBy: { id: 'desc' },
    });

    if (!row) return { status: 404, body: { error: 'No pending code. Please request a new one.' } };

    if ((row.attempts ?? 0) >= this.OTP_MAX_ATTEMPTS) {
      return { status: 429, body: { error: 'Too many attempts. Please request a new code.' } };
    }

    const expiresAt = row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at as any);
    if (Date.now() > expiresAt.getTime()) {
      return { status: 410, body: { error: 'Code expired. Please request a new code.' } };
    }

    const ok = this.safeCompareHex(String(row.code_hash), this.hashCode(code));
    if (!ok) {
      await this.prisma.userOtp.update({
        where: { id: row.id },
        data: { attempts: (row.attempts ?? 0) + 1 },
      });
      return { status: 401, body: { error: 'Invalid code' } };
    }

    // consume OTP
    await this.prisma.userOtp.delete({ where: { id: row.id } }).catch(() => undefined);

    // bus logic like /login
    const roleLower = this.toLowerRole(user.role);
    let busId: number | null = null;
    let busSource: 'none' | 'static' | 'pao_assignments' = 'none';

    const legacyBus = user.assigned_bus_id ? Number(user.assigned_bus_id) : null;

    if (roleLower === 'pao') {
      if (legacyBus) {
        busId = legacyBus;
        busSource = 'static';
      } else {
        busId = await this.todayBusForPao(user.id).catch(() => null);
        if (busId) busSource = 'pao_assignments';
      }
      if (!busId) {
        return {
          status: 403,
          body: { error: 'You are not assigned to a bus today. Please contact your manager.' },
        };
      }
    } else if (roleLower === 'driver') {
      busId = legacyBus;
      busSource = busId ? 'static' : 'none';
    }

    const token = this.issueJwt(user);

    // Optional push-token registration
    if (input.expoPushToken?.trim()) {
      await this.upsertDeviceToken({
        userId: user.id,
        token: input.expoPushToken.trim(),
        platform: input.platform?.trim(),
      });
    }

    return {
      status: 200,
      body: {
        message: 'Login successful',
        token,
        role: user.role,
        busId: roleLower === 'pao' || roleLower === 'driver' ? busId : null,
        busSource,
        user: {
          id: user.id,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          phoneNumber: user.phone_number,
          email: user.email,
          emailVerified: !!user.email_verified_at,
        },
      },
    };
  }

  async sessionCheck(payload: any) {
    const role = this.toLowerRole(payload?.role);
    if (role !== 'pao') return { status: 403, body: { error: 'Forbidden' } };

    const userId = Number(payload?.user_id);
    if (!userId) return { status: 401, body: { error: 'UNAUTHENTICATED' } };

    const { busId, source } = await this.resolvePaoBusForToday(userId);
    return { status: 200, body: { ok: true, busId, busSource: source } };
  }

  async verifyToken(payload: any) {
    const userId = Number(payload?.user_id);
    if (!userId) return { status: 401, body: { error: 'No token provided' } };

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true, role: true },
    });

    if (!user) return { status: 401, body: { error: 'User not found' } };

    return { status: 200, body: { valid: true, user } };
  }

  async resetPasswordByUsernamePhone(input: { username: string; phoneNumber: string; newPassword: string }) {
    const user = await this.prisma.user.findFirst({
      where: { username: input.username.trim(), phone_number: input.phoneNumber, role: 'commuter' },
      select: { id: true },
    });

    if (!user) return { status: 404, body: { error: 'Username and phone number do not match' } };

    const password_hash = await bcrypt.hash(input.newPassword, 10);
    await this.prisma.user.update({ where: { id: user.id }, data: { password_hash } });

    return { status: 200, body: { message: 'Password updated successfully' } };
  }

  async checkUsernamePhone(input: { username?: string; phoneNumber?: string }) {
    const username = (input.username ?? '').trim();
    const phone = (input.phoneNumber ?? '').trim();

    const digits = phone.replace(/\D/g, '');

    let usernameExists = false;
    let phoneExists = false;
    let pairMatchCommuter = false;
    let roleOfUsername: string | null = null;

    if (username) {
      const row = await this.prisma.user.findFirst({
        where: { username },
        select: { role: true },
      });
      if (row) {
        usernameExists = true;
        roleOfUsername = row.role ?? null;
      }
    }

    if (digits) {
      const row = await this.prisma.user.findFirst({ where: { phone_number: digits }, select: { id: true } });
      phoneExists = !!row;
    }

    if (username && digits) {
      const row = await this.prisma.user.findFirst({
        where: { username, phone_number: digits, role: 'commuter' },
        select: { id: true },
      });
      pairMatchCommuter = !!row;
    }

    return {
      status: 200,
      body: {
        usernameExists,
        phoneExists,
        match: pairMatchCommuter,
        roleOfUsername,
        resetAllowed: roleOfUsername === 'commuter',
      },
    };
  }

  private coercePurpose(purposeRaw: any): 'signup' | 'login' | 'reset' | null {
    const p = String(purposeRaw ?? 'signup').trim().toLowerCase();
    const alias: Record<string, 'reset'> = {
      forgot: 'reset',
      'forgot-password': 'reset',
      password_reset: 'reset',
      'password-reset': 'reset',
    };
    const norm = alias[p] ?? (p as any);
    return norm === 'signup' || norm === 'login' || norm === 'reset' ? norm : null;
  }

  async otpSend(input: { purpose?: string; username?: string; email?: string; to?: string }) {
    const purpose = this.coercePurpose(input.purpose);
    const ident = (input.username ?? '').trim() || (input.email ?? '').trim().toLowerCase() || (input.to ?? '').trim().toLowerCase();

    if (!purpose) return { status: 400, body: { error: 'Invalid purpose; use signup, login, or reset' } };
    if (!ident) return { status: 400, body: { error: 'Provide username or email' } };

    const user = await this.prisma.user.findFirst({
      where: { OR: [{ username: ident }, { email: ident }] },
      select: { id: true, role: true, email: true },
    });

    if (!user || !user.email) return { status: 404, body: { error: 'User/email not found' } };

    const roleLower = this.toLowerRole(user.role);

    if (purpose === 'reset' && roleLower !== 'commuter') {
      return { status: 400, body: { error: 'Password reset via email is only available for commuter accounts' } };
    }

    // Cooldown
    const last = await this.prisma.userOtp.findFirst({
      where: { user_id: user.id, purpose, channel: 'email' },
      orderBy: { id: 'desc' },
      select: { created_at: true },
    });

    if (last?.created_at) {
      const lastTs = new Date(last.created_at as any).getTime();
      const sinceSec = (Date.now() - lastTs) / 1000;
      const remaining = Math.max(0, Math.floor(this.OTP_RESEND_COOLDOWN_SEC - sinceSec));
      if (remaining > 0) {
        return { status: 429, body: { error: `Please wait ${remaining}s before requesting a new code` } };
      }
    }

    try {
      const full = await this.prisma.user.findUnique({ where: { id: user.id } });
      await this.createAndEmailOtp(full, purpose);
    } catch {
      return { status: 500, body: { error: 'Unable to send OTP right now' } };
    }

    return { status: 200, body: { message: 'OTP sent' } };
  }

  async otpVerifySignup(input: { username?: string; email?: string; code: string; expoPushToken?: string; platform?: string }) {
    const ident = (input.username ?? '').trim() || (input.email ?? '').trim().toLowerCase();
    const code = input.code.trim();

    const user = await this.prisma.user.findFirst({
      where: { OR: [{ username: ident }, { email: ident }] },
      select: {
        id: true,
        username: true,
        role: true,
        first_name: true,
        last_name: true,
        phone_number: true,
        email: true,
        email_verified_at: true,
        assigned_bus_id: true,
      },
    });

    if (!user || !user.email) return { status: 404, body: { error: 'User/email not found' } };

    const row = await this.prisma.userOtp.findFirst({
      where: { user_id: user.id, purpose: 'signup', channel: 'email' },
      orderBy: { id: 'desc' },
    });

    if (!row) return { status: 404, body: { error: 'No pending code. Please request a new one.' } };

    const expiresAt = row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at as any);
    if (Date.now() > expiresAt.getTime()) {
      return { status: 410, body: { error: 'Code expired. Please request a new one.' } };
    }

    const ok = this.safeCompareHex(String(row.code_hash), this.hashCode(code));
    if (!ok) {
      const attempts = (row.attempts ?? 0) + 1;
      await this.prisma.userOtp.update({ where: { id: row.id }, data: { attempts } });
      if (attempts >= this.OTP_MAX_ATTEMPTS) {
        return { status: 429, body: { error: 'Too many attempts. Please request a new code.' } };
      }
      return { status: 401, body: { error: 'Invalid code' } };
    }

    // Mark verified + consume OTP
    await this.prisma.user.update({
      where: { id: user.id },
      data: { email_verified_at: this.nowUtc() },
    });
    await this.prisma.userOtp.delete({ where: { id: row.id } }).catch(() => undefined);

    if (input.expoPushToken?.trim()) {
      await this.upsertDeviceToken({
        userId: user.id,
        token: input.expoPushToken.trim(),
        platform: input.platform?.trim(),
      });
    }

    const token = this.issueJwt(user);

    return {
      status: 200,
      body: {
        message: 'Email verified',
        token,
        role: user.role,
        user: {
          id: user.id,
          username: user.username,
          firstName: user.first_name,
          lastName: user.last_name,
          phoneNumber: user.phone_number,
          email: user.email,
          emailVerified: true,
        },
      },
    };
  }

  async otpVerifyReset(input: { email: string; code: string }) {
    const email = input.email.trim().toLowerCase();
    const code = input.code.trim();

    const user = await this.prisma.user.findFirst({
      where: { email },
      select: { id: true, role: true },
    });

    if (!user) return { status: 404, body: { error: 'User/email not found' } };
    if (this.toLowerRole(user.role) !== 'commuter') {
      return { status: 400, body: { error: 'Password reset via email is only available for commuter accounts' } };
    }

    const row = await this.prisma.userOtp.findFirst({
      where: { user_id: user.id, purpose: 'reset', channel: 'email' },
      orderBy: { id: 'desc' },
    });

    if (!row) return { status: 404, body: { error: 'No pending code. Please request a new one.' } };

    const expiresAt = row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at as any);
    if (Date.now() > expiresAt.getTime()) {
      return { status: 410, body: { error: 'Code expired. Please request a new one.' } };
    }

    const ok = this.safeCompareHex(String(row.code_hash), this.hashCode(code));
    if (!ok) {
      const attempts = (row.attempts ?? 0) + 1;
      await this.prisma.userOtp.update({ where: { id: row.id }, data: { attempts } });
      if (attempts >= this.OTP_MAX_ATTEMPTS) {
        return { status: 429, body: { error: 'Too many attempts. Please request a new code.' } };
      }
      return { status: 401, body: { error: 'Invalid code' } };
    }

    return { status: 200, body: { message: 'Code valid' } };
  }

  async resetPasswordEmail(input: { email: string; code: string; newPassword: string }) {
    const email = input.email.trim().toLowerCase();
    const code = input.code.trim();

    const user = await this.prisma.user.findFirst({
      where: { email },
      select: { id: true, role: true },
    });

    if (!user) return { status: 404, body: { error: 'User/email not found' } };
    if (this.toLowerRole(user.role) !== 'commuter') {
      return { status: 400, body: { error: 'Password reset via email is only available for commuter accounts' } };
    }

    const row = await this.prisma.userOtp.findFirst({
      where: { user_id: user.id, purpose: 'reset', channel: 'email' },
      orderBy: { id: 'desc' },
    });

    if (!row) return { status: 404, body: { error: 'No pending code. Please request a new one.' } };

    const expiresAt = row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at as any);
    if (Date.now() > expiresAt.getTime()) {
      return { status: 410, body: { error: 'Code expired. Please request a new one.' } };
    }

    const ok = this.safeCompareHex(String(row.code_hash), this.hashCode(code));
    if (!ok) {
      const attempts = (row.attempts ?? 0) + 1;
      await this.prisma.userOtp.update({ where: { id: row.id }, data: { attempts } });
      if (attempts >= this.OTP_MAX_ATTEMPTS) {
        return { status: 429, body: { error: 'Too many attempts. Please request a new code.' } };
      }
      return { status: 401, body: { error: 'Invalid code' } };
    }

    const password_hash = await bcrypt.hash(input.newPassword, 10);

    await this.prisma.user.update({ where: { id: user.id }, data: { password_hash } });
    await this.prisma.userOtp.delete({ where: { id: row.id } }).catch(() => undefined);

    return { status: 200, body: { message: 'Password updated successfully' } };
  }
}
