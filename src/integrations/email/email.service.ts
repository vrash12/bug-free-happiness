// src/integrations/email/email.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor(private config: ConfigService) {
    // Configure via env (adjust to your provider)
    const host = this.config.get<string>('SMTP_HOST');
    const port = Number(this.config.get<string>('SMTP_PORT') ?? '587');
    const user = this.config.get<string>('SMTP_USER');
    const pass = this.config.get<string>('SMTP_PASS');
    const secure = (this.config.get<string>('SMTP_SECURE') ?? '0') === '1';

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: user && pass ? { user, pass } : undefined,
    });
  }

  async sendEmail(args: { to: string; subject: string; html: string; text?: string }) {
    const from = this.config.get<string>('SMTP_FROM') ?? 'no-reply@onboard.local';
    await this.transporter.sendMail({
      from,
      to: args.to,
      subject: args.subject,
      html: args.html,
      text: args.text,
    });
  }
}
