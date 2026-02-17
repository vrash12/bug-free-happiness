// src/modules/auth/auth.dto.ts
import { IsEmail, IsOptional, IsString, Length, Matches } from 'class-validator';

export class SignupDto {
  @IsString() firstName!: string;
  @IsString() lastName!: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsString() username!: string;

  // PH: 09xxxxxxxxx
  @IsString()
  @Matches(/^09\d{9}$/)
  phoneNumber!: string;

  @IsString()
  @Length(6, 255)
  password!: string;
}

export class LoginDto {
  @IsString() username!: string;
  @IsString() password!: string;

  @IsOptional() @IsString() expoPushToken?: string;
  @IsOptional() @IsString() platform?: string;
}

export class LoginVerifyOtpDto {
  @IsOptional() @IsString() username?: string;
  @IsOptional() @IsEmail() email?: string;

  @IsString() @Matches(/^\d{6}$/) code!: string;

  @IsOptional() @IsString() expoPushToken?: string;
  @IsOptional() @IsString() platform?: string;
}

export class ResetPasswordByUsernamePhoneDto {
  @IsString() username!: string;
  @IsString() @Matches(/^09\d{9}$/) phoneNumber!: string;
  @IsString() @Length(6, 255) newPassword!: string;
}

export class CheckUsernamePhoneDto {
  @IsOptional() @IsString() username?: string;
  @IsOptional() @IsString() phoneNumber?: string;
}

export class OtpSendDto {
  @IsOptional() @IsString() purpose?: string; // signup|login|reset (+aliases)
  @IsOptional() @IsString() username?: string;
  @IsOptional() @IsEmail() email?: string;
  @IsOptional() @IsEmail() to?: string;
}

export class OtpVerifySignupDto {
  @IsOptional() @IsString() username?: string;
  @IsOptional() @IsEmail() email?: string;
  @IsString() @Matches(/^\d{6}$/) code!: string;

  @IsOptional() @IsString() expoPushToken?: string;
  @IsOptional() @IsString() platform?: string;
}

export class OtpVerifyResetDto {
  @IsEmail() email!: string;
  @IsString() @Matches(/^\d{6}$/) code!: string;
}

export class ResetPasswordEmailDto {
  @IsEmail() email!: string;
  @IsString() @Matches(/^\d{6}$/) code!: string;
  @IsString() @Length(6, 255) newPassword!: string;
}
