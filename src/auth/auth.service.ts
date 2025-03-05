import { BadRequestException, Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import { RegisterUserDto } from './dto/register-user.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { PrismaService } from 'src/prisma/prisma.service';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService
  ) {}

  async registerUser(dto: RegisterUserDto): Promise<any> {
    this.logger.log(`POST: auth/register: Registering user: ${dto.email}`);

    // ✅ Ensure passwords match
    if (dto.password !== dto.passwordconf) {
      throw new BadRequestException('Passwords do not match');
    }

    // ✅ Convert email to lowercase & trim spaces
    dto.email = dto.email.toLowerCase().trim();

    // ✅ Hash password
    const hashedPassword = await bcrypt.hash(dto.password, 10);

    try {
      const { passwordconf, ...userData } = dto;
      userData.password = hashedPassword;

      // ✅ Create user in database
      const newUser = await this.prisma.user.create({
        data: userData,
        select: {
          id: true,
          name: true,
          email: true,
          image: true,
          role: true,
          createdAt: true,
        },
      });

      this.logger.log(`POST: auth/register: User created successfully: ${newUser.email}`);

      return {
        message: 'User registered successfully',
        user: newUser,
        accessToken: this.getJwtToken({ id: newUser.id }),
      };
    } catch (error) {
      if (error.code === 'P2002') {
        this.logger.warn(`POST: auth/register: User already exists: ${dto.email}`);
        throw new BadRequestException('User already exists');
      }
      this.logger.error(`POST: auth/register: Internal error: ${error.message}`);
      throw new InternalServerErrorException('Server error');
    }
  }

  async loginUser(email: string, password: string): Promise<any> {
    this.logger.log(`POST: auth/login: Attempting login for ${email}`);

    let user;
    try {
      user = await this.prisma.user.findUniqueOrThrow({
        where: { email },
        select: {
          id: true,
          name: true,
          email: true,
          password: true,
          image: true,
          role: true,
          createdAt: true,
        },
      });
    } catch (error) {
      this.logger.warn(`POST: auth/login: User not found: ${email}`);
      throw new BadRequestException('Invalid credentials');
    }

    // ✅ Check if password is correct
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      this.logger.warn(`POST: auth/login: Wrong password for ${email}`);
      throw new BadRequestException('Invalid credentials');
    }

    delete user.password; // ✅ Remove password from response

    this.logger.log(`POST: auth/login: User authenticated successfully: ${user.email}`);

    return {
      message: 'Login successful',
      user,
      accessToken: this.getJwtToken({ id: user.id }),
    };
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    this.logger.log(`POST: auth/forgot-password: Password reset requested for ${email}`);

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
        throw new BadRequestException('User not found');
    }

    // ✅ Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // Expires in 1 hour

    // ✅ Store token in the database
    await this.prisma.passwordResetToken.upsert({
        where: { userId: user.id },
        update: { token: resetToken, expiresAt },
        create: { userId: user.id, token: resetToken, expiresAt },
    });

    // ✅ Send email with reset link
    await this.sendResetEmail(user.email, resetToken);

    return { message: 'Reset link sent to your email' };
  }

  private async sendResetEmail(email: string, token: string) {
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: Number(process.env.EMAIL_PORT),
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const resetLink = `http://yourfrontend.com/reset-password?token=${token}`;

    const mailOptions = {
        from: `"ProCare Support" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Reset Your Password',
        html: `
            <p>Hello,</p>
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <a href="${resetLink}" style="color: blue; text-decoration: none;">Reset Password</a>
            <p>If you did not request this, please ignore this email.</p>
            <p>Best regards,<br/>ProCare Team</p>
        `,
    };

    await transporter.sendMail(mailOptions);
    this.logger.log(`POST: auth/forgot-password: Reset email sent to ${email}`);
  }

  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    this.logger.log(`POST: auth/reset-password: Reset password requested`);

    const resetToken = await this.prisma.passwordResetToken.findUnique({
        where: { token },
        include: { user: true },
    });

    if (!resetToken || resetToken.expiresAt < new Date()) {
        throw new BadRequestException('Invalid or expired token');
    }

    // ✅ Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // ✅ Update user's password
    await this.prisma.user.update({
        where: { id: resetToken.userId },
        data: { password: hashedPassword },
    });

    // ✅ Delete the reset token after use
    await this.prisma.passwordResetToken.delete({ where: { token } });

    return { message: 'Password reset successfully' };
  }

  async refreshToken(user: User) {
    this.logger.log(`GET: auth/refresh-token: Refreshing token for ${user.email}`);

    return {
      message: 'Token refreshed successfully',
      user,
      accessToken: this.getJwtToken({ id: user.id }),
    };
  }

  private getJwtToken(payload: JwtPayload): string {
    return this.jwtService.sign(payload, { expiresIn: '1d' }); // ✅ Default expiration time set to 1 day
  }
}
