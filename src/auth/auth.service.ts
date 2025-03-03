import { BadRequestException, Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
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
