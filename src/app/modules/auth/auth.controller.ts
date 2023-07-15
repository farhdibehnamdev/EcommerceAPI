import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { AuthUser } from '@shared/decorators/auth-user.decorator';
import { AllowAnonymous } from '@shared/decorators/public.decorator';
import { Roles } from '@shared/decorators/roles.decorator';
import { RoleTypeEnum } from '@shared/enums/role-type.enum';
import { JwtPayload } from '@shared/interfaces/jwt-payload.interface';

import { AuthService } from './auth.service';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { LoginDto } from './dtos/login.dto';
import { LogoutDto } from './dtos/logout.dto';
import { RegisterDto } from './dtos/register.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { TokenDto } from './dtos/token.dto';

@Roles(RoleTypeEnum.All)
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @AllowAnonymous()
  async login(@Body() loginDto: LoginDto) {
    console.log('here');
    return this.authService.login(loginDto);
  }

  @Post('register')
  @AllowAnonymous()
  async register(@Body() registerUserDto: RegisterDto) {
    return this.authService.register(registerUserDto);
  }

  @Post('logout')
  async logout(@Body() logoutDto: LogoutDto) {
    return this.authService.logout(logoutDto);
  }

  @Post('generate/tokens')
  async generateTokens(@Body() tokenDto: TokenDto) {
    return this.authService.generateTokens(tokenDto);
  }

  @Post('forgot-password')
  @AllowAnonymous()
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Post('reset-password')
  @AllowAnonymous()
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Query('token') token: string,
  ) {
    return this.authService.resetPassword(resetPasswordDto, token);
  }

  @Get('verify-email')
  @AllowAnonymous()
  async verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  @Post('send-verification-email')
  async sendVerificationEmail(@AuthUser() user: JwtPayload) {
    return this.authService.sendVerificationEmail(user);
  }
}