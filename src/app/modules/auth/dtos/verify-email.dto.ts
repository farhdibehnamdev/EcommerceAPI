import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class EmailVerificationDto {
  @ApiProperty({
    type: String,
    required: true,
    description: 'Email Token',
  })
  @IsString()
  @IsNotEmpty()
  readonly token: string;
}
