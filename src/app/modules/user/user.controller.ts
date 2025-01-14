import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Query,
  UploadedFile,
} from '@nestjs/common';

import { AuthUser } from '@shared/decorators/auth-user.decorator';
import { UploadFileSingle } from '@shared/decorators/file.decorator';
import { Roles } from '@shared/decorators/roles.decorator';
import { ENUM_FILE_TYPE } from '@shared/enums/file.enum';
import { RoleTypeEnum } from '@shared/enums/role-type.enum';
import { JwtPayload } from '@shared/interfaces/jwt-payload.interface';
import { PaginationPipe } from '@shared/pipes/pagination.pipe';

import { CreateUserDto } from './dtos/create-user.dto';
import { FindUsersDto } from './dtos/find-users.dto';
import { UpdateUserDto } from './dtos/update-user.dto';
import { UserService } from './user.service';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
  ApiBody,
} from '@nestjs/swagger';
// @Controller('users')
// @Roles(RoleTypeEnum.SuperAdmin, RoleTypeEnum.Admin)
// export class UserController {
//   constructor(private readonly service: UserService) {}

//   @Post()
//   async create(@Body() data: CreateUserDto) {
//     return this.service.create(data);
//   }

//   @Get('me')
//   @Roles(RoleTypeEnum.All)
//   async getLoggedinUserDetails(@AuthUser() user: JwtPayload) {
//     return this.service.getLoggedinUserDetails(user);
//   }

//   @Delete('me')
//   @Roles(RoleTypeEnum.All)
//   async deleteLoggedinUserDetails(@AuthUser() user: JwtPayload) {
//     return this.service.deleteLoggedinUserDetails(user);
//   }

//   @UploadFileSingle('file', ENUM_FILE_TYPE.IMAGE)
//   @Post('me/images/upload')
//   @Roles(RoleTypeEnum.All)
//   async uploadLoggedinUserImage(
//     @AuthUser() user: JwtPayload,
//     @UploadedFile() file: Express.Multer.File,
//   ) {
//     return this.service.uploadLoggedinUserImage(user, file);
//   }

//   @Put(':id')
//   async updateById(@Param('id') id: string, @Body() data: UpdateUserDto) {
//     return this.service.updateById(id, data);
//   }

//   @Get()
//   async findAll(@Query(new PaginationPipe()) q: FindUsersDto) {
//     return this.service.findPaginated((<any>q).filter, {
//       ...(<any>q).options,
//     });
//   }

//   @Get(':id')
//   async findById(@Param('id') id: string) {
//     return this.service.findById(id);
//   }

//   @Delete(':id')
//   async deleteById(@Param('id') id: string) {
//     this.service.deleteById(id);
//   }

//   @UploadFileSingle('file', ENUM_FILE_TYPE.IMAGE)
//   @Post(':id/images/upload')
//   async upload(
//     @Param('id') id: string,
//     @UploadedFile() file: Express.Multer.File,
//   ) {
//     return this.service.uploadImage(id, file);
//   }
// }

@Controller('users')
@ApiTags('Users')
@Roles(RoleTypeEnum.SuperAdmin, RoleTypeEnum.Admin)
export class UserController {
  constructor(private readonly service: UserService) {}

  @Post()
  @ApiOperation({ summary: 'Create a user' })
  @ApiResponse({
    status: 201,
    description: 'The user has been successfully created.',
  })
  @ApiBody({ type: CreateUserDto })
  async create(@Body() data: CreateUserDto) {
    return this.service.create(data);
  }

  @Get('me')
  @Roles(RoleTypeEnum.All)
  @ApiOperation({ summary: 'Get logged-in user details' })
  @ApiResponse({
    status: 200,
    description: 'Returns details of the logged-in user.',
  })
  async getLoggedinUserDetails(@AuthUser() user: JwtPayload) {
    console.log('user :::', user);

    return this.service.getLoggedinUserDetails(user);
  }

  @Delete('me')
  @Roles(RoleTypeEnum.All)
  @ApiOperation({ summary: 'Delete logged-in user details' })
  @ApiResponse({
    status: 204,
    description: 'User details have been successfully deleted.',
  })
  async deleteLoggedinUserDetails(@AuthUser() user: JwtPayload) {
    return this.service.deleteLoggedinUserDetails(user);
  }

  @UploadFileSingle('file', ENUM_FILE_TYPE.IMAGE)
  @Post('me/images/upload')
  @Roles(RoleTypeEnum.All)
  @ApiOperation({ summary: 'Upload an image for the logged-in user' })
  @ApiResponse({
    status: 200,
    description: 'Image has been successfully uploaded.',
  })
  async uploadLoggedinUserImage(
    @AuthUser() user: JwtPayload,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return this.service.uploadLoggedinUserImage(user, file);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update a user by ID' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiBody({ type: UpdateUserDto })
  async updateById(@Param('id') id: string, @Body() data: UpdateUserDto) {
    return this.service.updateById(id, data);
  }

  @Get()
  @ApiOperation({ summary: 'Find users with pagination' })
  @ApiResponse({
    status: 200,
    description: 'Returns a list of users with pagination.',
  })
  @ApiQuery({ type: FindUsersDto })
  async findAll(@Query(new PaginationPipe()) q: FindUsersDto) {
    return this.service.findPaginated((<any>q).filter, {
      ...(<any>q).options,
    });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Find a user by ID' })
  @ApiParam({ name: 'id', description: 'User ID' })
  async findById(@Param('id') id: string) {
    return this.service.findById(id);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a user by ID' })
  @ApiParam({ name: 'id', description: 'User ID' })
  async deleteById(@Param('id') id: string) {
    this.service.deleteById(id);
  }

  @UploadFileSingle('file', ENUM_FILE_TYPE.IMAGE)
  @Post(':id/images/upload')
  @ApiOperation({ summary: 'Upload an image for a user by ID' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiResponse({
    status: 200,
    description: 'Image has been successfully uploaded.',
  })
  async upload(
    @Param('id') id: string,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return this.service.uploadImage(id, file);
  }
}
