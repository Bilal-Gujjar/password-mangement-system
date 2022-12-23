import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { PasswordManagerService } from './password-manager.service';
import { Task } from './password.model';
import { CreatePasswordManagerDto } from './dto/create-passwordManager.dto';
import { AuthGuard } from '@nestjs/passport';
import { GetUser } from 'src/auth/get-user.decorator';
import { User } from 'src/auth/user.entity';

@Controller('auth')
@UseGuards(AuthGuard())
export class PasswordManagerController {
  constructor(private passwordManagerService: PasswordManagerService) {}

  @Get('/:id')
  getPasswordDetailsById(@Param('id') id: string, user: User): Promise<Task> {
    return this.passwordManagerService.getPasswordDetailsById(id, user);
  }

  @Post()
  createPasswordManager(
    @Body() createPasswordManagerDto: CreatePasswordManagerDto,
    @GetUser() user: User,
  ): Promise<Task> {
    return this.passwordManagerService.createPasswordManager(
      createPasswordManagerDto,
      user,
    );
  }

  //resticting the user to see only his task
  @Get()
  getAllDetails(@GetUser() user: User): Promise<Task[]> {
    return this.passwordManagerService.getAllDetails(user);
  }
  //delete task by id
  @Delete('/:id')
  deleteDetails(@Param('id') id: string, @GetUser() user: User): Promise<void> {
    return this.passwordManagerService.deletePassword(id, user);
  }
  //update task by id
  @Patch('/:id/password')
  upadtePassword(
    @Param('id') id: string,
    @Body('password') password: string,
    @GetUser() user: User,
  ): Promise<Task> {
    return this.passwordManagerService.updatePassword(id, password, user);
  }
}
