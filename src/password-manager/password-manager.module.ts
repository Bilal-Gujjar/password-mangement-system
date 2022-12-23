import { Module } from '@nestjs/common';
import { PasswordManagerService } from './password-manager.service';
import { PasswordManagerController } from './password-manager.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Task } from './password-manager.entity';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [TypeOrmModule.forFeature([Task]), AuthModule],
  providers: [PasswordManagerService],
  controllers: [PasswordManagerController],
})
export class PasswordManagerModule {}
