import { Injectable, NotFoundException } from '@nestjs/common';
import { CreatePasswordManagerDto } from './dto/create-passwordManager.dto';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { Task } from './password-manager.entity';
import { User } from 'src/auth/user.entity';
import * as bcrypt from 'bcrypt';
@Injectable()
export class PasswordManagerService {
  constructor(
    @InjectRepository(Task)
    private passwordManagerRepository: Repository<Task>,
  ) {}

  //get task by id

  async getPasswordDetailsById(id: string, user: User): Promise<Task> {
    const found = await this.passwordManagerRepository.findOne({
      where: { id },
    });

    if (!found) {
      throw new NotFoundException(`Task with ID"${id}" not found `);
    }
    return found;
  }

  //add task
  async createPasswordManager(
    createPasswordManagerDto: CreatePasswordManagerDto,
    user: User,
  ): Promise<Task> {
    const { title, password } = createPasswordManagerDto;
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);
    const task = this.passwordManagerRepository.create({
      title,
      password: hashedPassword,
      user,
    });

    try {
      await this.passwordManagerRepository.save(task);
      return task;
    } catch (error) {
      console.log(error);
    }
  }
  //get all task
  async getAllDetails(user: User): Promise<Task[]> {
    return await this.passwordManagerRepository.find({ where: { user } });
  }
  //delete task by id
  async deletePassword(id: string, user: User): Promise<void> {
    const result = await this.passwordManagerRepository.delete({ id, user });
    if (result.affected === 0) {
      throw new NotFoundException(`Task with ID"${id}" not found `);
    }
  }
  //update task by id
  async updatePassword(
    id: string,
    password: string,
    user: User,
  ): Promise<Task> {
    const task = await this.getPasswordDetailsById(id, user);
    task.password = password;
    await this.passwordManagerRepository.save(task);
    return task;
  }
}
