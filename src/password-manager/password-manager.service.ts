import { Injectable, NotFoundException } from '@nestjs/common';
import { CreatePasswordManagerDto } from './dto/create-passwordManager.dto';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { Task } from './password-manager.entity';
import { User } from 'src/auth/user.entity';
import * as bcrypt from 'bcrypt';
import { createCipheriv, randomBytes, scrypt ,createDecipheriv  } from 'crypto';
import { promisify } from 'util';


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
    const iv = randomBytes(16);
    const encpassword = 'Password used to generate key';
    const key = (await promisify(scrypt)(encpassword, 'salt', 32)) as Buffer;
    const cipher = createCipheriv('aes-256-ctr', key, iv);  
    const { title, password } = createPasswordManagerDto;
    //save encrypted password
    const encryptedPassword = cipher.update (password, 'utf8', 'hex') + cipher.final('hex');
    const task = this.passwordManagerRepository.create({
      title,
      password: encryptedPassword,
      user,
    });
    await this.passwordManagerRepository.save(task);
    console.log(task);
    
    //return decrypted password with task to user
    const decipher = createDecipheriv('aes-256-ctr', key, iv);
    const decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf8') + decipher.final('utf8');
    task.password = decryptedPassword;
    console.log(decryptedPassword);
    
    return task;
  }
  //get all task
  async getAllDetails(user: User): Promise<Task[]> {
    // Retrieve all the tasks belonging to the user
    const tasks = await this.passwordManagerRepository.find({ where: { user } });
  
    // Generate the key and the IV for the decryption process
    const key = (await promisify(scrypt)('Password used to generate key', 'salt', 32)) as Buffer;
    const iv = randomBytes(16);
  
    // Decrypt the passwords of all the tasks
    for (const task of tasks) {
      console.log(typeof(task.password));
      
      const decipher = createDecipheriv('aes-256-ctr', key, iv);
      const decryptedPassword = decipher.update(task.password, 'hex', 'utf8') + decipher.final('utf8');
      task.password = decryptedPassword;
    }
  
    return tasks;
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
    const iv = randomBytes(16);
    const encpassword = 'Password used to generate key';
    const key = (await promisify(scrypt)(encpassword, 'salt', 32)) as Buffer;
    const cipher = createCipheriv('aes-256-ctr', key, iv);
    const encryptedPassword = cipher.update (password, 'utf8', 'hex') + cipher.final('hex');
    const task = await this.getPasswordDetailsById(id, user);
    task.password = encryptedPassword;
    await this.passwordManagerRepository.save(task);

    const decipher = createDecipheriv('aes-256-ctr', key, iv);
    const decryptedPassword = decipher.update (encryptedPassword, 'hex', 'utf8') + decipher.final('utf8');
    task.password = decryptedPassword;
    return task;


  }
}



