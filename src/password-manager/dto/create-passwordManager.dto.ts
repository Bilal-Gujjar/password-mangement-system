import { IsNotEmpty } from 'class-validator';

export class CreatePasswordManagerDto {
  @IsNotEmpty()
  title: string;
  @IsNotEmpty()
  password: string;
}
