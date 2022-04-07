import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";

@Injectable()
export class AuthService{
  constructor(private prisma: PrismaService) {}
 
  async signup(dto: AuthDto) {
    // generate the password hash 
    const hash = await argon.hash(dto.password)

    // save new user in the db
    try {

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        }
      })
      
      // return saved user
      delete user.hash
      
      return user
    }
    catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        // code 'P2002' refers to a built-in error from prisma stating that the field is not unique 
        if (err.code === 'P2002') {
          throw new ForbiddenException('This email address is already registered',)
        }
      }
      throw err
    }
  }
  
  async signin() {
    return { msg: 'I have signed in'}
  }
  
  login() {}
}