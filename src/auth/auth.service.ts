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
  
  async signin(dto: AuthDto) {

    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email,}
    })

    // if user does not exist, throw exception
    if (!user) throw new ForbiddenException('Email does not exist',)

    // if user exists, compare password
    const pwMatches = await argon.verify(user.hash, dto.password)

    // if password is incorrect, throw exception
    if (!pwMatches) throw new ForbiddenException('Password incorrect')

    //when successful, return user
    delete user.hash

    return user
  }
  
  login() {}
}