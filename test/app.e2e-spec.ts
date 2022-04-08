import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as pactum from 'pactum';
import { PrismaService } from '../src/prisma/prisma.service';
import { AppModule } from '../src/app.module';
import { AuthDto } from '../src/auth/dto';

describe('App e2e', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
      }),
    );
    await app.init();
    await app.listen(3033);

    prisma = app.get(PrismaService);
    await prisma.cleanDb();
    pactum.request.setBaseUrl('http://localhost:3033');
  });

  afterAll(() => {
    app.close();
  });

  describe('Auth', () => {
    const dto: AuthDto = {
      email: 'test@example.com',
      password: 'test123',
    };
    describe('signup', () => {
      it('should throw an error if email is empty/invalid', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({
            password: dto.password
          })
          .expectStatus(400);
      })
      it('should throw an error if password is empty/invalid', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({
            email: dto.email
          })
          .expectStatus(400);
      })
      it('should throw an error if no info provided is empty/invalid', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({
          })
          .expectStatus(400);
      })
      it('should signup', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody(dto)
          .expectStatus(201);
      });
    });
    describe('signin', () => {
      it('should throw an error if email is empty/invalid', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({
            password: dto.password
          })
          .expectStatus(400);
      })
      it('should throw an error if password is empty/invalid', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({
            email: dto.email
          })
          .expectStatus(400);
      })
      it('should throw an error if no info provided is empty/invalid', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({
          })
          .expectStatus(400);
      })
      it('should signin', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody(dto)
          .expectStatus(200)
          .stores('userAt', 'access_token')
      });
    });
  });
  describe('User', () => {
    describe('Get me', () => {
      it('should get current user', () => {
        return pactum
        .spec()
        .get('/users/me')
        .withHeaders({
          Authorization: `Bearer $S{userAt}`
        })
        .expectStatus(200)
      })
    });
    describe('Edit user', () => {});
  });
  describe('Bookmarks', () => {
    describe('Create bookmark', () => {});
    describe('Get all bookmarks', () => {});
    describe('Get bookmark by id', () => {});
    describe('Edit bookmark by id', () => {});
    describe('Delete bookmark by id', () => {});
  });
});
