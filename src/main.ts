import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { Logger, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe());

  app.enableCors();
  const logger = new Logger('bootstrap');
  const port = process.env.PORT || 8000;

  await app.listen(port);
  logger.log(`Application listening on port ${port}`);
}
bootstrap();
