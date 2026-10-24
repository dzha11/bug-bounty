import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { configureApp } from './app.setup.js';
import { config } from './config.js';
import { DatabaseService } from './db/database.service.js';

async function bootstrap() {
  const app = configureApp(await NestFactory.create(AppModule));
  await app.get(DatabaseService).migrate();
  await app.listen(config.port);
  console.log(`CyberHunt KZ API listening on :${config.port}`);
}

await bootstrap();
