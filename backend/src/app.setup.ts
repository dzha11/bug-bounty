import { INestApplication } from '@nestjs/common';
import { ZodFilter } from './common/validation.js';
import { config } from './config.js';

export function configureApp(app: INestApplication) {
  app.enableCors({ origin: config.corsOrigin, credentials: false });
  app.useGlobalFilters(new ZodFilter());
  app.use((_req: unknown, res: any, next: () => void) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store'); // confidential vulnerability data must not be cached
    next();
  });
  return app;
}
