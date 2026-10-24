import { ArgumentsHost, BadRequestException, Catch, ExceptionFilter } from '@nestjs/common';
import { ZodError, ZodType } from 'zod';

export function parse<T>(schema: ZodType<T>, body: unknown): T {
  const r = schema.safeParse(body);
  if (!r.success) {
    throw new BadRequestException({
      message: 'Validation failed',
      issues: r.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }
  return r.data;
}

@Catch(ZodError)
export class ZodFilter implements ExceptionFilter {
  catch(e: ZodError, host: ArgumentsHost) {
    host.switchToHttp().getResponse().status(400).json({ message: 'Validation failed', issues: e.issues });
  }
}
