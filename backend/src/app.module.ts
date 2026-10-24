import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AnalyticsController } from './analytics/analytics.controller.js';
import { AuditService } from './audit/audit.service.js';
import { AuthController } from './auth/auth.controller.js';
import { AuthGuard } from './auth/auth.guard.js';
import { CryptoService } from './common/crypto.service.js';
import { DatabaseService } from './db/database.service.js';
import { ProgramsController } from './programs/programs.controller.js';
import { ReportsController } from './reports/reports.controller.js';
import { ReportsService } from './reports/reports.service.js';

// The scaffold's third-party telemetry module (@nestjs/observe) was removed on purpose:
// a vulnerability-disclosure platform must not ship request data to an external SaaS.
@Module({
  controllers: [AuthController, ProgramsController, ReportsController, AnalyticsController],
  providers: [
    DatabaseService,
    CryptoService,
    AuditService,
    ReportsService,
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
export class AppModule {}
