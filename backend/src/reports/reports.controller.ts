import { Body, Controller, Get, HttpCode, Inject, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { CurrentUser, Roles } from '../auth/auth.guard.js';
import type { TokenPayload } from '../common/security.js';
import { parse } from '../common/validation.js';
import { STATUSES } from './workflow.js';
import { ReportsService } from './reports.service.js';

const SubmitSchema = z.object({
  programId: z.number().int().positive(),
  vulnType: z.enum([
    'SQL_INJECTION', 'XSS', 'IDOR', 'BROKEN_AUTHENTICATION', 'SSRF', 'RCE', 'CSRF',
    'INFORMATION_DISCLOSURE', 'MISCONFIGURATION', 'BUSINESS_LOGIC', 'OTHER',
  ]),
  title: z.string().min(5).max(200),
  target: z.string().min(3).max(500),
  description: z.string().min(20).max(20000),
  steps: z.string().min(10).max(20000),
  impact: z.string().min(10).max(5000),
  poc: z.string().max(50000).optional(),
  cvssVector: z.string().max(60),
});

const TransitionSchema = z.object({
  to: z.enum(STATUSES),
  comment: z.string().max(2000).optional(),
  duplicateOf: z.string().max(40).optional(),
});

const AssessSchema = z.object({
  cvssVector: z.string().max(60),
  realImpact: z.enum(['NONE', 'LIMITED', 'SIGNIFICANT', 'SEVERE']),
  exploitability: z.enum(['THEORETICAL', 'CONDITIONAL_POC', 'RELIABLE_POC', 'TRIVIAL_AUTOMATABLE']),
  scale: z.enum(['SINGLE_USER', 'USER_SUBSET', 'ALL_USERS', 'CROSS_SYSTEM']),
  quality: z.object({
    reproducible: z.boolean(),
    clearSteps: z.boolean(),
    workingPoc: z.boolean(),
    impactExplained: z.boolean(),
    remediationAdvice: z.boolean(),
  }),
  finalTier: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'EXCEPTIONAL']).optional(),
  overrideReason: z.string().max(2000).optional(),
});

const RemediationSchema = z.object({
  responsible: z.string().min(2).max(200),
  deadline: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
});
const FixedSchema = z.object({ fixNote: z.string().min(5).max(5000) });

@Controller('reports')
export class ReportsController {
  constructor(@Inject(ReportsService) private readonly reports: ReportsService) {}

  @Roles('RESEARCHER')
  @Post()
  submit(@CurrentUser() u: TokenPayload, @Body() body: unknown) {
    return this.reports.submit(u, parse(SubmitSchema, body));
  }

  @Get()
  list(@CurrentUser() u: TokenPayload) {
    return this.reports.list(u);
  }

  @Get(':id')
  get(@CurrentUser() u: TokenPayload, @Param('id') id: string) {
    return this.reports.get(u, id);
  }

  @Post(':id/transition')
  @HttpCode(200)
  transition(@CurrentUser() u: TokenPayload, @Param('id') id: string, @Body() body: unknown) {
    const b = parse(TransitionSchema, body);
    return this.reports.transition(u, id, b.to, b.comment, b.duplicateOf);
  }

  @Roles('OPERATOR')
  @Post(':id/assess')
  @HttpCode(200)
  assess(@CurrentUser() u: TokenPayload, @Param('id') id: string, @Body() body: unknown) {
    return this.reports.assess(u, id, parse(AssessSchema, body));
  }

  @Roles('AGENCY')
  @Post(':id/remediation')
  @HttpCode(200)
  remediation(@CurrentUser() u: TokenPayload, @Param('id') id: string, @Body() body: unknown) {
    const b = parse(RemediationSchema, body);
    return this.reports.startRemediation(u, id, b.responsible, b.deadline);
  }

  @Roles('AGENCY')
  @Post(':id/remediation/fixed')
  @HttpCode(200)
  fixed(@CurrentUser() u: TokenPayload, @Param('id') id: string, @Body() body: unknown) {
    return this.reports.markFixed(u, id, parse(FixedSchema, body).fixNote);
  }
}
