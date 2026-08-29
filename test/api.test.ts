import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server';

let app: Express;

beforeAll(async () => {
  app = await createApp();
});

afterEach(() => {
  delete process.env.APP_ACCESS_KEY;
});

describe('GET /api/health', () => {
  it('is public and leaks no internal details', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body).not.toHaveProperty('hasApiKey');
    expect(res.body).not.toHaveProperty('version');
  });
});

describe('API key auth middleware', () => {
  it('allows all /api routes when APP_ACCESS_KEY is unset', async () => {
    const res = await request(app).get('/api/projects');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('rejects /api routes without a matching x-api-key when APP_ACCESS_KEY is set', async () => {
    process.env.APP_ACCESS_KEY = 'secret-test-key';
    const res = await request(app).get('/api/projects');
    expect(res.status).toBe(401);
  });

  it('accepts requests carrying the correct x-api-key header', async () => {
    process.env.APP_ACCESS_KEY = 'secret-test-key';
    const res = await request(app)
      .get('/api/projects')
      .set('x-api-key', 'secret-test-key');
    expect(res.status).toBe(200);
  });

  it('keeps /api/health public even when APP_ACCESS_KEY is set', async () => {
    process.env.APP_ACCESS_KEY = 'secret-test-key';
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
  });
});

describe('input validation', () => {
  it('rejects an over-long userPrompt on run-mission', async () => {
    const res = await request(app)
      .post('/api/orchestrator/run-mission')
      .send({ userPrompt: 'x'.repeat(5000), target: '192.168.1.50' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });
});

describe('security gateway', () => {
  it('denies an explicitly out-of-scope target', async () => {
    const res = await request(app)
      .post('/api/gateway/check')
      .send({ target: 'production-billing.target-corp.com', toolName: 'nmap' });
    expect(res.status).toBe(200);
    expect(res.body.isAllowed).toBe(false);
    expect(res.body.scopeValidation).toBe('OUT_OF_SCOPE');
  });

  it('allows an in-scope lab target', async () => {
    const res = await request(app)
      .post('/api/gateway/check')
      .send({ target: '192.168.1.50', toolName: 'nmap' });
    expect(res.status).toBe(200);
    expect(res.body.isAllowed).toBe(true);
  });
});
