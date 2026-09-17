import { describe, it, expect, beforeAll, afterEach, beforeEach } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server';
import { setRunMode, DEFAULT_RUN_MODE, RUN_MODES } from '../src/server/runtime/index';

let app: Express;

beforeAll(async () => {
  app = await createApp();
});

afterEach(() => {
  delete process.env.APP_ACCESS_KEY;
});

beforeEach(() => {
  setRunMode(DEFAULT_RUN_MODE);
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

describe('run mode API', () => {
  it('reports the current mode, the default and the gates of every mode', async () => {
    const res = await request(app).get('/api/runtime/mode');
    expect(res.status).toBe(200);
    expect(res.body.current).toBe(DEFAULT_RUN_MODE);
    expect(res.body.default).toBe(DEFAULT_RUN_MODE);
    for (const mode of RUN_MODES) {
      expect(res.body.modes[mode]).toHaveProperty('purpose');
      expect(typeof res.body.modes[mode].egressAllowed).toBe('boolean');
    }
  });

  it('switches the mode with a valid value', async () => {
    const res = await request(app).post('/api/runtime/mode').send({ mode: 'pair' });
    expect(res.status).toBe(200);
    expect(res.body.current).toBe('pair');
    expect(res.body.previous).toBe(DEFAULT_RUN_MODE);
    expect(res.body.gate.approvalEveryStep).toBe(true);
  });

  it('rejects an invalid mode with a 400 and does not change state', async () => {
    const before = await request(app).get('/api/runtime/mode');
    const res = await request(app).post('/api/runtime/mode').send({ mode: 'chaotic_evil' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
    const after = await request(app).get('/api/runtime/mode');
    expect(after.body.current).toBe(before.body.current);
  });

  it('rejects a missing mode value', async () => {
    const res = await request(app).post('/api/runtime/mode').send({});
    expect(res.status).toBe(400);
  });
});

describe('agent catalog API', () => {
  it('reports fifty agents with live statuses and an honest overview', async () => {
    const res = await request(app).get('/api/catalog');
    expect(res.status).toBe(200);
    expect(res.body.overview.count).toBe(50);
    expect(res.body.overview.implemented).toBe(7);
    expect(res.body.overview.catalogOnly).toBe(43);
    expect(res.body.agents).toHaveLength(50);
    for (const a of res.body.agents) {
      expect(['IMPLEMENTED', 'PARTIAL', 'CATALOG_ONLY']).toContain(a.status);
      if (a.status !== 'IMPLEMENTED') expect(typeof a.reason).toBe('string');
    }
    const implemented = res.body.agents.filter((a: { status: string }) => a.status === 'IMPLEMENTED');
    expect(new Set(implemented.map((a: { id: string }) => a.id)).size).toBe(7);
  });
});

describe('security gateway', () => {  it('denies an explicitly out-of-scope target', async () => {
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
