import { describe, it, expect, afterEach } from 'vitest';
import {
  resolveProvider,
  generate,
  generateJSON,
  providerStatus,
  wrapUserInput,
} from '../src/server/llm/index';

afterEach(() => {
  delete process.env.AI_PROVIDER;
  delete process.env.GEMINI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
});

describe('LLM provider resolution', () => {
  it('falls back to local when no keys are configured', () => {
    expect(resolveProvider().id).toBe('local');
    expect(providerStatus().active).toBe('local');
    expect(providerStatus().available).toContain('local');
  });

  it('auto-selects gemini when only its key is present', () => {
    process.env.GEMINI_API_KEY = 'x';
    expect(resolveProvider().id).toBe('gemini');
  });

  it('honors a valid AI_PROVIDER pin', () => {
    process.env.GEMINI_API_KEY = 'x';
    process.env.ANTHROPIC_API_KEY = 'y';
    process.env.AI_PROVIDER = 'gemini';
    expect(resolveProvider().id).toBe('gemini');
  });

  it('ignores a pinned provider that is unavailable', () => {
    process.env.AI_PROVIDER = 'claude'; // no key → unusable
    expect(resolveProvider().id).toBe('local');
  });
});

describe('graceful degradation', () => {
  it('generate() always returns text via local fallback', async () => {
    const r = await generate([{ role: 'user', content: 'مرحبا' }]);
    expect(r.provider).toBe('local');
    expect(r.fallback).toBe(true);
    expect(r.text.length).toBeGreaterThan(0);
  });

  it('generateJSON() uses the supplied domain fallback on failure', async () => {
    const r = await generateJSON('p', 'hint', undefined, () => ({ ok: true }));
    expect(r.fallback).toBe(true);
    expect(r.data).toEqual({ ok: true });
  });
});

describe('prompt-injection boundary', () => {
  it('wraps untrusted text in <user_input> delimiters', () => {
    expect(wrapUserInput('rm -rf /')).toBe('<user_input>\nrm -rf /\n</user_input>');
  });
});
