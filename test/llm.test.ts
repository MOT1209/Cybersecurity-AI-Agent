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
  delete process.env.GROQ_API_KEY;
  delete process.env.GROQ_MODEL;
  delete process.env.OPENCODE_API_KEY;
  delete process.env.OPENCODE_ZEN_API_KEY;
  delete process.env.ZEN_MODEL;
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

  it('prefers zen over groq over claude over gemini when several keys exist', () => {
    process.env.GEMINI_API_KEY = 'x';
    process.env.ANTHROPIC_API_KEY = 'y';
    process.env.GROQ_API_KEY = 'z';
    process.env.OPENCODE_API_KEY = 'w';
    expect(resolveProvider().id).toBe('zen');
    expect(providerStatus().available).toEqual(['zen', 'groq', 'claude', 'gemini', 'local']);
  });

  it('auto-selects groq when only its key is present', () => {
    process.env.GROQ_API_KEY = 'z';
    expect(resolveProvider().id).toBe('groq');
  });

  it('auto-selects zen when only its key is present', () => {
    process.env.OPENCODE_API_KEY = 'w';
    expect(resolveProvider().id).toBe('zen');
  });

  it('honors a pin to groq or zen', () => {
    process.env.GEMINI_API_KEY = 'x';
    process.env.GROQ_API_KEY = 'z';
    process.env.OPENCODE_API_KEY = 'w';
    process.env.AI_PROVIDER = 'groq';
    expect(resolveProvider().id).toBe('groq');
    process.env.AI_PROVIDER = 'zen';
    expect(resolveProvider().id).toBe('zen');
  });

  it('reports zen as unavailable with no key (never half-available)', () => {
    expect(providerStatus().available).not.toContain('zen');
    expect(providerStatus().available).not.toContain('groq');
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
