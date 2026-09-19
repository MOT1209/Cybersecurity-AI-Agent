/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared adapter error type. Thrown by a tool adapter's `build*Request` when
 * the target/params fail a domain-specific check (e.g. "not a bare domain",
 * "missing FUZZ placeholder") that isn't expressible as a Zod schema on the
 * params object alone. Routes map this to HTTP 400, same as a ZodError.
 */
export class ToolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolInputError";
  }
}
