/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared input validation helpers. Extracted from server.ts (Phase 0) so the
 * same rules can be reused by future route modules and agents.
 */

export interface FieldValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validates string type, non-emptiness, and enforces a maximum character limit.
 * Behavior is identical to the original inline helper in server.ts.
 */
export function validateStringField(
  value: unknown,
  fieldName: string,
  maxLength: number,
  required: boolean = true,
): FieldValidationResult {
  if (value === undefined || value === null) {
    if (required) {
      return { valid: false, error: `Field '${fieldName}' is required and cannot be empty.` };
    }
    return { valid: true };
  }

  if (typeof value !== "string") {
    return { valid: false, error: `Field '${fieldName}' must be a string.` };
  }

  const trimmed = value.trim();
  if (required && trimmed.length === 0) {
    return { valid: false, error: `Field '${fieldName}' cannot be empty or whitespace only.` };
  }

  if (value.length > maxLength) {
    return {
      valid: false,
      error: `Field '${fieldName}' exceeds maximum allowed length of ${maxLength} characters (received ${value.length}).`,
    };
  }

  return { valid: true };
}
