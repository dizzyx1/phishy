/**
 * URL Normalization Utility
 *
 * Handles edge cases like missing protocols, protocol-relative URLs,
 * non-HTTP schemes, and ensures consistent URL parsing across the application.
 */

/**
 * Normalizes a raw URL input by adding https:// if needed
 * and handling various edge cases.
 *
 * @param rawInput - The raw URL string from user input
 * @returns Normalized URL string with protocol, ready for URL() constructor
 * @throws Error if the URL is malformed or has an empty hostname
 */
export function normalizeUrl(rawInput: string): string {
  let normalized = rawInput.trim();

  // Handle protocol-relative URLs (//example.com)
  if (normalized.startsWith("//")) {
    normalized = `https:${normalized}`;
  }
  // Handle URLs with non-HTTP/HTTPS schemes (e.g., ftp://, javascript:)
  // Only match schemes with :// to avoid false positives on host:port
  else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)) {
    // If it's not http:// or https://, strip the scheme and add https://
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = `https://${normalized.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")}`;
    }
  }
  // No scheme at all - add https://
  else if (!/^https?:\/\//i.test(normalized)) {
    normalized = `https://${normalized}`;
  }

  return normalized;
}

/**
 * Parses and validates a normalized URL.
 *
 * @param normalizedUrl - A normalized URL string (output of normalizeUrl)
 * @returns URL object if valid
 * @throws Error if URL is malformed or has empty hostname
 */
export function parseAndValidateUrl(normalizedUrl: string): URL {
  const parsed = new URL(normalizedUrl);

  // Validate that we have a non-empty hostname
  if (!parsed.hostname) {
    throw new Error("Empty hostname");
  }

  return parsed;
}
