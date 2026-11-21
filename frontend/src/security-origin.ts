/** Development bearer credentials may be entered only over a protected origin.
 * HTTPS is acceptable for a trusted deployment; local HTTP is acceptable only
 * over loopback (e.g. an SSH port forward). This does NOT authenticate endpoints.
 */
export function isSafeLabBrowserOrigin(protocol: string, hostname: string): boolean {
  if (protocol === 'https:') return true;
  if (protocol !== 'http:') return false;
  const host = hostname.trim().toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' ||
    host === '::1' || host === '[::1]';
}
