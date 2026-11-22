export type AppMode = 'soc' | 'lab' | 'unavailable';

/** The development token UI is an explicit loopback-only route. */
export function selectAppMode(protocol: string, hostname: string, pathname: string): AppMode {
  if (pathname === '/lab' || pathname === '/lab/') {
    const loopback = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(hostname.toLowerCase());
    return loopback && (protocol === 'http:' || protocol === 'https:') ? 'lab' : 'unavailable';
  }
  return pathname === '/' || pathname === '/soc' || pathname === '/soc/' ? 'soc' : 'unavailable';
}
