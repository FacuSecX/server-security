import { BlockList, isIP } from 'node:net';

const nonPublic = new BlockList();
for (const [ip,bits] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],
  ['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],
  ['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]]) {
  nonPublic.addSubnet(ip,bits,'ipv4');
}
const globalV6 = new BlockList();
globalV6.addSubnet('2000::',3,'ipv6');
nonPublic.addSubnet('2001:db8::',32,'ipv6');

export function isGeoCandidate(ip) {
  const family = isIP(ip);
  if (family === 4) return !nonPublic.check(ip,'ipv4');
  return family === 6 && !ip.includes('%') && globalV6.check(ip,'ipv6') && !nonPublic.check(ip,'ipv6');
}

export function validateListen(host, port) {
  if (!['127.0.0.1','::1','localhost'].includes(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('El panel requiere una dirección local (127.0.0.1, ::1 o localhost) y un puerto válido.');
  }
}

// The random action token does not replace protection against DNS rebinding.
export function localRequestAllowed(request, port) {
  const hosts = new Set(['127.0.0.1','localhost','[::1]'].map(host => `${host}${port === 80 ? '' : ':' + port}`));
  const host = String(request.headers.host || '').toLowerCase();
  if (!hosts.has(host)) return false;
  if (request.headers.origin && request.headers.origin !== `http://${host}`) return false;
  const site = request.headers['sec-fetch-site'];
  return !site || site === 'same-origin' || site === 'none';
}

export function setSecurityHeaders(response) {
  response.setHeader('X-Content-Type-Options','nosniff');
  response.setHeader('X-Frame-Options','DENY');
  response.setHeader('Referrer-Policy','no-referrer');
  response.setHeader('Cross-Origin-Opener-Policy','same-origin');
  response.setHeader('Cross-Origin-Resource-Policy','same-origin');
  response.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; script-src-attr 'none'; worker-src 'none'; frame-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://flagcdn.com; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
}
