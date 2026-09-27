import { IOC } from '../types';

export function iocEvidenceCategory(ioc: IOC): string {
  if (ioc.evidenceCategory && ioc.evidenceCategory !== 'Email evidence') {
    return ioc.evidenceCategory;
  }
  const source = ioc.source.toLowerCase();
  const value = ioc.normalizedValue?.toLowerCase() || ioc.value.toLowerCase();
  if (/\b(smtp\.mailfrom|header\.from|header\.d|header\.i)\b/.test(value)
    || /authentication-results|arc-authentication|arc-seal|arc-message-signature|dkim-signature|received-spf/.test(source)) {
    return 'Authentication artifact';
  }
  if (/\b(from|to|reply-to) header\b/.test(source) || (ioc.type === 'EMAIL' && !source.includes('email body'))) {
    return 'Sender identity';
  }
  if (/received header|x-originating-ip/.test(source)) {
    return 'Network/header infrastructure';
  }
  if (/email body/.test(source) || /attachment/i.test(source)) {
    return ioc.type === 'URL' || ioc.type === 'DOMAIN'
      ? 'URL/domain IOC'
      : 'Email evidence';
  }
  if (ioc.reputationStatus === 'MALICIOUS' || ioc.reputationStatus === 'SUSPICIOUS') {
    return 'Threat intelligence';
  }
  return 'Email evidence';
}
