import { request } from './core';
import type { ReviewItem, VerifiableCredential, CustomsDocument } from '../types';

export function listPending(): Promise<ReviewItem[]> {
  return request('/api/pending');
}

export function approvePending(id: number): Promise<{ item: ReviewItem; verifiableCredential: VerifiableCredential }> {
  return request(`/api/pending/${id}/approve`, { method: 'POST' });
}

export function rejectPending(id: number, note?: string): Promise<{ item: ReviewItem }> {
  return request(`/api/pending/${id}/reject`, { method: 'POST', body: JSON.stringify({ note }) });
}

export type { CustomsDocument };
