import { request } from './core';
import type { CustomsDocument, Submission, SubmissionStatus } from '../types';

export function createSubmission(document: CustomsDocument): Promise<Submission> {
  return request('/api/submissions', { method: 'POST', body: JSON.stringify(document) });
}

export function listSubmissions(status?: SubmissionStatus): Promise<Submission[]> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : '';
  return request(`/api/submissions${qs}`);
}

export function getSubmission(id: number): Promise<Submission> {
  return request(`/api/submissions/${id}`);
}

export function approveSubmission(id: number): Promise<Submission> {
  return request(`/api/submissions/${id}/approve`, { method: 'POST' });
}

export function rejectSubmission(id: number, note?: string): Promise<Submission> {
  return request(`/api/submissions/${id}/reject`, { method: 'POST', body: JSON.stringify({ note }) });
}
