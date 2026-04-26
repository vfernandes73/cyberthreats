import { Timestamp } from 'firebase/firestore';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface IOC {
  type: string;
  value: string;
  actor: string;
}

export interface Threat {
  id: string;
  title: string;
  summary: string;
  sourceUrl: string;
  region: string;
  vertical: string;
  domain?: string;
  actors: string[];
  iocs: IOC[];
  publishedAt: Timestamp;
  keywords: string[];
  severity: Severity;
}

export interface Alert {
  id: string;
  userId: string;
  filters: {
    region?: string;
    vertical?: string;
    keywords?: string[];
  };
  createdAt: Timestamp;
}

export interface ActorProfile {
  id: string;
  name: string;
  description: string;
  techniques: string[];
  lastSeen: Timestamp;
}

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
  }
}
