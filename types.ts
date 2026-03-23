export interface CVE {
  id: string;
  summary: string;
  cvss: number | null;
  cvssV40?: number | null;
  cvssV31?: number | null;
  cvssV30?: number | null;
  cvssV20?: number | null;
  cvssVectorV40?: string | null;
  cvssVectorV31?: string | null;
  cvssVectorV30?: string | null;
  cvssVectorV20?: string | null;
  Published: string;
  Modified: string;
  vulnerable_configuration: string[];
  vulnerable_configuration_cpe_2_2?: string[];
  references: string[];
  vulnStatus?: string;
}

export interface SearchParams {
  vendor: string;
  product: string;
}

export interface SavedSearch {
  id: string;
  label: string;
  timestamp: number;
  vendor: string;
  product: string;
  cves: CVE[];
}

export enum LoadingState {
  IDLE = 'IDLE',
  LOADING = 'LOADING',
  SUCCESS = 'SUCCESS',
  ERROR = 'ERROR',
  EMPTY = 'EMPTY'
}
