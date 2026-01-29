export interface CVE {
  id: string;
  summary: string;
  cvss: number | null;
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