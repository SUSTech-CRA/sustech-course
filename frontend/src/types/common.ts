export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface MessageResponse {
  ok: boolean;
  message?: string | null;
}

export interface UploadResponse {
  id: number;
  filename: string;
  stored_filename: string;
  url: string;
  uploaded?: number;
  resource_url?: string | null;
}

export interface RequestInfoResponse {
  server_time: string;
  client_ip?: string | null;
}

export interface SelectOption<T extends string | number = string> {
  label: string;
  value: T;
}
