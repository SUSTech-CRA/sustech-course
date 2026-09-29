export interface BannerCreate {
  desktop?: string | null;
  mobile?: string | null;
}

export interface BannerResponse extends BannerCreate {
  id: number;
  publish_time?: string | null;
}

export interface AnnouncementCreate {
  title: string;
  content: string;
}

export interface AnnouncementUpdate {
  title?: string;
  content?: string;
}

export interface AnnouncementResponse {
  id: number;
  author_id?: number | null;
  last_editor_id?: number | null;
  title?: string | null;
  content?: string | null;
  publish_time?: string | null;
  update_time?: string | null;
}

