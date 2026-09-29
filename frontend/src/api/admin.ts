import apiClient from './client';
import type {
  AnnouncementCreate,
  AnnouncementResponse,
  AnnouncementUpdate,
  BannerCreate,
  BannerResponse,
} from '../types';

export const adminApi = {
  async banners() {
    const { data } = await apiClient.get<BannerResponse[]>('/admin/banners');
    return data;
  },

  async currentBanner() {
    const { data } = await apiClient.get<BannerResponse | null>('/admin/banners/current');
    return data;
  },

  async createBanner(payload: BannerCreate) {
    const { data } = await apiClient.post<BannerResponse>('/admin/banners', payload);
    return data;
  },

  async announcements() {
    const { data } = await apiClient.get<AnnouncementResponse[]>('/admin/announcements');
    return data;
  },

  async createAnnouncement(payload: AnnouncementCreate) {
    const { data } = await apiClient.post<AnnouncementResponse>('/admin/announcements', payload);
    return data;
  },

  async updateAnnouncement(announcementId: number | string, payload: AnnouncementUpdate) {
    const { data } = await apiClient.patch<AnnouncementResponse>(
      `/admin/announcements/${announcementId}`,
      payload,
    );
    return data;
  },

  async deleteAnnouncement(announcementId: number | string) {
    await apiClient.delete(`/admin/announcements/${announcementId}`);
  },
};
