import { useQuery } from '@tanstack/react-query';

import { adminApi } from '../../api/admin';
import { HTMLContent } from '../common/HTMLContent';

export function BannerStrip() {
  const bannerQuery = useQuery({
    queryKey: ['banner', 'current'],
    queryFn: adminApi.currentBanner,
    staleTime: 10 * 60 * 1000,
  });
  const banner = bannerQuery.data;
  const desktop = banner?.desktop?.trim();
  const mobile = (banner?.mobile || banner?.desktop)?.trim();

  if (!desktop && !mobile) return null;

  return (
    <div className="site-banner">
      {desktop && (
        <div className="site-banner-desktop">
          <HTMLContent html={desktop} />
        </div>
      )}
      {mobile && (
        <div className="site-banner-mobile">
          <HTMLContent html={mobile} />
        </div>
      )}
    </div>
  );
}
