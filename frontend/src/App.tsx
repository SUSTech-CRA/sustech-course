import { QueryClientProvider } from '@tanstack/react-query';
import * as Sentry from '@sentry/react';
import { App as AntApp, ConfigProvider, Spin, theme as antdTheme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { lazy, Suspense, useEffect, useMemo, useState, type ComponentType } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { ChallengeModal } from './components/auth/ChallengeModal';
import { AppLayout } from './components/layout/AppLayout';
import { queryClient } from './queryClient';
import { useAuthStore } from './stores/authStore';

function lazyPage<T extends Record<string, ComponentType<any>>, K extends keyof T>(
  loader: () => Promise<T>,
  name: K,
) {
  return lazy(async () => ({ default: (await loader())[name] }));
}

const AboutPage = lazyPage(() => import('./pages/AboutPage'), 'AboutPage');
const AnnouncementsPage = lazyPage(() => import('./pages/AnnouncementsPage'), 'AnnouncementsPage');
const CourseDetailPage = lazyPage(() => import('./pages/CourseDetailPage'), 'CourseDetailPage');
const CourseEditPage = lazyPage(() => import('./pages/CourseEditPage'), 'CourseEditPage');
const CourseGotoPage = lazyPage(() => import('./pages/CourseGotoPage'), 'CourseGotoPage');
const CourseListPage = lazyPage(() => import('./pages/CourseListPage'), 'CourseListPage');
const CourseMaterialPage = lazyPage(() => import('./pages/CourseMaterialPage'), 'CourseMaterialPage');
const ConfirmEmailPage = lazyPage(() => import('./pages/ConfirmEmailPage'), 'ConfirmEmailPage');
const ForgotPasswordPage = lazyPage(() => import('./pages/ForgotPasswordPage'), 'ForgotPasswordPage');
const HomePage = lazyPage(() => import('./pages/HomePage'), 'HomePage');
const NewReviewPage = lazyPage(() => import('./pages/NewReviewPage'), 'NewReviewPage');
const NotFoundPage = lazyPage(() => import('./pages/NotFoundPage'), 'NotFoundPage');
const NotificationsPage = lazyPage(() => import('./pages/NotificationsPage'), 'NotificationsPage');
const OAuthCallbackPage = lazyPage(() => import('./pages/OAuthCallbackPage'), 'OAuthCallbackPage');
const RankingsPage = lazyPage(() => import('./pages/RankingsPage'), 'RankingsPage');
const ResetPasswordPage = lazyPage(() => import('./pages/ResetPasswordPage'), 'ResetPasswordPage');
const SearchPage = lazyPage(() => import('./pages/SearchPage'), 'SearchPage');
const SettingsPage = lazyPage(() => import('./pages/SettingsPage'), 'SettingsPage');
const SignInPage = lazyPage(() => import('./pages/SignInPage'), 'SignInPage');
const SignUpPage = lazyPage(() => import('./pages/SignUpPage'), 'SignUpPage');
const StatsPage = lazyPage(() => import('./pages/StatsPage'), 'StatsPage');
const TeacherEditPage = lazyPage(() => import('./pages/TeacherEditPage'), 'TeacherEditPage');
const TeacherProfilePage = lazyPage(() => import('./pages/TeacherProfilePage'), 'TeacherProfilePage');
const UserFollowListPage = lazyPage(() => import('./pages/UserFollowListPage'), 'UserFollowListPage');
const UserProfilePage = lazyPage(() => import('./pages/UserProfilePage'), 'UserProfilePage');
const AnnouncementManagePage = lazyPage(
  () => import('./pages/admin/AnnouncementManagePage'),
  'AnnouncementManagePage',
);
const BannerPage = lazyPage(() => import('./pages/admin/BannerPage'), 'BannerPage');

const LEGACY_BLUE = '#337ab7';
const LEGACY_SUCCESS = '#5cb85c';
const LEGACY_WARNING = '#f0ad4e';
const LEGACY_ERROR = '#d9534f';

function getPrefersDark() {
  if (typeof window === 'undefined') return false;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
}

export default function App() {
  const [isDarkMode, setIsDarkMode] = useState(getPrefersDark);
  const user = useAuthStore((state) => state.user);

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!media) return;
    const syncTheme = () => setIsDarkMode(media.matches);
    syncTheme();
    media.addEventListener('change', syncTheme);
    return () => media.removeEventListener('change', syncTheme);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = isDarkMode ? 'dark' : 'light';
  }, [isDarkMode]);

  useEffect(() => {
    if (!user) {
      Sentry.setUser(null);
      Sentry.setTag('user.role', undefined);
      Sentry.setTag('user.identity', undefined);
      return;
    }
    Sentry.setUser({
      id: String(user.id),
      username: user.username,
    });
    Sentry.setTag('user.role', user.role || 'User');
    Sentry.setTag('user.identity', user.identity || 'unknown');
  }, [user]);

  const theme = useMemo(
    () => ({
      algorithm: isDarkMode ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
      token: {
        colorPrimary: LEGACY_BLUE,
        colorLink: LEGACY_BLUE,
        colorInfo: LEGACY_BLUE,
        colorSuccess: LEGACY_SUCCESS,
        colorWarning: LEGACY_WARNING,
        colorError: LEGACY_ERROR,
        colorBgLayout: isDarkMode ? '#141414' : '#f5f7f9',
        colorBgContainer: isDarkMode ? '#1f1f1f' : '#ffffff',
        colorBgElevated: isDarkMode ? '#242424' : '#ffffff',
        colorBorder: isDarkMode ? '#3a3a3a' : '#d8dee6',
        colorBorderSecondary: isDarkMode ? '#303030' : '#e6ebf0',
        borderRadius: 6,
        borderRadiusLG: 8,
        boxShadow: isDarkMode
          ? '0 10px 30px rgba(0, 0, 0, 0.32)'
          : '0 10px 28px rgba(15, 23, 42, 0.08)',
        boxShadowSecondary: isDarkMode
          ? '0 6px 18px rgba(0, 0, 0, 0.26)'
          : '0 6px 18px rgba(15, 23, 42, 0.06)',
        fontFamily: '"Noto Sans SC", "PingFang SC", "Microsoft YaHei", Helvetica, Arial, sans-serif',
      },
      components: {
        Card: {
          headerBg: isDarkMode ? '#242424' : '#fbfcfd',
          bodyPaddingSM: 16,
          headerPaddingSM: 16,
        },
        Button: {
          defaultShadow: 'none',
          primaryShadow: 'none',
          dangerShadow: 'none',
        },
        Input: {
          activeShadow: '0 0 0 2px rgba(51, 122, 183, 0.12)',
        },
        Select: {
          activeOutlineColor: 'rgba(51, 122, 183, 0.12)',
        },
      },
    }),
    [isDarkMode],
  );

  return (
    <QueryClientProvider client={queryClient}>
      <ConfigProvider
        locale={zhCN}
        theme={theme}
      >
        <AntApp>
          <ChallengeModal />
          <BrowserRouter>
            <Suspense fallback={<Spin fullscreen description="加载页面" />}>
              <Routes>
                <Route element={<AppLayout />}>
                  <Route path="/" element={<HomePage />} />
                  <Route path="/latest_reviews" element={<HomePage />} />
                  <Route path="/follow_reviews" element={<HomePage />} />
                  <Route path="/search" element={<SearchPage />} />
                  <Route path="/courses" element={<CourseListPage />} />
                  <Route path="/courses/:id" element={<CourseDetailPage />} />
                  <Route path="/course/:id" element={<CourseDetailPage />} />
                  <Route path="/course/:id/" element={<CourseDetailPage />} />
                  <Route path="/courses/:id/review" element={<NewReviewPage />} />
                  <Route path="/course/:id/review" element={<NewReviewPage />} />
                  <Route path="/courses/:id/edit" element={<CourseEditPage />} />
                  <Route path="/course/:id/edit" element={<CourseEditPage />} />
                  <Route path="/courses/:id/material" element={<CourseMaterialPage />} />
                  <Route path="/course/:id/material" element={<CourseMaterialPage />} />
                  <Route path="/course/:id/material/" element={<CourseMaterialPage />} />
                  <Route path="/course/goto/:cno" element={<CourseGotoPage />} />
                  <Route path="/course/goto/:cno/:term" element={<CourseGotoPage />} />
                  <Route path="/reviews/:reviewId/edit" element={<NewReviewPage />} />
                  <Route path="/teachers/:id" element={<TeacherProfilePage />} />
                  <Route path="/teacher/:id" element={<TeacherProfilePage />} />
                  <Route path="/teachers/:id/edit" element={<TeacherEditPage />} />
                  <Route path="/teacher/:id/edit" element={<TeacherEditPage />} />
                  <Route path="/users/:id" element={<UserProfilePage />} />
                  <Route path="/user/:id" element={<UserProfilePage />} />
                  <Route path="/users/:id/followers" element={<UserFollowListPage kind="followers" />} />
                  <Route path="/user/:id/followers" element={<UserFollowListPage kind="followers" />} />
                  <Route path="/users/:id/followings" element={<UserFollowListPage kind="followings" />} />
                  <Route path="/user/:id/followings" element={<UserFollowListPage kind="followings" />} />
                  <Route path="/users/:id/following-courses" element={<UserFollowListPage kind="following-courses" />} />
                  <Route path="/user/:id/follow_course" element={<UserFollowListPage kind="following-courses" />} />
                  <Route path="/users/:id/joined-courses" element={<UserFollowListPage kind="joined-courses" />} />
                  <Route path="/user/:id/courses" element={<UserFollowListPage kind="joined-courses" />} />
                  <Route path="/rankings" element={<RankingsPage />} />
                  <Route path="/stats" element={<StatsPage />} />
                  <Route path="/about" element={<AboutPage />} />
                  <Route path="/community-rules" element={<AboutPage />} />
                  <Route path="/community-rules/" element={<AboutPage />} />
                  <Route path="/report-review" element={<AboutPage />} />
                  <Route path="/report-review/" element={<AboutPage />} />
                  <Route path="/announcements" element={<AnnouncementsPage />} />
                  <Route path="/signin" element={<SignInPage />} />
                  <Route path="/signup" element={<SignUpPage />} />
                  <Route path="/forgot-password" element={<ForgotPasswordPage />} />
                  <Route path="/reset-password" element={<ResetPasswordPage />} />
                  <Route path="/confirm-email" element={<ConfirmEmailPage />} />
                  <Route path="/oauth/cra/callback" element={<OAuthCallbackPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/notifications" element={<NotificationsPage />} />
                  <Route path="/admin/banners" element={<BannerPage />} />
                  <Route path="/admin/announcements" element={<AnnouncementManagePage />} />
                  <Route path="*" element={<NotFoundPage />} />
                </Route>
              </Routes>
            </Suspense>
          </BrowserRouter>
        </AntApp>
      </ConfigProvider>
    </QueryClientProvider>
  );
}
