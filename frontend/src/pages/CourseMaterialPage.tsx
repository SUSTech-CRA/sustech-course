import {
  ArrowLeftOutlined,
  DownloadOutlined,
  FileExcelOutlined,
  FileImageOutlined,
  FileOutlined,
  FilePdfOutlined,
  FilePptOutlined,
  FileTextOutlined,
  FileWordOutlined,
  FolderOpenOutlined,
  FolderOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Alert, App as AntApp, Breadcrumb, Button, Card, Result, Space, Spin, Table, Tag, Typography } from 'antd';
import type { TableProps } from 'antd';
import { Link, useLocation, useParams, useSearchParams } from 'react-router-dom';

import { coursesApi } from '../api/courses';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useCourse } from '../hooks/useCourse';
import { useAuthStore } from '../stores/authStore';
import type { CourseMaterialEntry } from '../types';
import { buildSignInPath, getRedirectFromLocation } from '../utils/authRedirect';
import { formatBytes, formatDateTime } from '../utils/format';

function materialIcon(entry: CourseMaterialEntry) {
  if (entry.is_dir) return <FolderOutlined />;
  const extension = entry.name.split('.').pop()?.toLowerCase();
  if (extension === 'pdf') return <FilePdfOutlined />;
  if (['doc', 'docx'].includes(extension || '')) return <FileWordOutlined />;
  if (['xls', 'xlsx', 'csv'].includes(extension || '')) return <FileExcelOutlined />;
  if (['ppt', 'pptx'].includes(extension || '')) return <FilePptOutlined />;
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(extension || '')) return <FileImageOutlined />;
  if (['txt', 'md', 'log'].includes(extension || '')) return <FileTextOutlined />;
  return <FileOutlined />;
}

export function CourseMaterialPage() {
  const { id } = useParams();
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const path = params.get('path') || '';
  const signInPath = buildSignInPath(getRedirectFromLocation(location));
  const courseQuery = useCourse(id);
  const materialsQuery = useQuery({
    queryKey: ['course', id, 'materials', path],
    queryFn: () => coursesApi.materials(id as string, path),
    enabled: Boolean(id && user),
    placeholderData: (previous) => previous,
  });

  const setPath = (nextPath: string) => {
    if (nextPath) setParams({ path: nextPath });
    else setParams({});
  };

  const download = async (entry: CourseMaterialEntry) => {
    try {
      const url = await coursesApi.materialPresignUrl(id as string, entry.path);
      window.open(url, '_blank', 'noopener,noreferrer');
    } catch {
      message.error('下载链接生成失败，请稍后再试');
    }
  };

  if (!user) {
    return (
      <Result
        status="403"
        title="请先登录"
        subTitle="课程公开课件/试卷需要登录后访问。"
        extra={<Button type="primary" href={signInPath}>登录</Button>}
      />
    );
  }

  if (courseQuery.isLoading) return <Spin fullscreen description="加载课程材料" />;
  if (courseQuery.isError || !courseQuery.data) return <Result status="404" title="课程不存在" />;

  const course = courseQuery.data;
  const materials = materialsQuery.data;
  const rows = [...(materials?.directories || []), ...(materials?.files || [])];
  const segments = (materials?.path || path).split('/').filter(Boolean);
  let cumulativePath = '';
  const breadcrumbItems = [
    {
      title: (
        <Button type="link" size="small" onClick={() => setPath('')}>
          {materials?.base_code || course.course_material_code || course.courseries || course.course_code || '材料库'}
        </Button>
      ),
    },
    ...segments.map((segment, index) => {
      cumulativePath += `${segment}/`;
      const crumbPath = cumulativePath;
      return {
        title:
          index === segments.length - 1 ? (
            segment
          ) : (
            <Button type="link" size="small" onClick={() => setPath(crumbPath)}>
              {segment}
            </Button>
          ),
      };
    }),
  ];

  const columns: TableProps<CourseMaterialEntry>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      render: (name, entry) => (
        <Button
          type="link"
          className="material-name-button"
          icon={materialIcon(entry)}
          onClick={() => (entry.is_dir ? setPath(entry.path) : download(entry))}
        >
          {name}
        </Button>
      ),
    },
    {
      title: '类型',
      width: 92,
      render: (_, entry) => <Tag>{entry.is_dir ? '目录' : '文件'}</Tag>,
      responsive: ['sm'],
    },
    {
      title: '更新时间',
      dataIndex: 'last_modified',
      width: 190,
      render: (value) => <span className="mono-text">{value ? formatDateTime(value) : '-'}</span>,
      responsive: ['md'],
    },
    {
      title: '大小',
      dataIndex: 'size',
      width: 110,
      render: (value, entry) => <span className="mono-text">{entry.is_dir ? '-' : formatBytes(value)}</span>,
    },
    {
      title: '操作',
      width: 92,
      render: (_, entry) =>
        entry.is_dir ? (
          <Button size="small" icon={<FolderOpenOutlined />} onClick={() => setPath(entry.path)} />
        ) : (
          <Button size="small" icon={<DownloadOutlined />} onClick={() => download(entry)} />
        ),
    },
  ];

  return (
    <div>
      <Seo title={`${course.name} 课程材料`} noindex />
      <PageTitle
        title={`${course.name} 课程材料`}
        subtitle="如无法打开，请在校内访问或使用 VPN 回校后再访问。"
        extra={
          <Link to={`/course/${course.id}`}>
            <Button icon={<ArrowLeftOutlined />}>返回课程</Button>
          </Link>
        }
      />
      <Card className="section-card material-browser-card">
        <Space orientation="vertical" className="full-width" size={14}>
          {course.course_material_code && (
            <Alert
              type="info"
              showIcon
              title={`此课程共用 ${course.course_material_code} 的课件库`}
            />
          )}
          <Breadcrumb items={breadcrumbItems} />
          <Table
            rowKey="key"
            loading={materialsQuery.isLoading}
            columns={columns}
            dataSource={rows}
            pagination={false}
            locale={{ emptyText: <Typography.Text type="secondary">这个文件夹是空的</Typography.Text> }}
            scroll={{ x: 'max-content' }}
          />
        </Space>
      </Card>
    </div>
  );
}
