import { DeleteOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { App as AntApp, Button, Card, Form, Input, InputNumber, Result, Space, Spin, Typography } from 'antd';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { coursesApi } from '../api/courses';
import { getApiErrorMessage } from '../api/client';
import { ItemList } from '../components/common/ItemList';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { RichTextEditor } from '../components/editor/RichTextEditor';
import { useCourse } from '../hooks/useCourse';
import { useAuthStore } from '../stores/authStore';
import type { CourseUpdate } from '../types';

export function CourseEditPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const courseQuery = useCourse(id);
  const [newTeacherId, setNewTeacherId] = useState<number | null>(null);
  const invalidateCourse = () => {
    queryClient.invalidateQueries({ queryKey: ['course', String(id)] });
    queryClient.invalidateQueries({ queryKey: ['course', Number(id)] });
  };
  const updateMutation = useMutation({
    mutationFn: (payload: CourseUpdate) => coursesApi.update(id as string, payload),
    onSuccess: (course) => {
      invalidateCourse();
      message.success('课程介绍已保存');
      navigate(`/course/${course.id}`);
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });
  const announcementMutation = useMutation({
    mutationFn: (payload: CourseUpdate) => coursesApi.update(id as string, payload),
    onSuccess: () => {
      invalidateCourse();
      message.success('管理员公告已保存');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });
  const addTeacherMutation = useMutation({
    mutationFn: (teacherId: number) => coursesApi.addTeacher(id as string, teacherId),
    onSuccess: () => {
      invalidateCourse();
      setNewTeacherId(null);
      message.success('已添加教师');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });
  const removeTeacherMutation = useMutation({
    mutationFn: (teacherId: number) => coursesApi.removeTeacher(id as string, teacherId),
    onSuccess: () => {
      invalidateCourse();
      message.success('已移除教师');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });

  if (!user) {
    return <Result status="403" title="请先登录" subTitle="登录后可以编辑课程介绍和主页。" />;
  }
  if (courseQuery.isLoading) return <Spin fullscreen description="加载课程信息" />;
  if (!courseQuery.data) return <Result status="404" title="课程不存在或无法访问" />;

  const course = courseQuery.data;
  const isAdmin = user.role === 'Admin';

  return (
    <div>
      <Seo title={`编辑课程介绍 - ${course.name}`} noindex />
      <PageTitle
        title="编辑课程介绍"
        subtitle={
          <>
            课程：<Link to={`/course/${course.id}`}>{course.name}</Link>
          </>
        }
      />
      <Card className="section-card">
        <Form<CourseUpdate>
          layout="vertical"
          initialValues={{ introduction: course.introduction || '', homepage: course.homepage || '' }}
          onFinish={(values) => updateMutation.mutate(values)}
        >
          <Form.Item name="homepage" label="课程主页">
            <Input placeholder="https://..." />
          </Form.Item>
          <Form.Item name="introduction" label="课程信息（同学贡献）">
            <RichTextEditor placeholder="补充课程信息、资料入口、选课建议等。" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={updateMutation.isPending}>
            保存课程介绍
          </Button>
        </Form>
      </Card>

      {isAdmin && (
        <Card className="section-card" title="管理员公告">
          <Form<CourseUpdate>
            layout="vertical"
            initialValues={{ admin_announcement: course.admin_announcement || '' }}
            onFinish={(values) => announcementMutation.mutate(values)}
          >
            <Form.Item name="admin_announcement" label="公告内容">
              <RichTextEditor placeholder="面向所有访客的课程公告。" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={announcementMutation.isPending}>
              保存公告
            </Button>
          </Form>
        </Card>
      )}

      {isAdmin && (
        <Card className="section-card" title="任课教师管理">
          <ItemList
            className="stacked-list"
            dataSource={course.teachers}
            emptyText="暂无教师"
            rowKey={(teacher) => teacher.id}
            renderItem={(teacher) => (
              <>
                <Typography.Text>{teacher.name || `教师 #${teacher.id}`}</Typography.Text>
                <div className="item-list-actions">
                  <Button
                    danger
                    type="text"
                    icon={<DeleteOutlined />}
                    loading={removeTeacherMutation.isPending}
                    onClick={() => removeTeacherMutation.mutate(teacher.id)}
                  >
                    移除
                  </Button>
                </div>
              </>
            )}
          />
          <Space className="course-edit-add-teacher">
            <InputNumber
              placeholder="教师 ID"
              value={newTeacherId}
              onChange={(value) => setNewTeacherId(value)}
            />
            <Button
              disabled={!newTeacherId}
              loading={addTeacherMutation.isPending}
              onClick={() => newTeacherId && addTeacherMutation.mutate(newTeacherId)}
            >
              添加教师
            </Button>
          </Space>
        </Card>
      )}
    </div>
  );
}

