import { Button, Card, Checkbox, Form, Rate, Select, Space, Typography } from 'antd';

import type { CourseDetail, ReviewCreate, ReviewResponse, ReviewUpdate } from '../../types';
import { DIMENSION_FIELD_OPTIONS } from '../../utils/constants';
import { termDisplay } from '../../utils/format';
import { RichTextEditor } from '../editor/RichTextEditor';

type ReviewFormValues = {
  term: string;
  difficulty: number;
  homework: number;
  grading: number;
  gain: number;
  rate_stars: number;
  content: string;
  is_anonymous?: boolean;
  only_visible_to_student?: boolean;
};

interface ReviewFormProps {
  course: CourseDetail;
  initialReview?: ReviewResponse;
  loading?: boolean;
  onSubmit: (payload: ReviewCreate | ReviewUpdate) => void;
}

const dimensionFields = [
  ['difficulty', '课程难度'],
  ['homework', '作业多少'],
  ['grading', '给分好坏'],
  ['gain', '收获大小'],
] as const;

export function ReviewForm({ course, initialReview, loading, onSubmit }: ReviewFormProps) {
  // 与老版一致：只能选择课程实际开课的学期（编辑时保留点评原有学期）
  const termOptions = Array.from(
    new Set([
      ...course.terms.map((item) => item.term).filter(Boolean),
      initialReview?.term,
    ]),
  ).filter(Boolean) as string[];

  const initialValues: ReviewFormValues = {
    term: initialReview?.term || termOptions[0],
    difficulty: initialReview?.difficulty || 2,
    homework: initialReview?.homework || 2,
    grading: initialReview?.grading || 2,
    gain: initialReview?.gain || 2,
    rate_stars: initialReview?.rate ? initialReview.rate / 2 : 0,
    content: initialReview?.content || '',
    is_anonymous: initialReview?.is_anonymous || false,
    only_visible_to_student: initialReview?.only_visible_to_student || false,
  };

  const submit = (values: ReviewFormValues) => {
    const payload = {
      course_id: course.id,
      term: values.term,
      difficulty: values.difficulty,
      homework: values.homework,
      grading: values.grading,
      gain: values.gain,
      rate: Math.max(1, Math.min(10, Math.round(values.rate_stars * 2))),
      content: values.content,
      is_anonymous: Boolean(values.is_anonymous),
      only_visible_to_student: Boolean(values.only_visible_to_student),
    };
    if (initialReview) {
      onSubmit({
        term: payload.term,
        difficulty: payload.difficulty,
        homework: payload.homework,
        grading: payload.grading,
        gain: payload.gain,
        rate: payload.rate,
        content: payload.content,
        is_anonymous: payload.is_anonymous,
        only_visible_to_student: payload.only_visible_to_student,
      });
      return;
    }
    onSubmit(payload);
  };

  return (
    <Card className="section-card">
      <Form layout="vertical" initialValues={initialValues} onFinish={submit}>
        <Form.Item name="term" label="学期" rules={[{ required: true, message: '请选择学期' }]}>
          <Select
            options={termOptions.map((value) => ({ value, label: termDisplay(value) }))}
            className="select-md"
          />
        </Form.Item>

        <div className="review-form-grid">
          {dimensionFields.map(([name, label]) => (
            <Form.Item key={name} name={name} label={label} rules={[{ required: true }]}>
              <Select options={DIMENSION_FIELD_OPTIONS[name]} />
            </Form.Item>
          ))}
        </div>

        <Form.Item
          name="rate_stars"
          label="总体评分"
          rules={[{ required: true, type: 'number', min: 0.5, message: '请给出评分' }]}
        >
          <Rate allowHalf />
        </Form.Item>

        <Form.Item
          name="content"
          label="点评内容"
          rules={[
            { required: true, message: '请输入点评内容' },
            { min: 10, message: '点评内容至少 10 个字符' },
          ]}
        >
          <RichTextEditor placeholder="课程内容、作业强度、考试形式、给分体验、适合人群..." />
        </Form.Item>

        <Space orientation="vertical" size={6} className="review-options">
          <Form.Item name="is_anonymous" valuePropName="checked" noStyle>
            <Checkbox>匿名发表点评（为防止无意义点评，匿名点评需满40字）</Checkbox>
          </Form.Item>
          <Form.Item name="only_visible_to_student" valuePropName="checked" noStyle>
            <Checkbox>仅登录学生用户可见</Checkbox>
          </Form.Item>
        </Space>

        <div className="form-actions">
          <Typography.Text type="secondary">
            编辑器没有自动保存功能，如需写长评论，为保险起见推荐在word或者markdown编辑器写完再复制至输入框；内容会按 HTML 安全白名单渲染。
          </Typography.Text>
          <Button type="primary" htmlType="submit" loading={loading}>
            {initialReview ? '保存修改' : '发布点评'}
          </Button>
        </div>
      </Form>
    </Card>
  );
}
