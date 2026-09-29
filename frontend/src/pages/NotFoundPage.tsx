import { Button, Result } from 'antd';
import { Link } from 'react-router-dom';

import { Seo } from '../components/common/Seo';

export function NotFoundPage() {
  return (
    <>
      <Seo title="页面不存在" noindex />
      <Result
        status="404"
        title="页面不存在"
        subTitle="这个地址暂时没有对应的前端页面。"
        extra={
          <Link to="/">
            <Button type="primary">回到首页</Button>
          </Link>
        }
      />
    </>
  );
}

