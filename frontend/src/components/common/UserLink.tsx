import { Link } from 'react-router-dom';
import { Typography } from 'antd';

import type { UserBrief } from '../../types';

interface UserLinkProps {
  user?: UserBrief | null;
  anonymous?: boolean;
}

export function UserLink({ user, anonymous }: UserLinkProps) {
  if (anonymous || !user) {
    return <Typography.Text className="linkish">匿名用户</Typography.Text>;
  }
  return <Link to={`/user/${user.id}`}>{user.username}</Link>;
}

