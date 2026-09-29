import { Avatar } from 'antd';
import type { AvatarProps } from 'antd';

import { FALLBACK_AVATAR } from '../../utils/constants';

interface UserAvatarProps extends AvatarProps {
  src?: string | null;
  name?: string | null;
}

export function UserAvatar({ src, name, ...props }: UserAvatarProps) {
  return <Avatar src={src || FALLBACK_AVATAR} alt={name || '用户头像'} {...props} />;
}

