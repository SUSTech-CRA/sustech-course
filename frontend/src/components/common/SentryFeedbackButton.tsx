import { MessageOutlined } from '@ant-design/icons';
import * as Sentry from '@sentry/react';
import { Button } from 'antd';
import { useEffect, useRef } from 'react';

import { sentryDsn } from '../../instrument';

interface SentryFeedbackButtonProps {
  source?: string;
}

export function SentryFeedbackButton({ source = 'quick_entry' }: SentryFeedbackButtonProps) {
  const buttonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const feedback = Sentry.getFeedback();
    const button = buttonRef.current;
    if (!feedback || !button) return undefined;

    return feedback.attachTo(button, {
      tags: {
        source,
      },
    });
  }, [source]);

  if (!sentryDsn) return null;

  return (
    <Button ref={buttonRef} type="link" className="quick-link-button" icon={<MessageOutlined />}>
      反馈问题
    </Button>
  );
}
