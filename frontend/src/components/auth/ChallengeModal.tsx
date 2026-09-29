import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Modal, Spin, Typography } from 'antd';
import { useCallback, useState } from 'react';

import { authApi } from '../../api/auth';
import { solveChallenge } from '../../api/challenge';
import { getApiErrorMessage, setChallengeExempt } from '../../api/client';
import { useAuthStore } from '../../stores/authStore';
import { useChallengeStore } from '../../stores/challengeStore';
import { TurnstileWidget } from './TurnstileWidget';

export function ChallengeModal() {
  const open = useChallengeStore((state) => state.open);
  const succeed = useChallengeStore((state) => state.succeed);
  const fail = useChallengeStore((state) => state.fail);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetSignal, setResetSignal] = useState(0);

  const publicConfigQuery = useQuery({
    queryKey: ['auth', 'public-config'],
    queryFn: authApi.publicConfig,
    enabled: open,
  });
  const siteKey = publicConfigQuery.data?.turnstile_site_key;

  const submit = useCallback(
    async (token: string | null) => {
      setSubmitting(true);
      setError(null);
      try {
        const data = await solveChallenge(token);
        setChallengeExempt(data.exempt_token, data.expires_in);
        succeed();
      } catch (err) {
        setError(getApiErrorMessage(err));
        setResetSignal((n) => n + 1);
      } finally {
        setSubmitting(false);
      }
    },
    [succeed],
  );

  const handleToken = useCallback(
    (token: string | null) => {
      if (token) void submit(token);
    },
    [submit],
  );

  return (
    <Modal
      open={open}
      title="请求频率超限"
      footer={null}
      mask={{ closable: false }}
      onCancel={fail}
      destroyOnHidden
    >
      <Typography.Paragraph>
        当前请求频率超出限制，完成人机验证后即可继续访问，验证结果在一段时间内有效。
      </Typography.Paragraph>
      {!isAuthenticated && (
        <Typography.Paragraph type="secondary">
          提示：登录用户享有更高的请求频率配额。
        </Typography.Paragraph>
      )}
      {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 12 }} />}
      {publicConfigQuery.isLoading ? (
        <Spin size="small" />
      ) : publicConfigQuery.isError ? (
        <Alert
          type="error"
          showIcon
          title={getApiErrorMessage(publicConfigQuery.error)}
          action={
            <Button size="small" onClick={() => void publicConfigQuery.refetch()}>
              重试
            </Button>
          }
        />
      ) : !siteKey ? (
        <Button type="primary" loading={submitting} onClick={() => void submit(null)}>
          继续访问
        </Button>
      ) : (
        <TurnstileWidget
          siteKey={siteKey}
          action="challenge"
          resetSignal={resetSignal}
          onToken={handleToken}
        />
      )}
    </Modal>
  );
}
