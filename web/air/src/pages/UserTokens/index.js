import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Layout, Button, Spin, Typography } from '@douyinfe/semi-ui';
import TokensTable from '../../components/TokensTable';
import { API, showError } from '../../helpers';
import { ROUTES } from '../../helpers/routes';

const UserTokens = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [userInfo, setUserInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const userId = parseInt(id, 10);

  useEffect(() => {
    const loadUser = async () => {
      try {
        const res = await API.get(`/api/user/${userId}`);
        const { success, message, data } = res.data;
        if (success) {
          setUserInfo(data);
        } else {
          showError(message);
        }
      } catch (err) {
        showError(err?.message || err);
      } finally {
        setLoading(false);
      }
    };
    if (!Number.isNaN(userId)) {
      loadUser();
    } else {
      showError('无效的用户 ID');
      setLoading(false);
    }
  }, [userId]);

  return (
    <Layout>
      <Layout.Header>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3>管理用户令牌</h3>
            {userInfo && (
              <Typography.Text>{`当前用户：${userInfo.username}（ID：${userInfo.id}）`}</Typography.Text>
            )}
          </div>
          <Button theme="solid" type="tertiary" onClick={() => navigate(ROUTES.USER)}>
            返回用户列表
          </Button>
        </div>
      </Layout.Header>
      <Layout.Content>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}>
            <Spin />
          </div>
        ) : (
          <TokensTable userId={userId} />
        )}
      </Layout.Content>
    </Layout>
  );
};

export default UserTokens;
