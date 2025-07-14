import React, { useContext, useEffect, useState } from 'react';
import { Dimmer, Loader, Segment } from 'semantic-ui-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { API, showError, showSuccess } from '../helpers';
import { UserContext } from '../context/User';

const CASOAuth = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [userState, userDispatch] = useContext(UserContext);
  const [prompt, setPrompt] = useState('处理中...');
  const [processing, setProcessing] = useState(true);

  let navigate = useNavigate();

  const sendTicket = async (ticket, service, state, count) => {
    try {
      const res = await API.get(`/api/oauth/cas?ticket=${ticket}&service=${service}&state=${state}`, {
        headers: {
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        }
      });
      const { success, message, data } = res.data;
      if (success) {
        if (message === '绑定成功') {
          showSuccess('绑定成功！');
          navigate('/setting');
        } else {
          userDispatch({ type: 'login', payload: data });
          localStorage.setItem('user', JSON.stringify(data));
          showSuccess('登录成功！');
          navigate('/');
        }
      } else {
        showError(message);
        if (count >= 2) { // 最多重试2次
          setPrompt(`操作失败，重定向至登录界面中...`);
          navigate('/setting'); // 绑定失败时重定向到设置页面
          return;
        }
        count++;
        setPrompt(`出现错误，第 ${count} 次重试中...`);
        await new Promise((resolve) => setTimeout(resolve, count * 5000)); // 增加延迟到5秒
        await sendTicket(ticket, service, state, count);
      }
    } catch (error) {
      console.error('CAS认证请求失败:', error);
      showError('网络请求失败');
      if (count >= 2) { // 最多重试2次
        setPrompt(`操作失败，重定向至登录界面中...`);
        navigate('/setting');
        return;
      }
      count++;
      setPrompt(`网络错误，第 ${count} 次重试中...`);
      await new Promise((resolve) => setTimeout(resolve, count * 5000));
      await sendTicket(ticket, service, state, count);
    }
  };

  useEffect(() => {
    let ticket = searchParams.get('ticket');
    let service = searchParams.get('service');
    let state = searchParams.get('state');
    
    if (ticket) {
      sendTicket(ticket, service, state, 0).then();
    } else {
      setPrompt('没有收到CAS票据，重定向中...');
      setTimeout(() => {
        navigate('/');
      }, 2000);
    }
  }, []);

  return (
    <Segment style={{ minHeight: '300px' }}>
      <Dimmer active inverted>
        <Loader size="large">{prompt}</Loader>
      </Dimmer>
    </Segment>
  );
};

export default CASOAuth; 