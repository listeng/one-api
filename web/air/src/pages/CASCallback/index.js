import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { API } from '../../helpers/api';
import { ROUTES } from '../../helpers/routes';

const CASCallback = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [status, setStatus] = useState('processing');
    const [message, setMessage] = useState('正在处理CAS认证...');

    useEffect(() => {
        const handleCASCallback = async () => {
            try {
                // 获取URL参数
                const urlParams = new URLSearchParams(location.search);
                const ticket = urlParams.get('ticket');
                const service = urlParams.get('service');

                if (!ticket) {
                    setStatus('error');
                    setMessage('缺少认证票据');
                    return;
                }

                // 调用CAS认证API
                const response = await API.get(`/api/oauth/cas?ticket=${ticket}&service=${encodeURIComponent(service || '')}`, {
                    withCredentials: true, // 确保包含cookie
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                const result = response.data;

                if (result.success) {
                    setStatus('success');
                    setMessage('CAS认证成功，正在跳转...');
                    
                    // 存储用户信息到localStorage（如果需要）
                    if (result.data) {
                        localStorage.setItem('user', JSON.stringify(result.data));
                    }

                    // 延迟跳转到主页
                    setTimeout(() => {
                        navigate(ROUTES.HOME, { replace: true });
                    }, 1500);
                } else {
                    setStatus('error');
                    setMessage(result.message || 'CAS认证失败');
                }
            } catch (error) {
                console.error('CAS认证处理错误:', error);
                setStatus('error');
                setMessage('网络错误，请重试');
            }
        };

        handleCASCallback();
    }, [location, navigate]);

    const getStatusIcon = () => {
        switch (status) {
            case 'success':
                return '✅';
            case 'error':
                return '❌';
            default:
                return '⏳';
        }
    };

    const getStatusClass = () => {
        switch (status) {
            case 'success':
                return 'text-green-600';
            case 'error':
                return 'text-red-600';
            default:
                return 'text-blue-600';
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
            <div className="max-w-md w-full space-y-8">
                <div className="bg-white py-8 px-6 shadow rounded-lg sm:px-10">
                    <div className="text-center">
                        <div className="text-4xl mb-4">{getStatusIcon()}</div>
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">
                            CAS认证处理
                        </h2>
                        <p className={`text-lg ${getStatusClass()}`}>
                            {message}
                        </p>
                        {status === 'error' && (
                            <button
                                onClick={() => navigate(ROUTES.HOME)}
                                className="mt-4 w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                            >
                                返回首页
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CASCallback; 