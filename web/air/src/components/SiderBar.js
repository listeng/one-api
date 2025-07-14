import React, { useContext, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { UserContext } from '../context/User';
import { StatusContext } from '../context/Status';

import { API, getLogo, getSystemName, isAdmin, isMobile, showError } from '../helpers';
import { ROUTES } from '../helpers/routes';
import '../index.css';

import {
  IconCalendarClock,
  IconComment,
  IconCreditCard,
  IconGift,
  IconHistogram,
  IconHome,
  IconImage,
  IconKey,
  IconLayers,
  IconSetting,
  IconSend,
  IconUser
} from '@douyinfe/semi-icons';
import { Layout, Nav } from '@douyinfe/semi-ui';

// HeaderBar Buttons

const SiderBar = () => {
  const [userState, userDispatch] = useContext(UserContext);
  const [statusState, statusDispatch] = useContext(StatusContext);
  const defaultIsCollapsed = isMobile() || localStorage.getItem('default_collapse_sidebar') === 'true';

  let navigate = useNavigate();
  const [selectedKeys, setSelectedKeys] = useState(['home']);
  const systemName = getSystemName();
  const logo = getLogo();
  const [isCollapsed, setIsCollapsed] = useState(defaultIsCollapsed);

  const headerButtons = useMemo(() => [
    {
      text: '首页',
      itemKey: 'home',
      to: ROUTES.HOME,
      icon: <IconHome />
    },
    {
      text: '渠道',
      itemKey: 'channel',
      to: ROUTES.CHANNEL,
      icon: <IconLayers />,
      className: isAdmin() ? 'semi-navigation-item-normal' : 'tableHiddle'
    },
    {
      text: '聊天',
      itemKey: 'chat',
      to: ROUTES.CHAT,
      icon: <IconComment />,
      className: localStorage.getItem('chat_link') ? 'semi-navigation-item-normal' : 'tableHiddle'
    },
    {
      text: '令牌',
      itemKey: 'token',
      to: ROUTES.TOKEN,
      icon: <IconKey />
    },
    // 根据设置决定是否显示兑换菜单
    ...(localStorage.getItem('RedemptionMenuEnabled') !== 'false' ? [{
      text: '兑换',
      itemKey: 'redemption',
      to: ROUTES.REDEMPTION,
      icon: <IconGift />,
      className: isAdmin() ? 'semi-navigation-item-normal' : 'tableHiddle'
    }] : []),
    // 根据设置决定是否显示充值菜单
    ...(localStorage.getItem('TopUpMenuEnabled') !== 'false' ? [{
      text: '充值',
      itemKey: 'topup',
      to: `${ROUTES.BASE_PATH}/topup`,
      icon: <IconCreditCard />
    }] : []),
    {
      text: '用户',
      itemKey: 'user',
      to: ROUTES.USER,
      icon: <IconUser />,
      className: isAdmin() ? 'semi-navigation-item-normal' : 'tableHiddle'
    },
    {
      text: '日志',
      itemKey: 'log',
      to: ROUTES.LOG,
      icon: <IconHistogram />
    },
    {
      text: '数据看板',
      itemKey: 'detail',
      to: `${ROUTES.BASE_PATH}/detail`,
      icon: <IconCalendarClock />,
      className: localStorage.getItem('enable_data_export') === 'true' ? 'semi-navigation-item-normal' : 'tableHiddle'
    },
    {
      text: '绘图',
      itemKey: 'midjourney',
      to: ROUTES.MIDJOURNEY,
      icon: <IconImage />,
      className: localStorage.getItem('enable_drawing') === 'true' ? 'semi-navigation-item-normal' : 'tableHiddle'
    },
    {
      text: '设置',
      itemKey: 'setting',
      to: ROUTES.SETTING,
      icon: <IconSetting />
    },
    {
        text: '关于',
        itemKey: 'about',
        to: ROUTES.ABOUT,
        icon: <IconSend/>
    }
  ], [localStorage.getItem('enable_data_export'), localStorage.getItem('enable_drawing'), localStorage.getItem('chat_link'), localStorage.getItem('RedemptionMenuEnabled'), localStorage.getItem('TopUpMenuEnabled'), isAdmin()]);

  const loadStatus = async () => {
    const res = await API.get('/api/status');
    const { success, data } = res.data;
    if (success) {
      localStorage.setItem('status', JSON.stringify(data));
      statusDispatch({ type: 'set', payload: data });
      localStorage.setItem('system_name', data.system_name);
      localStorage.setItem('logo', data.logo);
      localStorage.setItem('footer_html', data.footer_html);
      localStorage.setItem('quota_per_unit', data.quota_per_unit);
      localStorage.setItem('display_in_currency', data.display_in_currency);
      localStorage.setItem('enable_drawing', data.enable_drawing);
      localStorage.setItem('enable_data_export', data.enable_data_export);
      localStorage.setItem('data_export_default_time', data.data_export_default_time);
      localStorage.setItem('default_collapse_sidebar', data.default_collapse_sidebar);
      localStorage.setItem('mj_notify_enabled', data.mj_notify_enabled);
      localStorage.setItem('RedemptionMenuEnabled', data.RedemptionMenuEnabled);
      localStorage.setItem('TopUpMenuEnabled', data.TopUpMenuEnabled);
      if (data.chat_link) {
        localStorage.setItem('chat_link', data.chat_link);
      } else {
        localStorage.removeItem('chat_link');
      }
      if (data.chat_link2) {
        localStorage.setItem('chat_link2', data.chat_link2);
      } else {
        localStorage.removeItem('chat_link2');
      }
    } else {
      showError('无法正常连接至服务器！');
    }
  };

  useEffect(() => {
    loadStatus().then(() => {
      setIsCollapsed(isMobile() || localStorage.getItem('default_collapse_sidebar') === 'true');
    });
  }, []);

  return (
    <>
      <Layout>
        <div style={{ height: '100%' }}>
          <Nav
            // bodyStyle={{ maxWidth: 200 }}
            style={{ maxWidth: 200 }}
            defaultIsCollapsed={isMobile() || localStorage.getItem('default_collapse_sidebar') === 'true'}
            isCollapsed={isCollapsed}
            onCollapseChange={collapsed => {
              setIsCollapsed(collapsed);
            }}
            selectedKeys={selectedKeys}
            renderWrapper={({ itemElement, isSubNav, isInSubNav, props }) => {
              const routerMap = {
                home: ROUTES.HOME,
                channel: ROUTES.CHANNEL,
                token: ROUTES.TOKEN,
                redemption: ROUTES.REDEMPTION,
                topup: `${ROUTES.BASE_PATH}/topup`,
                user: ROUTES.USER,
                log: ROUTES.LOG,
                midjourney: ROUTES.MIDJOURNEY,
                setting: ROUTES.SETTING,
                about: ROUTES.ABOUT,
                chat: ROUTES.CHAT,
                detail: `${ROUTES.BASE_PATH}/detail`
              };
              return (
                <Link
                  style={{ textDecoration: 'none' }}
                  to={routerMap[props.itemKey]}
                >
                  {itemElement}
                </Link>
              );
            }}
            items={headerButtons}
            onSelect={key => {
              setSelectedKeys([key.itemKey]);
            }}
            header={{
              logo: <img src={logo} alt="logo" style={{ marginRight: '0.75em' }} />,
              text: systemName
            }}
            // footer={{
            //   text: '© 2021 NekoAPI',
            // }}
          >

            <Nav.Footer collapseButton={true}>
            </Nav.Footer>
          </Nav>
        </div>
      </Layout>
    </>
  );
};

export default SiderBar;
