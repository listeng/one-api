// 路由前缀配置
export const BASE_PATH = process.env.REACT_APP_BASE_PATH || 'aigate';

// 生成带前缀的路由路径
export const getRoutePath = (path) => {
  // 如果路径以 / 开头，去掉开头的 /
  const cleanPath = path.startsWith('/') ? path.slice(1) : path;
  return `/${BASE_PATH}/${cleanPath}`;
};

// 常用路由路径
export const ROUTES = {
  BASE_PATH: BASE_PATH,
  HOME: getRoutePath('/'),
  LOGIN: getRoutePath('/login'),
  REGISTER: getRoutePath('/register'),
  RESET: getRoutePath('/reset'),
  CHANNEL: getRoutePath('/channel'),
  TOKEN: getRoutePath('/token'),
  REDEMPTION: getRoutePath('/redemption'),
  USER: getRoutePath('/user'),
  SETTING: getRoutePath('/setting'),
  LOG: getRoutePath('/log'),
  CHAT: getRoutePath('/chat'),
  MIDJOURNEY: getRoutePath('/midjourney'),
  ABOUT: getRoutePath('/about'),
  OAUTH_GITHUB: getRoutePath('/api/oauth/github'),
  OAUTH_CAS: getRoutePath('/api/oauth/cas'),
  OAUTH_CAS_CALLBACK: getRoutePath('/api/oauth/cas/callback'),
}; 