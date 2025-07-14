import { showError } from './utils';
import axios from 'axios';

// 获取 BASE_PATH，默认为 aigate
const BASE_PATH = process.env.REACT_APP_BASE_PATH || 'aigate';

export const API = axios.create({
  baseURL: process.env.REACT_APP_SERVER ? 
    `${process.env.REACT_APP_SERVER}/${BASE_PATH}` : 
    `/${BASE_PATH}`,
});

API.interceptors.response.use(
  (response) => response,
  (error) => {
    showError(error);
  }
);
