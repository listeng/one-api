import React, { lazy, Suspense, useContext, useEffect } from 'react';
import { Route, Routes } from 'react-router-dom';
import Loading from './components/Loading';
import User from './pages/User';
import { PrivateRoute } from './components/PrivateRoute';
import RegisterForm from './components/RegisterForm';
import LoginForm from './components/LoginForm';
import NotFound from './pages/NotFound';
import Setting from './pages/Setting';
import EditUser from './pages/User/EditUser';
import { getLogo, getSystemName } from './helpers';
import PasswordResetForm from './components/PasswordResetForm';
import GitHubOAuth from './components/GitHubOAuth';
import CASOAuth from './components/CASOAuth';
import CASCallback from './pages/CASCallback';
import PasswordResetConfirm from './components/PasswordResetConfirm';
import { UserContext } from './context/User';
import Channel from './pages/Channel';
import Token from './pages/Token';
import UserTokens from './pages/UserTokens';
import EditChannel from './pages/Channel/EditChannel';
import Redemption from './pages/Redemption';
import TopUp from './pages/TopUp';
import Log from './pages/Log';
import Chat from './pages/Chat';
import { Layout } from '@douyinfe/semi-ui';
import Midjourney from './pages/Midjourney';
import Detail from './pages/Detail';
import { ROUTES } from './helpers/routes';

const Home = lazy(() => import('./pages/Home'));
const About = lazy(() => import('./pages/About'));

function App() {
  const [userState, userDispatch] = useContext(UserContext);
  // const [statusState, statusDispatch] = useContext(StatusContext);

  const loadUser = () => {
    let user = localStorage.getItem('user');
    if (user) {
      let data = JSON.parse(user);
      userDispatch({ type: 'login', payload: data });
    }
  };

  useEffect(() => {
    loadUser();
    let systemName = getSystemName();
    if (systemName) {
      document.title = systemName;
    }
    let logo = getLogo();
    if (logo) {
      let linkElement = document.querySelector('link[rel~=\'icon\']');
      if (linkElement) {
        linkElement.href = logo;
      }
    }
  }, []);

  return (
    <Layout>
      <Layout.Content>
        <Routes>
          <Route
            path={ROUTES.HOME}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <Home />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.CHANNEL}
            element={
              <PrivateRoute>
                <Channel />
              </PrivateRoute>
            }
          />
          <Route
            path={`${ROUTES.CHANNEL}/edit/:id`}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <EditChannel />
              </Suspense>
            }
          />
          <Route
            path={`${ROUTES.CHANNEL}/add`}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <EditChannel />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.TOKEN}
            element={
              <PrivateRoute>
                <Token />
              </PrivateRoute>
            }
          />
          <Route
            path={ROUTES.REDEMPTION}
            element={
              <PrivateRoute>
                <Redemption />
              </PrivateRoute>
            }
          />
          <Route
            path={ROUTES.USER}
            element={
              <PrivateRoute>
                <User />
              </PrivateRoute>
            }
          />
          <Route
            path={ROUTES.USER_TOKENS}
            element={
              <PrivateRoute>
                <UserTokens />
              </PrivateRoute>
            }
          />
          <Route
            path={`${ROUTES.USER}/edit/:id`}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <EditUser />
              </Suspense>
            }
          />
          <Route
            path={`${ROUTES.USER}/edit`}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <EditUser />
              </Suspense>
            }
          />
          <Route
            path={`${ROUTES.USER}/reset`}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <PasswordResetConfirm />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.LOGIN}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <LoginForm />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.REGISTER}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <RegisterForm />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.RESET}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <PasswordResetForm />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.OAUTH_GITHUB}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <GitHubOAuth />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.OAUTH_CAS}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <CASOAuth />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.OAUTH_CAS_CALLBACK}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <CASCallback />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.SETTING}
            element={
              <PrivateRoute>
                <Suspense fallback={<Loading></Loading>}>
                  <Setting />
                </Suspense>
              </PrivateRoute>
            }
          />
          <Route
            path={`${ROUTES.BASE_PATH}/topup`}
            element={
              <PrivateRoute>
                <Suspense fallback={<Loading></Loading>}>
                  <TopUp />
                </Suspense>
              </PrivateRoute>
            }
          />
          <Route
            path={ROUTES.LOG}
            element={
              <PrivateRoute>
                <Log />
              </PrivateRoute>
            }
          />
          <Route
            path={`${ROUTES.BASE_PATH}/detail`}
            element={
              <PrivateRoute>
                <Detail />
              </PrivateRoute>
            }
          />
          <Route
            path={ROUTES.MIDJOURNEY}
            element={
              <PrivateRoute>
                <Midjourney />
              </PrivateRoute>
            }
          />
          <Route
            path={ROUTES.ABOUT}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <About />
              </Suspense>
            }
          />
          <Route
            path={ROUTES.CHAT}
            element={
              <Suspense fallback={<Loading></Loading>}>
                <Chat />
              </Suspense>
            }
          />
          <Route path="*" element={
            <NotFound />
          } />
        </Routes>
      </Layout.Content>
    </Layout>
  );
}

export default App;
