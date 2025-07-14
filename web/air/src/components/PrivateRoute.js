import { Navigate } from 'react-router-dom';

import { history } from '../helpers';
import { ROUTES } from '../helpers/routes';


function PrivateRoute({ children }) {
  if (!localStorage.getItem('user')) {
    return <Navigate to={ROUTES.LOGIN} state={{ from: history.location }} />;
  }
  return children;
}

export { PrivateRoute };