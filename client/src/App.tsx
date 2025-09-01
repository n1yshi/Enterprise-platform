import React, { Suspense, useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, GlobalStyles } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { HelmetProvider } from 'react-helmet-async';
import { ErrorBoundary } from 'react-error-boundary';
import { Toaster } from 'react-hot-toast';
import { AnimatePresence } from 'framer-motion';
import { I18nextProvider } from 'react-i18next';

import { store, persistor } from './store';
import { useAppSelector, useAppDispatch } from './hooks/redux';
import { useAuth } from './hooks/useAuth';
import { useTheme } from './hooks/useTheme';
import { useWebSocket } from './hooks/useWebSocket';
import { useAnalytics } from './hooks/useAnalytics';
import { useNotifications } from './hooks/useNotifications';
import { usePerformanceMonitoring } from './hooks/usePerformanceMonitoring';

import i18n from './i18n';
import { authService } from './services/auth';
import { analyticsService } from './services/analytics';
import { notificationService } from './services/notifications';

import LoadingSpinner from './components/ui/LoadingSpinner';
import ErrorFallback from './components/ui/ErrorFallback';
import Layout from './components/layout/Layout';
import ProtectedRoute from './components/auth/ProtectedRoute';
import PWAInstallPrompt from './components/pwa/PWAInstallPrompt';
import CookieConsent from './components/legal/CookieConsent';
import MaintenanceMode from './components/system/MaintenanceMode';
import NetworkStatus from './components/system/NetworkStatus';

const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Analytics = React.lazy(() => import('./pages/Analytics'));
const Projects = React.lazy(() => import('./pages/Projects'));
const ProjectDetail = React.lazy(() => import('./pages/ProjectDetail'));
const Tasks = React.lazy(() => import('./pages/Tasks'));
const TaskDetail = React.lazy(() => import('./pages/TaskDetail'));
const Team = React.lazy(() => import('./pages/Team'));
const UserProfile = React.lazy(() => import('./pages/UserProfile'));
const Settings = React.lazy(() => import('./pages/Settings'));
const Reports = React.lazy(() => import('./pages/Reports'));
const Integrations = React.lazy(() => import('./pages/Integrations'));
const Workflows = React.lazy(() => import('./pages/Workflows'));
const Calendar = React.lazy(() => import('./pages/Calendar'));
const Files = React.lazy(() => import('./pages/Files'));
const Notifications = React.lazy(() => import('./pages/Notifications'));
const Billing = React.lazy(() => import('./pages/Billing'));
const Admin = React.lazy(() => import('./pages/Admin'));
const Login = React.lazy(() => import('./pages/auth/Login'));
const Register = React.lazy(() => import('./pages/auth/Register'));
const ForgotPassword = React.lazy(() => import('./pages/auth/ForgotPassword'));
const ResetPassword = React.lazy(() => import('./pages/auth/ResetPassword'));
const EmailVerification = React.lazy(() => import('./pages/auth/EmailVerification'));
const TwoFactorAuth = React.lazy(() => import('./pages/auth/TwoFactorAuth'));
const NotFound = React.lazy(() => import('./pages/NotFound'));
const Unauthorized = React.lazy(() => import('./pages/Unauthorized'));
const ServerError = React.lazy(() => import('./pages/ServerError'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000,
      cacheTime: 10 * 60 * 1000,
      retry: (failureCount, error: any) => {
        if (error?.status === 404 || error?.status === 403) return false;
        return failureCount < 3;
      },
      refetchOnWindowFocus: false,
      refetchOnReconnect: true,
    },
    mutations: {
      retry: 1,
    },
  },
});

const globalStyles = (
  <GlobalStyles
    styles={{
      '*': {
        boxSizing: 'border-box',
      },
      html: {
        WebkitFontSmoothing: 'antialiased',
        MozOsxFontSmoothing: 'grayscale',
        height: '100%',
        width: '100%',
      },
      body: {
        height: '100%',
        width: '100%',
        margin: 0,
        padding: 0,
        fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
      },
      '#root': {
        height: '100%',
        width: '100%',
      },
      '.nprogress-bar': {
        background: '#1976d2 !important',
        height: '3px !important',
      },
      '.nprogress-peg': {
        boxShadow: '0 0 10px #1976d2, 0 0 5px #1976d2 !important',
      },
      '.nprogress-spinner-icon': {
        borderTopColor: '#1976d2 !important',
        borderLeftColor: '#1976d2 !important',
      },
    }}
  />
);

interface AppContentProps {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: any;
  theme: any;
  isMaintenanceMode: boolean;
}

const AppContent: React.FC<AppContentProps> = ({
  isAuthenticated,
  isLoading,
  user,
  theme,
  isMaintenanceMode,
}) => {
  const { trackPageView } = useAnalytics();
  const { isOnline } = useNetworkStatus();

  useEffect(() => {
    trackPageView(window.location.pathname);
  }, [trackPageView]);

  if (isMaintenanceMode) {
    return <MaintenanceMode />;
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {globalStyles}
      <LocalizationProvider dateAdapter={AdapterDateFns}>
        <Router>
          <AnimatePresence mode="wait">
            <Routes>
              <Route
                path="/login"
                element={
                  isAuthenticated ? (
                    <Navigate to="/dashboard" replace />
                  ) : (
                    <Suspense fallback={<LoadingSpinner />}>
                      <Login />
                    </Suspense>
                  )
                }
              />
              <Route
                path="/register"
                element={
                  isAuthenticated ? (
                    <Navigate to="/dashboard" replace />
                  ) : (
                    <Suspense fallback={<LoadingSpinner />}>
                      <Register />
                    </Suspense>
                  )
                }
              />
              <Route
                path="/forgot-password"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <ForgotPassword />
                  </Suspense>
                }
              />
              <Route
                path="/reset-password/:token"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <ResetPassword />
                  </Suspense>
                }
              />
              <Route
                path="/verify-email/:token"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <EmailVerification />
                  </Suspense>
                }
              />
              <Route
                path="/two-factor"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <TwoFactorAuth />
                  </Suspense>
                }
              />

              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Layout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route
                  path="dashboard"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Dashboard />
                    </Suspense>
                  }
                />
                <Route
                  path="analytics"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Analytics />
                    </Suspense>
                  }
                />
                <Route
                  path="projects"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Projects />
                    </Suspense>
                  }
                />
                <Route
                  path="projects/:id"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <ProjectDetail />
                    </Suspense>
                  }
                />
                <Route
                  path="tasks"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Tasks />
                    </Suspense>
                  }
                />
                <Route
                  path="tasks/:id"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <TaskDetail />
                    </Suspense>
                  }
                />
                <Route
                  path="team"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Team />
                    </Suspense>
                  }
                />
                <Route
                  path="profile"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <UserProfile />
                    </Suspense>
                  }
                />
                <Route
                  path="settings"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Settings />
                    </Suspense>
                  }
                />
                <Route
                  path="reports"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Reports />
                    </Suspense>
                  }
                />
                <Route
                  path="integrations"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Integrations />
                    </Suspense>
                  }
                />
                <Route
                  path="workflows"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Workflows />
                    </Suspense>
                  }
                />
                <Route
                  path="calendar"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Calendar />
                    </Suspense>
                  }
                />
                <Route
                  path="files"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Files />
                    </Suspense>
                  }
                />
                <Route
                  path="notifications"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Notifications />
                    </Suspense>
                  }
                />
                <Route
                  path="billing"
                  element={
                    <Suspense fallback={<LoadingSpinner />}>
                      <Billing />
                    </Suspense>
                  }
                />
                <Route
                  path="admin/*"
                  element={
                    <ProtectedRoute requiredRole="admin">
                      <Suspense fallback={<LoadingSpinner />}>
                        <Admin />
                      </Suspense>
                    </ProtectedRoute>
                  }
                />
              </Route>

              <Route
                path="/unauthorized"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <Unauthorized />
                  </Suspense>
                }
              />
              <Route
                path="/server-error"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <ServerError />
                  </Suspense>
                }
              />
              <Route
                path="*"
                element={
                  <Suspense fallback={<LoadingSpinner />}>
                    <NotFound />
                  </Suspense>
                }
              />
            </Routes>
          </AnimatePresence>

          <NetworkStatus isOnline={isOnline} />
          <PWAInstallPrompt />
          <CookieConsent />
          
          <Toaster
            position="top-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: theme.palette.background.paper,
                color: theme.palette.text.primary,
                border: `1px solid ${theme.palette.divider}`,
              },
              success: {
                iconTheme: {
                  primary: theme.palette.success.main,
                  secondary: theme.palette.success.contrastText,
                },
              },
              error: {
                iconTheme: {
                  primary: theme.palette.error.main,
                  secondary: theme.palette.error.contrastText,
                },
              },
            }}
          />
        </Router>
      </LocalizationProvider>
    </ThemeProvider>
  );
};

const useNetworkStatus = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return { isOnline };
};

const App: React.FC = () => {
  const [isMaintenanceMode, setIsMaintenanceMode] = useState(false);
  
  usePerformanceMonitoring();

  useEffect(() => {
    const checkMaintenanceMode = async () => {
      try {
        const response = await fetch('/api/v1/system/status');
        const data = await response.json();
        setIsMaintenanceMode(data.maintenanceMode || false);
      } catch (error) {
        console.warn('Could not check maintenance mode status');
      }
    };

    checkMaintenanceMode();
    const interval = setInterval(checkMaintenanceMode, 60000);
    return () => clearInterval(interval);
  }, []);

  return (
    <ErrorBoundary
      FallbackComponent={ErrorFallback}
      onError={(error, errorInfo) => {
        console.error('Application Error:', error, errorInfo);
        analyticsService.trackError(error, errorInfo);
      }}
    >
      <HelmetProvider>
        <I18nextProvider i18n={i18n}>
          <Provider store={store}>
            <PersistGate loading={<LoadingSpinner />} persistor={persistor}>
              <QueryClientProvider client={queryClient}>
                <AppWrapper isMaintenanceMode={isMaintenanceMode} />
                <ReactQueryDevtools initialIsOpen={false} />
              </QueryClientProvider>
            </PersistGate>
          </Provider>
        </I18nextProvider>
      </HelmetProvider>
    </ErrorBoundary>
  );
};

interface AppWrapperProps {
  isMaintenanceMode: boolean;
}

const AppWrapper: React.FC<AppWrapperProps> = ({ isMaintenanceMode }) => {
  const { isAuthenticated, isLoading, user } = useAuth();
  const { theme } = useTheme();
  
  useWebSocket(isAuthenticated);
  useNotifications(isAuthenticated);

  useEffect(() => {
    if (isAuthenticated && user) {
      analyticsService.identify(user.id, {
        email: user.email,
        name: user.name,
        role: user.role,
        organization: user.organization?.name,
      });
    }
  }, [isAuthenticated, user]);

  return (
    <AppContent
      isAuthenticated={isAuthenticated}
      isLoading={isLoading}
      user={user}
      theme={theme}
      isMaintenanceMode={isMaintenanceMode}
    />
  );
};

export default App;