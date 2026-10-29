import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import { AppLayout } from './components/layout/AppLayout';

// Route-level code splitting via React.lazy
const RunPage = React.lazy(() => import('./pages/RunPage').then(m => ({ default: m.RunPage })));
const OverviewPage = React.lazy(() => import('./pages/OverviewPage').then(m => ({ default: m.OverviewPage })));
const TasksPage = React.lazy(() => import('./pages/TasksPage').then(m => ({ default: m.TasksPage })));
const TaskDetailPage = React.lazy(() => import('./pages/TaskDetailPage').then(m => ({ default: m.TaskDetailPage })));
const AgentsPage = React.lazy(() => import('./pages/AgentsPage').then(m => ({ default: m.AgentsPage })));
const ActivityPage = React.lazy(() => import('./pages/ActivityPage').then(m => ({ default: m.ActivityPage })));
const ApprovalsPage = React.lazy(() => import('./pages/ApprovalsPage').then(m => ({ default: m.ApprovalsPage })));
const EvaluationPage = React.lazy(() => import('./pages/EvaluationPage').then(m => ({ default: m.EvaluationPage })));
const ArchitecturePage = React.lazy(() => import('./pages/ArchitecturePage').then(m => ({ default: m.ArchitecturePage })));

const PageLoader: React.FC = () => (
  <div className="flex items-center justify-center min-h-[350px] text-slate-400 font-mono text-xs">
    <div className="flex items-center gap-2">
      <div className="w-2.5 h-2.5 rounded-full bg-cyan-500 animate-ping" />
      <span>Loading view telemetry...</span>
    </div>
  </div>
);

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter basename="/dashboard">
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="run" element={<Suspense fallback={<PageLoader />}><RunPage /></Suspense>} />
              <Route index element={<Suspense fallback={<PageLoader />}><OverviewPage /></Suspense>} />
              <Route path="tasks" element={<Suspense fallback={<PageLoader />}><TasksPage /></Suspense>} />
              <Route path="tasks/:taskId" element={<Suspense fallback={<PageLoader />}><TaskDetailPage /></Suspense>} />
              <Route path="agents" element={<Suspense fallback={<PageLoader />}><AgentsPage /></Suspense>} />
              <Route path="activity" element={<Suspense fallback={<PageLoader />}><ActivityPage /></Suspense>} />
              <Route path="approvals" element={<Suspense fallback={<PageLoader />}><ApprovalsPage /></Suspense>} />
              <Route path="evaluation" element={<Suspense fallback={<PageLoader />}><EvaluationPage /></Suspense>} />
              <Route path="architecture" element={<Suspense fallback={<PageLoader />}><ArchitecturePage /></Suspense>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
};
