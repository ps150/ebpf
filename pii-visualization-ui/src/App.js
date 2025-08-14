import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import { PrimeReactProvider } from 'primereact/api';
import PIIFlowDashboard from './PIIFlowDashboard';
import Login from './Login';
import Register from './Registration';
import authService from './authService';
import 'primereact/resources/themes/saga-blue/theme.css';
import 'primereact/resources/primereact.min.css';
import 'primeicons/primeicons.css';
import 'reactflow/dist/style.css';
import './index.css';

// Protected route component to secure dashboard
const ProtectedRoute = ({ children }) => {
  if (!authService.isAuthenticated()) {
    return <Navigate to="/login" />;
  }
  return children;
};

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check authentication status when app loads
    setIsAuthenticated(authService.isAuthenticated());
    
    // Listen for authentication changes
    const checkAuthentication = () => {
      setIsAuthenticated(authService.isAuthenticated());
    };
    
    window.addEventListener('storage', checkAuthentication);
    
    return () => {
      window.removeEventListener('storage', checkAuthentication);
    };
  }, []);

  return (
    <PrimeReactProvider>
      <Router>
        <Routes>
          {/* Authentication routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          
          {/* Protected dashboard route */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <PIIFlowDashboard />
              </ProtectedRoute>
            }
          />
          
          {/* Default route redirects based on auth status */}
          <Route
            path="*"
            element={
              isAuthenticated ? 
              <Navigate to="/dashboard" /> : 
              <Navigate to="/login" />
            }
          />
        </Routes>
      </Router>
    </PrimeReactProvider>
  );
}

export default App;
