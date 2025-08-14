// src/components/Login.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from 'primereact/button';
import { InputText } from 'primereact/inputtext';
import { Card } from 'primereact/card';
import { Password } from 'primereact/password';
import { Message } from 'primereact/message';
import authService from './authService';
import './Auth.css';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Redirect if already logged in
    if (authService.isAuthenticated()) {
      navigate('/dashboard');
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      await authService.login(username, password);
      navigate('/dashboard');
    } catch (err) {
      setError(
        err.response?.data?.message || 
        'Invalid username or password. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <Card className="auth-card">
        <h2 className="auth-title">PII Dashboard Login</h2>
        <form onSubmit={handleSubmit}>
          <div className="p-field">
            <label htmlFor="username">Username</label>
            <InputText
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full"
              required
            />
          </div>
          <div className="p-field">
            <label htmlFor="password">Password</label>
            <Password
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full"
              toggleMask
              feedback={false}
              required
            />
          </div>
          {error && <div className="p-error">{error}</div>}
          <Button 
            label="Login" 
            type="submit" 
            className="p-button-raised p-button-primary" 
            loading={loading}
            icon="pi pi-sign-in"
            iconPos="right"
          />
        </form>
        <div className="auth-footer">
          Don't have an account? <a href="/register">Register here</a>
        </div>
      </Card>
    </div>
  );
};

export default Login;
