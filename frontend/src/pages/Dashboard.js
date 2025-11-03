import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CircularProgress,
} from '@mui/material';
import {
  BugReport as BugIcon,
  Scanner as ScanIcon,
  TrackChanges as TargetIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';
import { getStatistics } from '../api/api';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

function StatCard({ title, value, icon, color }) {
  return (
    <Card elevation={3}>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography color="textSecondary" variant="body2" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" fontWeight="bold">
              {value}
            </Typography>
          </Box>
          <Box
            sx={{
              backgroundColor: color,
              borderRadius: '50%',
              width: 60,
              height: 60,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStatistics();
  }, []);

  const fetchStatistics = async () => {
    try {
      const response = await getStatistics();
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch statistics:', error);
      // Set default stats on error
      setStats({
        targets: 0,
        scans: 0,
        findings: 0,
        severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        scan_status_breakdown: { pending: 0, running: 0, completed: 0, failed: 0 }
      });
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!stats) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <Typography variant="h6">Failed to load statistics</Typography>
      </Box>
    );
  }

  const severityData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [
      {
        data: [
          stats?.severity_breakdown?.critical || 0,
          stats?.severity_breakdown?.high || 0,
          stats?.severity_breakdown?.medium || 0,
          stats?.severity_breakdown?.low || 0,
          stats?.severity_breakdown?.info || 0,
        ],
        backgroundColor: [
          '#d32f2f',
          '#f57c00',
          '#fbc02d',
          '#388e3c',
          '#1976d2',
        ],
      },
    ],
  };

  const statusData = {
    labels: ['Completed', 'Running', 'Pending', 'Failed'],
    datasets: [
      {
        label: 'Scans',
        data: [
          stats?.scan_status_breakdown?.completed || 0,
          stats?.scan_status_breakdown?.running || 0,
          stats?.scan_status_breakdown?.pending || 0,
          stats?.scan_status_breakdown?.failed || 0,
        ],
        backgroundColor: ['#4caf50', '#2196f3', '#ff9800', '#f44336'],
      },
    ],
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom fontWeight="bold">
        Dashboard
      </Typography>
      <Typography variant="body1" color="textSecondary" paragraph>
        Genel Güvenlik Test İstatistikleri
      </Typography>

      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Targets"
            value={stats?.targets || 0}
            icon={<TargetIcon sx={{ fontSize: 30, color: '#fff' }} />}
            color="#1976d2"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Scans"
            value={stats?.scans || 0}
            icon={<ScanIcon sx={{ fontSize: 30, color: '#fff' }} />}
            color="#f57c00"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Findings"
            value={stats?.findings || 0}
            icon={<BugIcon sx={{ fontSize: 30, color: '#fff' }} />}
            color="#d32f2f"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Critical Issues"
            value={stats?.severity_breakdown?.critical || 0}
            icon={<SecurityIcon sx={{ fontSize: 30, color: '#fff' }} />}
            color="#9c27b0"
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom fontWeight="bold">
              Findings by Severity
            </Typography>
            <Box display="flex" justifyContent="center" mt={2}>
              <Box width="300px" height="300px">
                <Pie data={severityData} options={{ maintainAspectRatio: false }} />
              </Box>
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom fontWeight="bold">
              Scans by Status
            </Typography>
            <Box mt={2}>
              <Bar data={statusData} options={{ maintainAspectRatio: true }} />
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;

