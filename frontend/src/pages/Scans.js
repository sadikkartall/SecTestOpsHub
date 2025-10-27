import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  IconButton,
  Tooltip,
  Chip,
} from '@mui/material';
import { Visibility as ViewIcon, Refresh as RefreshIcon } from '@mui/icons-material';
import { getScans } from '../api/api';
import StatusChip from '../components/StatusChip';

function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000); // Auto-refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchScans = async () => {
    try {
      const response = await getScans();
      setScans(response.data);
    } catch (error) {
      console.error('Failed to load scans:', error);
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

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" gutterBottom fontWeight="bold">
            Scans
          </Typography>
          <Typography variant="body1" color="textSecondary">
            View all security scans
          </Typography>
        </Box>
        <Tooltip title="Refresh">
          <IconButton onClick={fetchScans} color="primary">
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Box>

      <TableContainer component={Paper} elevation={3}>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
              <TableCell><strong>Scan ID</strong></TableCell>
              <TableCell><strong>Tools</strong></TableCell>
              <TableCell><strong>Status</strong></TableCell>
              <TableCell><strong>Started</strong></TableCell>
              <TableCell><strong>Finished</strong></TableCell>
              <TableCell align="center"><strong>Actions</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {scans.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography color="textSecondary">No scans found. Start a scan from the Targets page!</Typography>
                </TableCell>
              </TableRow>
            ) : (
              scans.map((scan) => (
                <TableRow key={scan.id} hover>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {scan.id.substring(0, 8)}...
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" gap={0.5} flexWrap="wrap">
                      {scan.tools.map((tool) => (
                        <Chip key={tool} label={tool.toUpperCase()} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <StatusChip status={scan.status} />
                  </TableCell>
                  <TableCell>
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}
                  </TableCell>
                  <TableCell>
                    {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '-'}
                  </TableCell>
                  <TableCell align="center">
                    <Tooltip title="View Details">
                      <IconButton
                        color="primary"
                        onClick={() => navigate(`/scans/${scan.id}`)}
                      >
                        <ViewIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

export default Scans;

