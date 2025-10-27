import React, { useState, useEffect } from 'react';
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
  Chip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Grid,
} from '@mui/material';
import { getFindings } from '../api/api';
import SeverityChip from '../components/SeverityChip';

function Findings() {
  const [findings, setFindings] = useState([]);
  const [filteredFindings, setFilteredFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterTool, setFilterTool] = useState('all');

  useEffect(() => {
    fetchFindings();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [filterSeverity, filterTool, findings]);

  const fetchFindings = async () => {
    try {
      const response = await getFindings();
      setFindings(response.data);
    } catch (error) {
      console.error('Failed to load findings:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = findings;

    if (filterSeverity !== 'all') {
      filtered = filtered.filter((f) => f.severity === filterSeverity);
    }

    if (filterTool !== 'all') {
      filtered = filtered.filter((f) => f.tool === filterTool);
    }

    setFilteredFindings(filtered);
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
      <Typography variant="h4" gutterBottom fontWeight="bold">
        All Findings
      </Typography>
      <Typography variant="body1" color="textSecondary" paragraph>
        View and filter all security findings
      </Typography>

      {/* Filters */}
      <Paper elevation={2} sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth size="small">
              <InputLabel>Filter by Severity</InputLabel>
              <Select
                value={filterSeverity}
                label="Filter by Severity"
                onChange={(e) => setFilterSeverity(e.target.value)}
              >
                <MenuItem value="all">All Severities</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
                <MenuItem value="info">Info</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth size="small">
              <InputLabel>Filter by Tool</InputLabel>
              <Select
                value={filterTool}
                label="Filter by Tool"
                onChange={(e) => setFilterTool(e.target.value)}
              >
                <MenuItem value="all">All Tools</MenuItem>
                <MenuItem value="nmap">Nmap</MenuItem>
                <MenuItem value="zap">OWASP ZAP</MenuItem>
                <MenuItem value="trivy">Trivy</MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      <TableContainer component={Paper} elevation={3}>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
              <TableCell><strong>Title</strong></TableCell>
              <TableCell><strong>Tool</strong></TableCell>
              <TableCell><strong>Severity</strong></TableCell>
              <TableCell><strong>Endpoint</strong></TableCell>
              <TableCell><strong>OWASP Category</strong></TableCell>
              <TableCell><strong>Found At</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredFindings.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography color="textSecondary">No findings match the filters</Typography>
                </TableCell>
              </TableRow>
            ) : (
              filteredFindings.map((finding) => (
                <TableRow key={finding.id} hover>
                  <TableCell>
                    <Typography variant="body2">
                      {finding.title.length > 60
                        ? `${finding.title.substring(0, 60)}...`
                        : finding.title}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip label={finding.tool.toUpperCase()} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>
                    <SeverityChip severity={finding.severity} />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {finding.endpoint
                        ? finding.endpoint.length > 40
                          ? `${finding.endpoint.substring(0, 40)}...`
                          : finding.endpoint
                        : '-'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {finding.owasp_category ? (
                      <Chip label={finding.owasp_category.substring(0, 10)} size="small" />
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {new Date(finding.created_at).toLocaleString()}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Box mt={2}>
        <Typography variant="body2" color="textSecondary">
          Showing {filteredFindings.length} of {findings.length} findings
        </Typography>
      </Box>
    </Box>
  );
}

export default Findings;

