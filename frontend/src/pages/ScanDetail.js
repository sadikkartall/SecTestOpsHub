import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Grid,
  CircularProgress,
  Card,
  CardContent,
  Divider,
  Chip,
  Button,
  Menu,
  MenuItem,
} from '@mui/material';
import { Download as DownloadIcon } from '@mui/icons-material';
import { getScan, getScanFindings } from '../api/api';
import StatusChip from '../components/StatusChip';
import SeverityChip from '../components/SeverityChip';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function ScanDetail() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [anchorEl, setAnchorEl] = useState(null);

  const fetchScanData = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const [scanRes, findingsRes] = await Promise.all([
        getScan(scanId),
        getScanFindings(scanId),
      ]);
      setScan(scanRes.data || null);
      setFindings(findingsRes.data || []);
    } catch (error) {
      console.error('Failed to load scan data:', error);
      setScan(null);
      setFindings([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const handleDownloadClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleDownloadClose = () => {
    setAnchorEl(null);
  };

  const handleDownload = (format) => {
    const url = `${API_BASE_URL}/api/scans/${scanId}/report/${format}`;
    window.open(url, '_blank');
    handleDownloadClose();
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!scan) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <Typography variant="h6">Scan not found</Typography>
      </Box>
    );
  }

  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h4" fontWeight="bold">
          Scan Details
        </Typography>
        <Button
          variant="contained"
          startIcon={<DownloadIcon />}
          onClick={handleDownloadClick}
        >
          Download Report
        </Button>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleDownloadClose}
        >
          <MenuItem onClick={() => handleDownload('json')}>JSON Format</MenuItem>
          <MenuItem onClick={() => handleDownload('markdown')}>Markdown Format</MenuItem>
          <MenuItem onClick={() => handleDownload('pdf')}>PDF Format</MenuItem>
        </Menu>
      </Box>

      {/* Scan Info */}
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Typography variant="body2" color="textSecondary">Scan ID</Typography>
            <Typography variant="body1" fontFamily="monospace" gutterBottom>{scan.id}</Typography>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="body2" color="textSecondary">Status</Typography>
            <Box mt={0.5}>
              <StatusChip status={scan.status} />
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="body2" color="textSecondary">Tools Used</Typography>
            <Box display="flex" gap={0.5} mt={0.5} flexWrap="wrap">
              {scan.tools.map((tool) => (
                <Chip key={tool} label={tool.toUpperCase()} size="small" />
              ))}
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="body2" color="textSecondary">Duration</Typography>
            <Typography variant="body1">
              {scan.started_at && scan.finished_at
                ? `${Math.round((new Date(scan.finished_at) - new Date(scan.started_at)) / 1000)} seconds`
                : 'In progress...'}
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* Findings Summary */}
      <Typography variant="h5" gutterBottom fontWeight="bold">
        Findings ({findings.length})
      </Typography>
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
          <Grid item xs={6} sm={2.4} key={severity}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h4" fontWeight="bold" gutterBottom>
                  {severityCounts[severity] || 0}
                </Typography>
                <SeverityChip severity={severity} />
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Findings List */}
      <Typography variant="h5" gutterBottom fontWeight="bold" mt={4}>
        All Findings
      </Typography>
      {findings.length === 0 ? (
        <Paper elevation={2} sx={{ p: 3, textAlign: 'center' }}>
          <Typography color="textSecondary">No findings detected</Typography>
        </Paper>
      ) : (
        findings.map((finding) => (
          <Paper key={finding.id} elevation={2} sx={{ p: 3, mb: 2 }}>
            <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
              <Box>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  {finding.title}
                </Typography>
                <Box display="flex" gap={1} alignItems="center">
                  <SeverityChip severity={finding.severity} />
                  <Chip label={finding.tool.toUpperCase()} size="small" color="primary" variant="outlined" />
                  {finding.cve_id && <Chip label={finding.cve_id} size="small" />}
                </Box>
              </Box>
              {finding.cvss_score && (
                <Chip
                  label={`CVSS: ${finding.cvss_score}`}
                  color="error"
                  sx={{ fontWeight: 'bold' }}
                />
              )}
            </Box>

            <Divider sx={{ my: 2 }} />

            {finding.endpoint && (
              <>
                <Typography variant="body2" color="textSecondary">Endpoint</Typography>
                <Typography variant="body1" fontFamily="monospace" gutterBottom>
                  {finding.endpoint}
                </Typography>
              </>
            )}

            {finding.description && (
              <>
                <Typography variant="body2" color="textSecondary" mt={2}>Description</Typography>
                <Typography variant="body1" paragraph sx={{ whiteSpace: 'pre-line' }}>
                  {finding.description}
                </Typography>
              </>
            )}

            {finding.ai_summary && (
              <>
                <Typography variant="body2" color="textSecondary" mt={2}>AI Analysis</Typography>
                <Paper sx={{ p: 2, backgroundColor: '#f5f5f5', mt: 1 }}>
                  <Typography variant="body2" paragraph>
                    {finding.ai_summary}
                  </Typography>
                  {finding.ai_recommendation && (
                    <>
                      <Typography variant="body2" fontWeight="bold">Recommendation:</Typography>
                      <Typography variant="body2">{finding.ai_recommendation}</Typography>
                    </>
                  )}
                  {finding.probable_fp && (
                    <Chip label="Possible False Positive" size="small" color="warning" sx={{ mt: 1 }} />
                  )}
                </Paper>
              </>
            )}

            {finding.recommendation && (
              <>
                <Typography variant="body2" color="textSecondary" mt={2}>Recommendation</Typography>
                <Typography variant="body1" sx={{ whiteSpace: 'pre-line' }}>
                  {finding.recommendation}
                </Typography>
              </>
            )}

            {finding.owasp_category && (
              <Chip
                label={finding.owasp_category}
                size="small"
                color="secondary"
                variant="outlined"
                sx={{ mt: 2 }}
              />
            )}
          </Paper>
        ))
      )}
    </Box>
  );
}

export default ScanDetail;

