import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  CircularProgress,
  Alert,
  Tooltip,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
} from '@mui/material';
import { Add as AddIcon, Delete as DeleteIcon, Scanner as ScanIcon, PlayCircle as PlayIcon } from '@mui/icons-material';
import { getTargets, createTarget, deleteTarget, createScan, getPlaybooks } from '../api/api';

function Targets() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [newTarget, setNewTarget] = useState({ url: '', description: '' });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [scanDialog, setScanDialog] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState(null);
  const [tools, setTools] = useState({ nmap: true, zap: true, trivy: true });
  const [playbooks, setPlaybooks] = useState([]);
  const [playbookId, setPlaybookId] = useState('');

  useEffect(() => {
    fetchTargets();
    fetchPlaybooks();
  }, []);

  const fetchTargets = async () => {
    try {
      const response = await getTargets();
      setTargets(response.data);
    } catch (error) {
      setError('Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  const fetchPlaybooks = async () => {
    try {
      const res = await getPlaybooks();
      setPlaybooks(res.data || []);
    } catch (_) {
      // ignore
    }
  };

  const handleAddTarget = async () => {
    try {
      await createTarget(newTarget);
      setSuccess('Target added successfully');
      setOpenDialog(false);
      setNewTarget({ url: '', description: '' });
      fetchTargets();
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError('Failed to add target');
    }
  };

  const handleDeleteTarget = async (id) => {
    if (window.confirm('Are you sure you want to delete this target?')) {
      try {
        await deleteTarget(id);
        setSuccess('Target deleted successfully');
        fetchTargets();
        setTimeout(() => setSuccess(''), 3000);
      } catch (error) {
        setError('Failed to delete target');
      }
    }
  };

  const openScanDialog = (targetId) => {
    setSelectedTargetId(targetId);
    setScanDialog(true);
  };

  const handleStartScan = async () => {
    try {
      const selectedTools = Object.entries(tools)
        .filter(([_, v]) => v)
        .map(([k]) => k);
      await createScan({
        target_id: selectedTargetId,
        tools: selectedTools.length ? selectedTools : undefined,
        playbook_id: playbookId || undefined,
      });
      setSuccess('Scan started successfully');
      setScanDialog(false);
      setTools({ nmap: true, zap: true, trivy: true });
      setPlaybookId('');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError('Failed to start scan');
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
            Targets
          </Typography>
          <Typography variant="body1" color="textSecondary">
            Manage your scan targets
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpenDialog(true)}>
          Add Target
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>{success}</Alert>}

      <TableContainer component={Paper} elevation={3}>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
              <TableCell><strong>URL</strong></TableCell>
              <TableCell><strong>Description</strong></TableCell>
              <TableCell><strong>Created At</strong></TableCell>
              <TableCell align="center"><strong>Actions</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {targets.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <Typography color="textSecondary">No targets found. Add your first target!</Typography>
                </TableCell>
              </TableRow>
            ) : (
              targets.map((target) => (
                <TableRow key={target.id} hover>
                  <TableCell>{target.url}</TableCell>
                  <TableCell>{target.description || '-'}</TableCell>
                  <TableCell>{new Date(target.created_at).toLocaleString()}</TableCell>
                  <TableCell align="center">
                    <Tooltip title="Start Scan (quick)">
                      <IconButton color="primary" onClick={() => openScanDialog(target.id)}>
                        <ScanIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton color="error" onClick={() => handleDeleteTarget(target.id)}>
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Add Target Dialog */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add New Target</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Target URL or IP"
            fullWidth
            variant="outlined"
            value={newTarget.url}
            onChange={(e) => setNewTarget({ ...newTarget, url: e.target.value })}
            placeholder="https://example.com or 192.168.1.1"
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Description (Optional)"
            fullWidth
            variant="outlined"
            multiline
            rows={3}
            value={newTarget.description}
            onChange={(e) => setNewTarget({ ...newTarget, description: e.target.value })}
            placeholder="Description of this target..."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button onClick={handleAddTarget} variant="contained" disabled={!newTarget.url}>Add Target</Button>
        </DialogActions>
      </Dialog>

      {/* Create Scan Dialog */}
      <Dialog open={scanDialog} onClose={() => setScanDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create Scan</DialogTitle>
        <DialogContent>
          <Typography variant="subtitle2" gutterBottom>Tools</Typography>
          <FormGroup row>
            {['nmap', 'zap', 'trivy'].map((t) => (
              <FormControlLabel
                key={t}
                control={<Checkbox checked={tools[t]} onChange={(e) => setTools({ ...tools, [t]: e.target.checked })} />}
                label={t.toUpperCase()}
              />
            ))}
          </FormGroup>

          <Box mt={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Playbook (optional)</InputLabel>
              <Select value={playbookId} label="Playbook (optional)" onChange={(e) => setPlaybookId(e.target.value)}>
                <MenuItem value="">None</MenuItem>
                {playbooks.map((pb) => (
                  <MenuItem key={pb.id} value={pb.id}>{pb.name}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>

          <Box mt={2}>
            <Typography variant="body2" color="textSecondary">
              If a playbook is selected, its steps override selected tools.
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScanDialog(false)}>Cancel</Button>
          <Button onClick={handleStartScan} variant="contained" startIcon={<PlayIcon />}>Start</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Targets;

