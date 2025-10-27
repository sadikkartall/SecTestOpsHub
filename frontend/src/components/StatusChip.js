import React from 'react';
import { Chip } from '@mui/material';
import PendingIcon from '@mui/icons-material/Pending';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';

const statusConfig = {
  pending: { color: 'default', icon: <PendingIcon />, label: 'Pending' },
  running: { color: 'info', icon: <PlayArrowIcon />, label: 'Running' },
  completed: { color: 'success', icon: <CheckCircleIcon />, label: 'Completed' },
  failed: { color: 'error', icon: <ErrorIcon />, label: 'Failed' },
};

function StatusChip({ status }) {
  const config = statusConfig[status?.toLowerCase()] || statusConfig.pending;

  return (
    <Chip
      icon={config.icon}
      label={config.label}
      color={config.color}
      size="small"
      sx={{ fontWeight: 500 }}
    />
  );
}

export default StatusChip;

