import React from 'react';
import { Chip } from '@mui/material';

const severityColors = {
  critical: { bg: '#d32f2f', color: '#fff' },
  high: { bg: '#f57c00', color: '#fff' },
  medium: { bg: '#fbc02d', color: '#000' },
  low: { bg: '#388e3c', color: '#fff' },
  info: { bg: '#1976d2', color: '#fff' },
};

function SeverityChip({ severity }) {
  const colors = severityColors[severity?.toLowerCase()] || severityColors.info;

  return (
    <Chip
      label={severity?.toUpperCase()}
      size="small"
      sx={{
        backgroundColor: colors.bg,
        color: colors.color,
        fontWeight: 600,
        minWidth: 80,
      }}
    />
  );
}

export default SeverityChip;

