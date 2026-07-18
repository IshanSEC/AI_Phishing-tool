import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

interface GaugeMeterProps {
  score: number; // 0 - 100
  size?: number;
}

export const GaugeMeter: React.FC<GaugeMeterProps> = ({ score, size = 200 }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Standard numerical counter animation
    const duration = 1000;
    const startTime = performance.now();
    const startValue = animatedScore;

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out quad
      const ease = progress * (2 - progress);
      const currentVal = Math.round(startValue + (score - startValue) * ease);
      setAnimatedScore(currentVal);

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [score]);

  // Gauge calculations
  const radius = size * 0.4;
  const strokeWidth = size * 0.08;
  const cx = size / 2;
  const cy = size / 2 + 10;
  
  // Circumference for 180-degree semi-circle arc
  const arcLength = Math.PI * radius;
  const strokeDashoffset = arcLength - (animatedScore / 100) * arcLength;

  // Needle rotation: -90deg (for 0 score) to +90deg (for 100 score)
  const needleRotation = -90 + (animatedScore / 100) * 180;

  // Colors based on score
  let strokeColor = '#10b981'; // Green
  let shadowColor = 'rgba(16, 185, 129, 0.4)';
  let threatLabel = 'SAFE';

  if (score >= 75) {
    strokeColor = '#ef4444'; // Red
    shadowColor = 'rgba(239, 68, 68, 0.4)';
    threatLabel = 'CRITICAL THREAT';
  } else if (score >= 30) {
    strokeColor = '#f59e0b'; // Orange
    shadowColor = 'rgba(245, 158, 11, 0.4)';
    threatLabel = 'SUSPICIOUS';
  }

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative" style={{ width: size, height: size * 0.65 }}>
        <svg width={size} height={size * 0.7} className="overflow-visible">
          {/* Background Arc */}
          <path
            d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Active Gradient Arc */}
          <path
            d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
            fill="none"
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={arcLength}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0px 0px 8px ${strokeColor})`,
              transition: 'stroke 0.5s ease',
            }}
          />
          {/* Center Hub */}
          <circle cx={cx} cy={cy} r="8" fill="#f8fafc" />
          <circle cx={cx} cy={cy} r="4" fill="#050816" />

          {/* Needle Indicator */}
          <motion.g
            initial={{ rotate: -90 }}
            animate={{ rotate: needleRotation }}
            transition={{ type: 'spring', stiffness: 50, damping: 15 }}
            style={{ originX: `${cx}px`, originY: `${cy}px` }}
          >
            <line
              x1={cx}
              y1={cy}
              x2={cx}
              y2={cy - radius + 15}
              stroke="#f8fafc"
              strokeWidth="3"
              strokeLinecap="round"
            />
            <polygon
              points={`${cx - 5},${cy} ${cx + 5},${cy} ${cx},${cy - radius + 5}`}
              fill="#f8fafc"
            />
          </motion.g>
        </svg>

        {/* Center Digital Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-2">
          <span className="text-4xl font-bold tracking-tight text-white font-mono leading-none">
            {animatedScore}
            <span className="text-lg text-cyber-gray">%</span>
          </span>
          <span 
            className="text-xs font-extrabold tracking-widest mt-1 font-mono uppercase"
            style={{ color: strokeColor, textShadow: `0 0 8px ${shadowColor}` }}
          >
            {threatLabel}
          </span>
        </div>
      </div>
    </div>
  );
};
export default GaugeMeter;
