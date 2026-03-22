interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg'
}

const sizeMap = {
  sm: 'w-4 h-4 border-2',
  md: 'w-8 h-8 border-2',
  lg: 'w-12 h-12 border-4',
}

export default function LoadingSpinner({ size = 'md' }: LoadingSpinnerProps) {
  return (
    <div
      className={`${sizeMap[size]} rounded-full animate-spin`}
      style={{
        borderColor: 'rgba(189,54,58,0.2)',
        borderTopColor: '#bd363a',
      }}
      role="status"
      aria-label="Loading"
    />
  )
}
