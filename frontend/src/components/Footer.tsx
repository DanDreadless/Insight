export default function Footer() {
  return (
    <footer
      className="py-6 text-center text-sm"
      style={{ backgroundColor: '#2a3238', color: 'rgba(255,255,255,0.4)' }}
    >
      <p>
        &copy; 2026 Vault1337 &middot; Passive web threat scanner &middot;{' '}
        <a
          href="https://insight.vault1337.com"
          className="hover:text-white/70 transition-colors"
          style={{ color: 'rgba(255,255,255,0.4)' }}
          rel="noopener noreferrer"
          target="_blank"
        >
          insight.vault1337.com
        </a>
      </p>
    </footer>
  )
}
