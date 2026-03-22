import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 h-14 flex items-center px-4"
      style={{ backgroundColor: '#2a3238' }}
    >
      <div className="max-w-screen-xl mx-auto w-full flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2 no-underline">
          <span
            className="text-lg font-bold tracking-widest"
            style={{ color: '#bd363a' }}
          >
            INSIGHT
          </span>
          <span className="text-white/40 text-lg">|</span>
          <span className="text-white font-semibold tracking-wide">vault1337</span>
        </Link>

        {/* Desktop nav */}
        <div className="hidden md:flex items-center gap-6">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              `text-sm font-medium transition-colors ${isActive ? 'text-[#bd363a]' : 'text-white/80 hover:text-white'}`
            }
          >
            Home
          </NavLink>
          <NavLink
            to="/history"
            className={({ isActive }) =>
              `text-sm font-medium transition-colors ${isActive ? 'text-[#bd363a]' : 'text-white/80 hover:text-white'}`
            }
          >
            History
          </NavLink>
          <NavLink
            to="/about"
            className={({ isActive }) =>
              `text-sm font-medium transition-colors ${isActive ? 'text-[#bd363a]' : 'text-white/80 hover:text-white'}`
            }
          >
            About
          </NavLink>
        </div>

        {/* Mobile hamburger */}
        <button
          className="md:hidden flex flex-col gap-1.5 p-2 cursor-pointer"
          onClick={() => setMenuOpen((o) => !o)}
          aria-label="Toggle menu"
          aria-expanded={menuOpen}
        >
          <span
            className={`block w-5 h-0.5 bg-white transition-transform ${menuOpen ? 'rotate-45 translate-y-2' : ''}`}
          />
          <span
            className={`block w-5 h-0.5 bg-white transition-opacity ${menuOpen ? 'opacity-0' : ''}`}
          />
          <span
            className={`block w-5 h-0.5 bg-white transition-transform ${menuOpen ? '-rotate-45 -translate-y-2' : ''}`}
          />
        </button>
      </div>

      {/* Mobile menu dropdown */}
      {menuOpen && (
        <div
          className="absolute top-14 left-0 right-0 flex flex-col p-4 gap-4 md:hidden"
          style={{ backgroundColor: '#2a3238', borderTop: '1px solid rgba(255,255,255,0.1)' }}
        >
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              `text-sm font-medium ${isActive ? 'text-[#bd363a]' : 'text-white/80'}`
            }
            onClick={() => setMenuOpen(false)}
          >
            Home
          </NavLink>
          <NavLink
            to="/history"
            className={({ isActive }) =>
              `text-sm font-medium ${isActive ? 'text-[#bd363a]' : 'text-white/80'}`
            }
            onClick={() => setMenuOpen(false)}
          >
            History
          </NavLink>
          <NavLink
            to="/about"
            className={({ isActive }) =>
              `text-sm font-medium ${isActive ? 'text-[#bd363a]' : 'text-white/80'}`
            }
            onClick={() => setMenuOpen(false)}
          >
            About
          </NavLink>
        </div>
      )}
    </nav>
  )
}
