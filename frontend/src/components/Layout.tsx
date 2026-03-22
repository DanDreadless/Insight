import type { ReactNode } from 'react'
import Navbar from './Navbar'
import Footer from './Footer'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen flex flex-col" style={{ backgroundColor: '#353E43' }}>
      <Navbar />
      <main className="flex-1 pt-14">
        <div className="max-w-screen-xl mx-auto px-4 py-8">
          {children}
        </div>
      </main>
      <Footer />
    </div>
  )
}
