import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PEGASUS - Secure Software Intelligence Platform",
  description: "Automated Code Review, Forensics & AI Secure Coding Education",
  icons: {
    icon: "/pegasus-logo-design-free-vector.webp",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#0B0F19] text-gray-100 antialiased">
        {/* Universal Sticky Header (Visible on all pages) */}
        <header className="border-b border-gray-800 bg-[#111827]/90 backdrop-blur sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
            {/* Logo and Brand Title */}
            <a href="/" className="flex items-center space-x-3.5 group">
              {/* Pegasus Logo Container */}
              <div className="w-10 h-10 rounded-lg bg-white p-1 flex items-center justify-center shadow-md group-hover:ring-2 group-hover:ring-blue-500 transition-all overflow-hidden">
                <img
                  src="/pegasus-logo-design-free-vector.webp"
                  alt="Pegasus Logo"
                  className="w-full h-full object-contain"
                />
              </div>

              {/* Title Branding */}
              <div className="flex flex-col">
                <span className="text-base font-black tracking-wider text-white uppercase group-hover:text-blue-400 transition-colors">
                  PEGASUS
                </span>
                <span className="text-[11px] text-gray-400 tracking-tight font-medium -mt-1">
                  Secure Software Intelligence
                </span>
              </div>
            </a>

            {/* Platform Tag / Badge */}
            <div className="flex items-center space-x-3">
              <span className="text-xs bg-blue-950 text-blue-400 border border-blue-800 px-3 py-1 rounded-full font-mono font-medium">
                v1.0 • Forensics & AI Tutor
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="max-w-7xl mx-auto px-6 py-8">{children}</main>
      </body>
    </html>
  );
}