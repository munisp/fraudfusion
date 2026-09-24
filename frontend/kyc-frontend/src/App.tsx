import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import Home from './pages/Home';

// Route-level code splitting: each verification step ships as its own chunk.
const KYCVerification = lazy(() => import('./pages/KYCVerification'));
const BiometricVerification = lazy(() => import('./pages/BiometricVerification'));
const DocumentVerification = lazy(() => import('./pages/DocumentVerification'));
const Screening = lazy(() => import('./pages/Screening'));
const RiskAssessment = lazy(() => import('./pages/RiskAssessment'));

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        {/* Navigation */}
        <nav className="bg-white shadow-lg">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex">
                <div className="flex-shrink-0 flex items-center">
                  <h1 className="text-2xl font-bold text-primary-600">KYC Verification System</h1>
                </div>
                <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
                  <Link
                    to="/"
                    className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
                  >
                    Home
                  </Link>
                  <Link
                    to="/kyc"
                    className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
                  >
                    KYC Verification
                  </Link>
                  <Link
                    to="/biometric"
                    className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
                  >
                    Biometric
                  </Link>
                  <Link
                    to="/document"
                    className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
                  >
                    Document
                  </Link>
                  <Link
                    to="/screening"
                    className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
                  >
                    Screening
                  </Link>
                  <Link
                    to="/risk"
                    className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
                  >
                    Risk Assessment
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <Suspense fallback={<p role="status" aria-live="polite" className="text-gray-500">Loading…</p>}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/kyc" element={<KYCVerification />} />
              <Route path="/biometric" element={<BiometricVerification />} />
              <Route path="/document" element={<DocumentVerification />} />
              <Route path="/screening" element={<Screening />} />
              <Route path="/risk" element={<RiskAssessment />} />
            </Routes>
          </Suspense>
        </main>

        {/* Footer */}
        <footer className="bg-white border-t border-gray-200 mt-12">
          <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
            <p className="text-center text-gray-500 text-sm">
              © 2024 KYC Verification System. All rights reserved.
            </p>
          </div>
        </footer>
      </div>
    </Router>
  );
}

export default App;
