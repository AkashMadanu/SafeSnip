// App.jsx
import { useState } from 'react';
import './App.css';

// --- Configuration --- //
const SHORTENER_API_URL = 'https://shortenurl.app/api/v1/shorten';
const GOOGLE_API_KEY = 'AIzaSyDp5js5Co4sTkS4IJCObUKxIuxlNbWp_mc'; // From Google Cloud Console

// --- Services --- //
const checkUrlSafety = async (url) => {
  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'SafeSnip', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );
    const data = await response.json();
    return !data.matches; // Returns true if safe (no matches)
  } catch (error) {
    console.error('Safety check failed:', error);
    return true; // Assume safe if API fails
  }
};

const shortenUrl = async (longUrl) => {
  try {
    const response = await fetch(SHORTENER_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: longUrl
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to shorten URL');
    }

    const data = await response.json();
    console.log('API Response:', data);
    
    // Handle different response structures
    if (data && data.data && data.data.shortUrl) {
      return data.data.shortUrl;
    } else if (data && data.shortUrl) {
      return data.shortUrl;
    } else {
      console.error('Unexpected API response structure:', data);
      throw new Error('Unexpected response from URL shortener');
    }
  } catch (error) {
    console.error('Shortening failed:', error);
    throw error;
  }
};

// --- Icons --- //
const LinkIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
  </svg>
);

const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 6L9 17l-5-5"></path>
  </svg>
);

const AlertIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
    <line x1="12" y1="9" x2="12" y2="13"></line>
    <line x1="12" y1="17" x2="12.01" y2="17"></line>
  </svg>
);

const CopyIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
  </svg>
);

const CheckCircleIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
    <polyline points="22 4 12 14.01 9 11.01"></polyline>
  </svg>
);

const AlertCircleIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle>
    <line x1="12" y1="8" x2="12" y2="12"></line>
    <line x1="12" y1="16" x2="12.01" y2="16"></line>
  </svg>
);

// --- Main Component --- //
function App() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [isSafe, setIsSafe] = useState(null);
  const [error, setError] = useState(null);
  const [expiryInfo, setExpiryInfo] = useState(null);
  const [copyText, setCopyText] = useState('Copy');

  const validateUrl = (inputUrl) => {
    try {
      if (!inputUrl) throw new Error('URL is required');
      if (!inputUrl.match(/^https?:\/\//i)) {
        throw new Error('URL must start with http:// or https://');
      }
      new URL(inputUrl); // This will throw if URL is invalid
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    }
  };

  const handleSubmit = async (e) => {
    if (e) e.preventDefault(); // Prevent form submission if called from form
    
    setError(null);
    setExpiryInfo(null);
    setCopyText('Copy');
    if (!validateUrl(url)) return;

    setIsLoading(true);
    setResult(null);
    setIsSafe(null);

    try {
      // 1. Safety Check
      const isSafeUrl = await checkUrlSafety(url);
      if (!isSafeUrl) {
        setIsSafe(false);
        throw new Error('This URL is flagged as dangerous');
      }

      // 2. Shorten URL
      const shortUrl = await shortenUrl(url);
      setResult(shortUrl);
      setIsSafe(true);
      setExpiryInfo('Note: URL expires after 1 month of inactivity');
    } catch (err) {
      setError(err.message);
      if (err.message.includes('dangerous')) {
        setIsSafe(false);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = () => {
    if (!result) return;
    
    navigator.clipboard.writeText(result)
      .then(() => {
        setCopyText('Copied!');
        setTimeout(() => {
          setCopyText('Copy');
        }, 2000);
      })
      .catch(err => {
        console.error('Failed to copy: ', err);
        setCopyText('Failed');
        setTimeout(() => {
          setCopyText('Copy');
        }, 2000);
      });
  };

  return (
    <div className="app-container">
      <div className="app-content">
        <h1>SafeSnip</h1>
        <p className="tagline">Secure URL Shortening</p>
        
        <form className="input-container" onSubmit={handleSubmit}>
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setError(null);
            }}
            placeholder="https://example.com"
            disabled={isLoading}
          />
          <button 
            type="submit"
            disabled={isLoading || !url}
          >
            {isLoading ? (
              <span className="loader"></span>
            ) : (
              <>Shorten</>
            )}
          </button>
        </form>

        {/* Enhanced Error/Warning Message */}
        {error && isSafe === false && (
          <div className="message warning">
            <div className="warning-icon">
              <AlertIcon />
            </div>
            <div className="warning-content">
              <div className="warning-title">Security Alert</div>
              <div className="warning-description">
                This URL has been flagged as potentially dangerous. We cannot create a shortened link for your safety.
              </div>
            </div>
          </div>
        )}
        {error && isSafe !== false && (
          <div className="message error">
            <AlertCircleIcon />
            {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div className={`result-container ${isSafe ? 'safe' : 'unsafe'}`}>
            <div className="status-indicator">
              {isSafe ? (
                <>
                  <CheckCircleIcon /> 
                  Safe Link Verified
                </>
              ) : (
                <>
                  <AlertIcon />
                  Unsafe Link Warning
                </>
              )}
            </div>
            
            <div className="result-url">
              <a href={result} target="_blank" rel="noopener noreferrer">
                {result}
              </a>
            </div>
            
            <button 
              onClick={copyToClipboard}
              className="copy-button"
            >
              {copyText === 'Copy' ? <CopyIcon /> : <CheckIcon />} {copyText}
            </button>

            {expiryInfo && (
              <div className="expiry-info">
                {expiryInfo}
              </div>
            )}

<div className="service-credits">
  Powered by{' '}
  <a href="https://developers.google.com/safe-browsing" target="_blank" rel="noopener noreferrer">
    Google Safe Browsing
  </a>
  {' '}
  and{' '}
  <a href="https://shortenurl.app" target="_blank" rel="noopener noreferrer">
    shortenurl.app
  </a>
  
</div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;