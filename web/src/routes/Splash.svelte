<script>
  import { link } from 'svelte-spa-router';

  const asciiLogo = `
██████╗ ███╗   ██╗███████╗███╗   ███╗
██╔══██╗████╗  ██║██╔════╝████╗ ████║
██║  ██║██╔██╗ ██║███████╗██╔████╔██║
██║  ██║██║╚██╗██║╚════██║██║╚██╔╝██║
██████╔╝██║ ╚████║███████║██║ ╚═╝ ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝`;
</script>

<div class="splash-container">
  <div class="content">
    <div class="ascii-card">
      <pre>{asciiLogo}</pre>
    </div>

    <div class="tagline">
      <p class="desc">
        A small but comprehensive toolkit for covert data exfiltration using DNS.
      </p>
    </div>

    <nav class="nav-grid">
      <a href="#/inbox" use:link class="nav-card">
        <div class="card-icon">📬</div>
        <div class="card-content">
          <h3>Inbox</h3>
          <p>WebSocket + HTTP message viewer</p>
        </div>
      </a>

      <a href="#/browser-test" use:link class="nav-card">
        <div class="card-icon">🧪</div>
        <div class="card-content">
          <h3>Browser Test</h3>
          <p>Wasm + WebSocket integration test</p>
        </div>
      </a>

      <a href="https://github.com/k-o-n-t-o-r/dnsm" target="_blank" rel="noopener noreferrer" class="nav-card">
        <div class="card-icon github-icon">
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
        </div>
        <div class="card-content">
          <h3>GitHub</h3>
          <p>Source code<br>and documentation</p>
        </div>
      </a>
    </nav>

    <footer class="splash-footer">
      <div class="links">
        <a href="https://crates.io/crates/dnsm" target="_blank" rel="noopener noreferrer">
          <img src="https://img.shields.io/crates/v/dnsm.svg" alt="crates.io" />
        </a>
      </div>
    </footer>
  </div>
</div>

<style>
  .splash-container {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 20px;
  }

  .content {
    max-width: 900px;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 32px;
  }

  .ascii-card {
    display: inline-block;
    background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 20px 24px;
    box-shadow:
      0 0 0 1px var(--accent-glow),
      var(--shadow-lg);
    position: relative;
    overflow: hidden;
  }

  .ascii-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg,
      transparent,
      var(--accent-glow) 50%,
      transparent
    );
    animation: shimmer 3s ease-in-out infinite;
  }

  @keyframes shimmer {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 1; }
  }

  .ascii-card pre {
    color: var(--accent);
    font-size: 5px;
    line-height: 1.0;
    margin: 0;
    font-variant-ligatures: none;
    font-feature-settings: "liga" 0, "calt" 0;
    letter-spacing: 0;
    text-shadow: 0 0 10px rgba(29, 242, 166, 0.3);
  }

  .tagline {
    text-align: center;
  }

  .desc {
    color: var(--muted);
    font-size: 1em;
    line-height: 1.6;
    margin: 0;
  }

  .nav-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    width: 100%;
    max-width: 900px;
  }

  .nav-card {
    display: flex;
    align-items: center;
    gap: 16px;
    background: linear-gradient(135deg, var(--panel) 0%, var(--panel-2) 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 20px;
    text-decoration: none;
    color: var(--text);
    transition: all 0.2s ease;
    box-shadow: var(--shadow);
  }

  .nav-card:hover {
    border-color: var(--accent);
    box-shadow: var(--shadow), 0 0 0 1px var(--accent), var(--glow);
    transform: translateY(-2px);
  }

  .card-icon {
    font-size: 32px;
    line-height: 1;
    flex-shrink: 0;
  }

  .github-icon {
    width: 32px;
    height: 32px;
    color: var(--text);
  }

  .github-icon svg {
    width: 100%;
    height: 100%;
    display: block;
  }

  .card-content h3 {
    margin: 0 0 4px 0;
    font-size: 18px;
    font-weight: 600;
    color: var(--text);
  }

  .card-content p {
    margin: 0;
    font-size: 12px;
    color: var(--muted);
  }

  .splash-footer {
    margin-top: 16px;
  }

  .links {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    justify-content: center;
  }

  .links a {
    transition: opacity 0.2s ease;
  }

  .links a:hover {
    opacity: 0.8;
  }

  @media (max-width: 640px) {
    .ascii-card pre {
      font-size: 3px;
    }

    .desc {
      font-size: 13px;
    }

    .nav-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
