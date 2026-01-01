/**
 * Client-side device fingerprinting
 * Collect browser/device characteristics for enhanced security
 * 
 * Usage: 
 * const fingerprint = await collectFingerprint();
 * // Send fingerprint with login request
 */

async function collectFingerprint() {
  const fingerprint = {};

  // 1. Screen properties
  fingerprint.screenResolution = `${window.screen.width}x${window.screen.height}`;
  fingerprint.colorDepth = window.screen.colorDepth;
  fingerprint.pixelRatio = window.devicePixelRatio || 1;

  // 2. Timezone
  fingerprint.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  fingerprint.timezoneOffset = new Date().getTimezoneOffset();

  // 3. Platform and hardware
  fingerprint.platform = navigator.platform;
  fingerprint.hardwareConcurrency = navigator.hardwareConcurrency || 0;
  fingerprint.deviceMemory = navigator.deviceMemory || 0;

  // 4. Language
  fingerprint.language = navigator.language;
  fingerprint.languages = navigator.languages?.join(',') || '';

  // 5. Canvas fingerprint (most stable)
  fingerprint.canvas = await getCanvasFingerprint();

  // 6. WebGL fingerprint
  fingerprint.webgl = getWebGLFingerprint();

  // 7. Installed fonts (sample check)
  fingerprint.fonts = await checkFonts();

  // 8. Audio context fingerprint
  fingerprint.audioContext = await getAudioFingerprint();

  // 9. Plugins (deprecated but still useful)
  fingerprint.plugins = getPlugins();

  return fingerprint;
}

// Canvas fingerprinting
async function getCanvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = 200;
    canvas.height = 50;
    
    // Draw text with various styles
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Canvas 🎨', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Fingerprint', 4, 17);
    
    // Convert to hash
    const dataURL = canvas.toDataURL();
    return await hashString(dataURL);
  } catch (err) {
    return '';
  }
}

// WebGL fingerprinting
function getWebGLFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    
    if (!gl) return '';
    
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return '';
    
    return {
      vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
      renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
    };
  } catch (err) {
    return '';
  }
}

// Check for common fonts
async function checkFonts() {
  const baseFonts = ['monospace', 'sans-serif', 'serif'];
  const testFonts = [
    'Arial', 'Verdana', 'Times New Roman', 'Courier New',
    'Georgia', 'Palatino', 'Garamond', 'Bookman',
    'Comic Sans MS', 'Trebuchet MS', 'Impact'
  ];
  
  const detected = [];
  
  // Simple font detection using canvas
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  
  for (const font of testFonts) {
    let isDetected = false;
    
    for (const baseFont of baseFonts) {
      ctx.font = `72px ${baseFont}`;
      const baseWidth = ctx.measureText('mmmmmmmmmmlli').width;
      
      ctx.font = `72px ${font}, ${baseFont}`;
      const testWidth = ctx.measureText('mmmmmmmmmmlli').width;
      
      if (baseWidth !== testWidth) {
        isDetected = true;
        break;
      }
    }
    
    if (isDetected) detected.push(font);
  }
  
  return detected.join(',');
}

// Audio context fingerprinting
async function getAudioFingerprint() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return '';
    
    const context = new AudioContext();
    const oscillator = context.createOscillator();
    const analyser = context.createAnalyser();
    const gainNode = context.createGain();
    const scriptProcessor = context.createScriptProcessor(4096, 1, 1);
    
    gainNode.gain.value = 0; // Mute
    oscillator.connect(analyser);
    analyser.connect(scriptProcessor);
    scriptProcessor.connect(gainNode);
    gainNode.connect(context.destination);
    
    oscillator.start(0);
    
    return new Promise((resolve) => {
      scriptProcessor.onaudioprocess = function(event) {
        const output = event.outputBuffer.getChannelData(0);
        const sum = output.reduce((a, b) => a + b, 0);
        
        oscillator.stop();
        scriptProcessor.disconnect();
        context.close();
        
        resolve(sum.toString());
      };
    });
  } catch (err) {
    return '';
  }
}

// Get plugins
function getPlugins() {
  if (!navigator.plugins) return '';
  
  const plugins = [];
  for (let i = 0; i < navigator.plugins.length; i++) {
    plugins.push(navigator.plugins[i].name);
  }
  return plugins.join(',');
}

// Hash helper (simple implementation)
async function hashString(str) {
  const msgBuffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Example usage in login
async function loginWithFingerprint(email, password) {
  const fingerprint = await collectFingerprint();
  
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email,
      password,
      fingerprint
    })
  });
  
  return response.json();
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { collectFingerprint, loginWithFingerprint };
}