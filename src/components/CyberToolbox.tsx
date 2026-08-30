import React, { useState, useId } from 'react';
import { 
  Wrench, 
  Hash, 
  KeyRound, 
  Network, 
  Copy, 
  Check, 
  Search,
} from 'lucide-react';
import { COMMON_PORTS } from '../data/cyberData';

interface CyberToolboxProps {
  language: 'ar' | 'en';
}

export const CyberToolbox: React.FC<CyberToolboxProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [activeTool, setActiveTool] = useState<'encoder' | 'hasher' | 'ports' | 'password'>('encoder');

  // Encoder state
  const [encoderMode, setEncoderMode] = useState<'base64' | 'hex' | 'url' | 'rot13' | 'binary'>('base64');
  const [encoderInput, setEncoderInput] = useState<string>('admin:password123');
  const [encoderOutput, setEncoderOutput] = useState<string>('');
  const [copiedEncoder, setCopiedEncoder] = useState<boolean>(false);

  // Hasher state
  const [hasherInput, setHasherInput] = useState<string>('admin123');
  const [hashes, setHashes] = useState<{ sha256: string; sha1: string; sha512: string; md5: string }>({
    sha256: '',
    sha1: '',
    sha512: '',
    md5: '',
  });
  const [detectHashInput, setDetectHashInput] = useState<string>('5f4dcc3b5aa765d61d8327deb882cf99');
  const [detectedHashType, setDetectedHashType] = useState<string>('MD5 or NTLM Hash (128-bit)');

  // Ports search
  const [portSearch, setPortSearch] = useState<string>('');

  // Password Evaluator state
  const [passInput, setPassInput] = useState<string>('Cyber@Shield_2026!');

  // Simple pure JS MD5 for client-side hashing demonstration
  const simpleMD5 = (string: string) => {
    function RotateLeft(lValue: number, iShiftBits: number) {
      return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }
    function AddUnsigned(lX: number, lY: number) {
      const lX8 = lX & 0x80000000;
      const lY8 = lY & 0x80000000;
      const lX4 = lX & 0x40000000;
      const lY4 = lY & 0x40000000;
      const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
      if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
      if (lX4 | lY4) {
        if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
        else return lResult ^ 0x40000000 ^ lX8 ^ lY8;
      } else return lResult ^ lX8 ^ lY8;
    }
    function F(x: number, y: number, z: number) { return (x & y) | (~x & z); }
    function G(x: number, y: number, z: number) { return (x & z) | (y & ~z); }
    function H(x: number, y: number, z: number) { return x ^ y ^ z; }
    function I(x: number, y: number, z: number) { return y ^ (x | ~z); }
    function FF(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    }
    function GG(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    }
    function HH(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    }
    function II(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    }
    function ConvertToWordArray(string: string) {
      let lWordCount;
      const lMessageLength = string.length;
      const lNumberOfWords_temp1 = lMessageLength + 8;
      const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
      const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
      const lWordArray = Array(lNumberOfWords - 1);
      let lBytePosition = 0;
      let lByteCount = 0;
      while (lByteCount < lMessageLength) {
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
        lByteCount++;
      }
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
      lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
      lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
      return lWordArray;
    }
    function WordToHex(lValue: number) {
      let WordToHexValue = '', WordToHexValue_temp = '', lByte, lCount;
      for (lCount = 0; lCount <= 3; lCount++) {
        lByte = (lValue >>> (lCount * 8)) & 255;
        WordToHexValue_temp = '0' + lByte.toString(16);
        WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
      }
      return WordToHexValue;
    }

    const x = ConvertToWordArray(string);
    let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
    const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
    const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
    const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

    for (let k = 0; k < x.length; k += 16) {
      const AA = a, BB = b, CC = c, DD = d;
      a = FF(a, b, c, d, x[k + 0], S11, 0xd76aa478);
      d = FF(d, a, b, c, x[k + 1], S12, 0xe8c7b756);
      c = FF(c, d, a, b, x[k + 2], S13, 0x242070db);
      b = FF(b, c, d, a, x[k + 3], S14, 0xc1bdceee);
      a = FF(a, b, c, d, x[k + 4], S11, 0xf57c0faf);
      d = FF(d, a, b, c, x[k + 5], S12, 0x4787c62a);
      c = FF(c, d, a, b, x[k + 6], S13, 0xa8304613);
      b = FF(b, c, d, a, x[k + 7], S14, 0xfd469501);
      a = FF(a, b, c, d, x[k + 8], S11, 0x698098d8);
      d = FF(d, a, b, c, x[k + 9], S12, 0x8b44f7af);
      c = FF(c, d, a, b, x[k + 10], S13, 0xffff5bb1);
      b = FF(b, c, d, a, x[k + 11], S14, 0x895cd7be);
      a = FF(a, b, c, d, x[k + 12], S11, 0x6b901122);
      d = FF(d, a, b, c, x[k + 13], S12, 0xfd987193);
      c = FF(c, d, a, b, x[k + 14], S13, 0xa679438e);
      b = FF(b, c, d, a, x[k + 15], S14, 0x49b40821);
      a = GG(a, b, c, d, x[k + 1], S21, 0xf61e2562);
      d = GG(d, a, b, c, x[k + 6], S22, 0xc040b340);
      c = GG(c, d, a, b, x[k + 11], S23, 0x265e5a51);
      b = GG(b, c, d, a, x[k + 0], S24, 0xe9b6c7aa);
      a = GG(a, b, c, d, x[k + 5], S21, 0xd62f105d);
      d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
      c = GG(c, d, a, b, x[k + 15], S23, 0xd8a1e681);
      b = GG(b, c, d, a, x[k + 4], S24, 0xe7d3fbc8);
      a = GG(a, b, c, d, x[k + 9], S21, 0x21e1cde6);
      d = GG(d, a, b, c, x[k + 14], S22, 0xc33707d6);
      c = GG(c, d, a, b, x[k + 3], S23, 0xf4d50d87);
      b = GG(b, c, d, a, x[k + 8], S24, 0x455a14ed);
      a = GG(a, b, c, d, x[k + 13], S21, 0xa9e3e905);
      d = GG(d, a, b, c, x[k + 2], S22, 0xfcefa3f8);
      c = GG(c, d, a, b, x[k + 7], S23, 0x676f02d9);
      b = GG(b, c, d, a, x[k + 12], S24, 0x8d2a4c8a);
      a = HH(a, b, c, d, x[k + 5], S31, 0xfffa3942);
      d = HH(d, a, b, c, x[k + 8], S32, 0x8771f681);
      c = HH(c, d, a, b, x[k + 11], S33, 0x6d9d6122);
      b = HH(b, c, d, a, x[k + 14], S34, 0xfde5380c);
      a = HH(a, b, c, d, x[k + 1], S31, 0xa4beea44);
      d = HH(d, a, b, c, x[k + 4], S32, 0x4bdecfa9);
      c = HH(c, d, a, b, x[k + 7], S33, 0xf6bb4b60);
      b = HH(b, c, d, a, x[k + 10], S34, 0xbebfbc70);
      a = HH(a, b, c, d, x[k + 13], S31, 0x289b7ec6);
      d = HH(d, a, b, c, x[k + 0], S32, 0xeaa127fa);
      c = HH(c, d, a, b, x[k + 3], S33, 0xd4ef3085);
      b = HH(b, c, d, a, x[k + 6], S34, 0x4881d05);
      a = HH(a, b, c, d, x[k + 9], S31, 0xd9d4d039);
      d = HH(d, a, b, c, x[k + 12], S32, 0xe6db99e5);
      c = HH(c, d, a, b, x[k + 15], S33, 0x1fa27cf8);
      b = HH(b, c, d, a, x[k + 2], S34, 0xc4ac5665);
      a = II(a, b, c, d, x[k + 0], S41, 0xf4292244);
      d = II(d, a, b, c, x[k + 7], S42, 0x432aff97);
      c = II(c, d, a, b, x[k + 14], S43, 0xab9423a7);
      b = II(b, c, d, a, x[k + 5], S44, 0xfc93a039);
      a = II(a, b, c, d, x[k + 12], S41, 0x655b59c3);
      d = II(d, a, b, c, x[k + 3], S42, 0x8f0ccc92);
      c = II(c, d, a, b, x[k + 10], S43, 0xffeff47d);
      b = II(b, c, d, a, x[k + 1], S44, 0x85845dd1);
      a = II(a, b, c, d, x[k + 8], S41, 0x6fa87e4f);
      d = II(d, a, b, c, x[k + 15], S42, 0xfe2ce6e0);
      c = II(c, d, a, b, x[k + 6], S43, 0xa3014314);
      b = II(b, c, d, a, x[k + 13], S44, 0x4e0811a1);
      a = II(a, b, c, d, x[k + 4], S41, 0xf7537e82);
      d = II(d, a, b, c, x[k + 11], S42, 0xbd3af235);
      c = II(c, d, a, b, x[k + 2], S43, 0x2ad7d2bb);
      b = II(b, c, d, a, x[k + 9], S44, 0xeb86d391);
      a = AddUnsigned(a, AA);
      b = AddUnsigned(b, BB);
      c = AddUnsigned(c, CC);
      d = AddUnsigned(d, DD);
    }
    return (WordToHex(a) + WordToHex(b) + WordToHex(c) + WordToHex(d)).toLowerCase();
  };

  // Convert functions
  const handleEncode = (text: string, mode: string) => {
    try {
      if (mode === 'base64') {
        return btoa(unescape(encodeURIComponent(text)));
      } else if (mode === 'hex') {
        return Array.from(new TextEncoder().encode(text))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      } else if (mode === 'url') {
        return encodeURIComponent(text);
      } else if (mode === 'rot13') {
        return text.replace(/[a-zA-Z]/g, (c) => {
          const base = c <= 'Z' ? 65 : 97;
          return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
      } else if (mode === 'binary') {
        return Array.from(new TextEncoder().encode(text))
          .map((b) => b.toString(2).padStart(8, '0'))
          .join(' ');
      }
      return text;
    } catch {
      return 'Error encoding input';
    }
  };

  const handleDecode = (text: string, mode: string) => {
    try {
      if (mode === 'base64') {
        return decodeURIComponent(escape(atob(text.trim())));
      } else if (mode === 'hex') {
        const clean = text.replace(/[^0-9a-fA-F]/g, '');
        const bytes = new Uint8Array(clean.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []);
        return new TextDecoder().decode(bytes);
      } else if (mode === 'url') {
        return decodeURIComponent(text);
      } else if (mode === 'rot13') {
        return handleEncode(text, 'rot13');
      } else if (mode === 'binary') {
        const clean = text.trim().split(/\s+/);
        const bytes = new Uint8Array(clean.map((bin) => parseInt(bin, 2)));
        return new TextDecoder().decode(bytes);
      }
      return text;
    } catch {
      return 'Error decoding input format';
    }
  };

  // Live hash calculator using SubtleCrypto
  React.useEffect(() => {
    const calcHashes = async () => {
      if (!hasherInput) {
        setHashes({ sha256: '', sha1: '', sha512: '', md5: '' });
        return;
      }
      const data = new TextEncoder().encode(hasherInput);
      
      const buffer256 = await crypto.subtle.digest('SHA-256', data);
      const sha256 = Array.from(new Uint8Array(buffer256)).map((b) => b.toString(16).padStart(2, '0')).join('');

      const buffer1 = await crypto.subtle.digest('SHA-1', data);
      const sha1 = Array.from(new Uint8Array(buffer1)).map((b) => b.toString(16).padStart(2, '0')).join('');

      const buffer512 = await crypto.subtle.digest('SHA-512', data);
      const sha512 = Array.from(new Uint8Array(buffer512)).map((b) => b.toString(16).padStart(2, '0')).join('');

      const md5 = simpleMD5(hasherInput);

      setHashes({ sha256, sha1, sha512, md5 });
    };

    calcHashes();
  }, [hasherInput]);

  // Live hash identifier
  React.useEffect(() => {
    const clean = detectHashInput.trim();
    if (!clean) {
      setDetectedHashType('Enter hash string to identify');
      return;
    }

    if (clean.startsWith('$2a$') || clean.startsWith('$2b$') || clean.startsWith('$2y$')) {
      setDetectedHashType('bcrypt (Blowfish crypt) - Highly Secure');
    } else if (clean.startsWith('$argon2')) {
      setDetectedHashType('Argon2 (Argon2id/Argon2i) - High Grade Password Hash');
    } else if (clean.startsWith('$6$')) {
      setDetectedHashType('SHA-512 Unix Crypt ($6$)');
    } else if (clean.startsWith('$1$')) {
      setDetectedHashType('MD5 Unix Crypt ($1$)');
    } else if (/^[0-9a-fA-F]{32}$/.test(clean)) {
      setDetectedHashType('MD5 / NTLM / MD4 (32 Hex Characters)');
    } else if (/^[0-9a-fA-F]{40}$/.test(clean)) {
      setDetectedHashType('SHA-1 / RIPEMD-160 (40 Hex Characters)');
    } else if (/^[0-9a-fA-F]{64}$/.test(clean)) {
      setDetectedHashType('SHA-256 / Keccak-256 / HMAC-SHA256 (64 Hex Characters)');
    } else if (/^[0-9a-fA-F]{128}$/.test(clean)) {
      setDetectedHashType('SHA-512 / Whirlpool (128 Hex Characters)');
    } else {
      setDetectedHashType('Unknown or custom encoded string');
    }
  }, [detectHashInput]);

  // Password Entropy evaluation
  const calculatePasswordEntropy = (pass: string) => {
    if (!pass) return { entropy: 0, strength: 'None', crackTime: '0 seconds' };

    let poolSize = 0;
    if (/[a-z]/.test(pass)) poolSize += 26;
    if (/[A-Z]/.test(pass)) poolSize += 26;
    if (/[0-9]/.test(pass)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(pass)) poolSize += 33;

    const entropy = Math.round(pass.length * (Math.log2(poolSize || 1)));

    let strength = 'Weak (ضعيفة)';
    let color = 'text-red-400';
    let crackTime = '< 1 second';

    if (entropy >= 80) {
      strength = isAr ? 'قوية جداً (Very Strong)' : 'Very Strong';
      crackTime = isAr ? 'ملايين السنين على أقوى مزارع GPU' : 'Millions of years against GPU clusters';
    } else if (entropy >= 60) {
      strength = isAr ? 'قوية (Strong)' : 'Strong';
      crackTime = isAr ? 'عدة عقود' : 'Decades';
    } else if (entropy >= 45) {
      strength = isAr ? 'متوسطة (Moderate)' : 'Moderate';
      crackTime = isAr ? 'عدة أسابيع إلى شهور' : 'Weeks to months';
    } else {
      strength = isAr ? 'ضعيفة جداً (Very Weak)' : 'Very Weak';
      crackTime = isAr ? 'ثوانٍ معدودة' : 'Few seconds';
    }

    return { entropy, strength, crackTime, poolSize };
  };

  const passStats = calculatePasswordEntropy(passInput);

  const filteredPorts = COMMON_PORTS.filter(
    (p) =>
      p.port.toString().includes(portSearch) ||
      p.service.toLowerCase().includes(portSearch.toLowerCase()) ||
      p.description.toLowerCase().includes(portSearch.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-5">
      {/* Top Toolbox Navigation */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-teal-950 border border-teal-800/60 text-teal-400">
            <Wrench className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>{isAr ? 'صندوق أدوات الأمن السيبراني (Cyber Toolbox)' : 'Cybersecurity Utility Toolbox'}</span>
            </h2>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'أدوات مساعدة لتشفير وفك تشفير النصوص، حساب وفحص الـ Hashes، دليل المنافذ، واختبار قوة كلمات المرور.'
                : 'Utility suite for encoding/decoding, hash generator & identifier, port matrix, and password entropy.'}
            </p>
          </div>
        </div>

        {/* Tab Buttons */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveTool('encoder')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTool === 'encoder' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {isAr ? 'المشفر والمحول' : 'Encoders'}
          </button>
          <button
            onClick={() => setActiveTool('hasher')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTool === 'hasher' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {isAr ? 'الهاش وتحديده' : 'Hashes'}
          </button>
          <button
            onClick={() => setActiveTool('ports')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTool === 'ports' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {isAr ? 'دليل المنافذ' : 'Ports Matrix'}
          </button>
          <button
            onClick={() => setActiveTool('password')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTool === 'password' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {isAr ? 'مقياس الإنتروبيا' : 'Password Entropy'}
          </button>
        </div>
      </div>

      {/* TOOL 1: Multi-Encoder & Decoder */}
      {activeTool === 'encoder' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-12 flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-medium">{isAr ? 'خوارزمية التحويل:' : 'Algorithm:'}</span>
              {(['base64', 'hex', 'url', 'rot13', 'binary'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setEncoderMode(m)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-all ${
                    encoderMode === m
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                      : 'bg-slate-950 text-slate-400 hover:bg-slate-800'
                  }`}
                >
                  {m.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setEncoderOutput(handleEncode(encoderInput, encoderMode))}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shadow-md shadow-cyan-950"
              >
                {isAr ? 'تشفير / ترميز (Encode)' : 'Encode ->'}
              </button>
              <button
                onClick={() => setEncoderOutput(handleDecode(encoderInput, encoderMode))}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs shadow-md shadow-emerald-950"
              >
                {isAr ? 'فك التشفير (Decode)' : '<- Decode'}
              </button>
            </div>
          </div>

          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-2">
            <label className="text-xs font-semibold text-slate-300">{isAr ? 'النص المدخل (Input):' : 'Input String:'}</label>
            <textarea
              value={encoderInput}
              onChange={(e) => setEncoderInput(e.target.value)}
              placeholder="Enter string to encode or decode..."
              rows={8}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-800"
            />
          </div>

          <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-cyan-400">{isAr ? 'النتيجة (Output):' : 'Output Result:'}</label>
              {encoderOutput && (
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(encoderOutput);
                    setCopiedEncoder(true);
                    setTimeout(() => setCopiedEncoder(false), 2000);
                  }}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-300"
                >
                  {copiedEncoder ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedEncoder ? 'Copied' : 'Copy'}</span>
                </button>
              )}
            </div>
            <textarea
              readOnly
              value={encoderOutput || handleEncode(encoderInput, encoderMode)}
              rows={8}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-cyan-300 focus:outline-none"
            />
          </div>
        </div>
      )}

      {/* TOOL 2: Hashes Calculator & Identifier */}
      {activeTool === 'hasher' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Hash Generator */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Hash className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'مولد البصمات التشفيرية (Live Hashes Generator)' : 'Cryptographic Hash Generator'}</span>
            </h3>

            <div className="flex flex-col gap-1.5">
              <label className="text-xs text-slate-400">{isAr ? 'النص الصريح (Plaintext):' : 'Plaintext Input:'}</label>
              <input
                type="text"
                value={hasherInput}
                onChange={(e) => setHasherInput(e.target.value)}
                placeholder="Type any password or string..."
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-800"
              />
            </div>

            <div className="flex flex-col gap-2.5 mt-2">
              {[
                { label: 'MD5 (128-bit)', value: hashes.md5, warn: isAr ? 'قديم ومكسور تشفيرياً (Insecure)' : 'Deprecated' },
                { label: 'SHA-1 (160-bit)', value: hashes.sha1, warn: isAr ? 'ضعيف ومعرض للتصادم' : 'Vulnerable to collision' },
                { label: 'SHA-256 (256-bit)', value: hashes.sha256, good: isAr ? 'معيار قوي وموصى به' : 'Recommended standard' },
                { label: 'SHA-512 (512-bit)', value: hashes.sha512, good: isAr ? 'فائق الأمان والحماية' : 'High security' },
              ].map((h, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex flex-col gap-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-slate-300 font-mono">{h.label}</span>
                    {h.warn && <span className="text-[10px] text-amber-400 bg-amber-950/40 px-1.5 rounded">{h.warn}</span>}
                    {h.good && <span className="text-[10px] text-emerald-400 bg-emerald-950/40 px-1.5 rounded">{h.good}</span>}
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-cyan-300 truncate select-all">{h.value}</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(h.value)}
                      className="p-1 hover:text-cyan-400 text-slate-500"
                      title="Copy"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Hash Type Detector */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
              <Search className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'كاشف نوع الهاش (Hash Type Identifier)' : 'Hash Type Identifier'}</span>
            </h3>

            <p className="text-xs text-slate-400">
              {isAr
                ? 'الصق أي هاش مجهول لتحديد الخوارزمية المحتملة وطول البصمة.'
                : 'Paste any unknown hash string to identify its probable algorithm and structure.'}
            </p>

            <div className="flex flex-col gap-1.5">
              <input
                type="text"
                value={detectHashInput}
                onChange={(e) => setDetectHashInput(e.target.value)}
                placeholder="e.g. 5d41402abc4b2a76b9719d911017c592"
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-800"
              />
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-cyan-900/40 mt-1 flex flex-col gap-2">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
                {isAr ? 'النوع المتوقع:' : 'Detected Algorithm:'}
              </span>
              <span className="text-sm font-bold text-cyan-400 font-mono">
                {detectedHashType}
              </span>
              <div className="text-[11px] text-slate-400 mt-1">
                <span>{isAr ? 'طول السلسلة:' : 'Character Length:'} </span>
                <span className="font-mono text-slate-200 font-bold">{detectHashInput.trim().length} chars</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TOOL 3: Ports & Protocols Matrix */}
      {activeTool === 'ports' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200">
                {isAr ? 'مصفوفة المنافذ والبروتوكولات الشائعة (Common Ports Matrix)' : 'Common Ports & Risk Matrix'}
              </h3>
            </div>

            <div className="relative w-full sm:w-72">
              <Search className="w-4 h-4 text-slate-500 absolute top-2.5 left-2.5" />
              <input
                type="text"
                value={portSearch}
                onChange={(e) => setPortSearch(e.target.value)}
                placeholder={isAr ? 'ابحث بالمنفذ أو الخدمة...' : 'Filter by port or service...'}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-800"
              />
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-xs text-start">
              <thead className="bg-slate-950 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3 text-start">{isAr ? 'المنفذ' : 'Port'}</th>
                  <th className="p-3 text-start">{isAr ? 'الخدمة' : 'Service'}</th>
                  <th className="p-3 text-start">{isAr ? 'البروتوكول' : 'Transport'}</th>
                  <th className="p-3 text-start">{isAr ? 'مستوى الخطر الأمني' : 'Risk Level'}</th>
                  <th className="p-3 text-start">{isAr ? 'التفاصيل والاعتبارات الأمنية' : 'Security Notes'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                {filteredPorts.map((p, idx) => (
                  <tr key={idx} className="hover:bg-slate-950/40 transition-colors">
                    <td className="p-3 font-bold text-cyan-400">{p.port}</td>
                    <td className="p-3 font-bold text-slate-200">{p.service}</td>
                    <td className="p-3 text-slate-400">{p.transport}</td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          p.risk === 'Critical'
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : p.risk === 'High'
                            ? 'bg-orange-950 text-orange-400 border border-orange-800'
                            : p.risk === 'Medium'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-blue-950 text-blue-400 border border-blue-800'
                        }`}
                      >
                        {p.risk}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300 font-sans text-xs">{p.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TOOL 4: Password Entropy & Strength Evaluator */}
      {activeTool === 'password' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-4">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">
              {isAr ? 'مقياس إنتروبيا وقوة كلمات المرور (Password Entropy Evaluator)' : 'Password Entropy & Resistance Evaluator'}
            </h3>
          </div>

          <div className="flex flex-col gap-2">
            <label className="text-xs text-slate-400">{isAr ? 'اختبر كلمة المرور:' : 'Test Password:'}</label>
            <input
              type="text"
              value={passInput}
              onChange={(e) => setPassInput(e.target.value)}
              placeholder="Enter password..."
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-sm font-mono text-cyan-300 focus:outline-none focus:border-cyan-800"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">{isAr ? 'الإنتروبيا (Bits)' : 'Entropy Score'}</span>
              <span className="text-xl font-bold font-mono text-cyan-400 mt-1">{passStats.entropy} bits</span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">{isAr ? 'التقييم الأمني' : 'Security Strength'}</span>
              <span className="text-base font-bold text-slate-100 mt-1">{passStats.strength}</span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">{isAr ? 'الوقت المتوقع للكسر' : 'Crack Time (GPU)'}</span>
              <span className="text-xs font-semibold text-emerald-400 mt-1">{passStats.crackTime}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
