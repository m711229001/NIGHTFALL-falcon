export default function GlitchText({ text, className = "" }) {
  return (
    <div className={`relative inline-block ${className}`}>
      <span className="relative z-10">{text}</span>
      <span className="absolute inset-0 z-0 text-red-600 animate-glitch-1" aria-hidden="true">{text}</span>
      <span className="absolute inset-0 z-0 text-cyan-500 animate-glitch-2" aria-hidden="true">{text}</span>
    </div>
  );
}
